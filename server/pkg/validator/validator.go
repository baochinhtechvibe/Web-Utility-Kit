// ============================================
// FILE: pkg/validator/validator.go
// Input validation and type detection
// ============================================
package validator

import (
	"net"
	"regexp"
	"strings"
)

var domainRegex = regexp.MustCompile(
	`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`,
)

type InputType int

const (
	InputTypeInvalid InputType = iota
	InputTypeDomain
	InputTypeIPv4
	InputTypeIPv6
)

type ValidationResult struct {
	Valid      bool
	Type       InputType
	Input      string
	ErrorMsg   string
	ValidTypes []string // Valid record types for this input
}

// ValidateAndDetect validates input and detects its type
func ValidateAndDetect(input string) ValidationResult {
	input = strings.TrimSpace(input)

	if input == "" {
		return ValidationResult{
			Valid:    false,
			ErrorMsg: "Hostname không được để trống!",
		}
	}

	// Try to parse as IP
	ip := net.ParseIP(input)

	// Check if it's IPv4
	if ip != nil && ip.To4() != nil {
		return ValidationResult{
			Valid:      true,
			Type:       InputTypeIPv4,
			Input:      input,
			ValidTypes: []string{"PTR", "BLACKLIST", "ALL"},
		}
	}

	// Check if it's IPv6
	if ip != nil && ip.To4() == nil {
		return ValidationResult{
			Valid:      true,
			Type:       InputTypeIPv6,
			Input:      input,
			ValidTypes: []string{"PTR", "ALL"},
		}
	}

	// Check if it's a valid domain
	if IsValidDomain(input) {
		return ValidationResult{
			Valid:      true,
			Type:       InputTypeDomain,
			Input:      input,
			ValidTypes: []string{"A", "AAAA", "NS", "MX", "CNAME", "TXT", "DNSSEC", "ALL"},
		}
	}

	return ValidationResult{
		Valid:    false,
		ErrorMsg: "Hostname không hợp lệ. Vui lòng nhập tên miền, địa chỉ IPv4 hoặc IPv6 hợp lệ",
	}
}

// isValidDomain checks if the input is a valid domain name
func IsValidDomain(domain string) bool {
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	// Domain regex pattern
	// pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?
	// pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	if !domainRegex.MatchString(domain) {
		return false
	}

	// Additional checks
	if len(domain) > 253 {
		return false
	}

	// Check each label length
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 63 || len(label) == 0 {
			return false
		}
	}

	return true
}

// IsValidRecordType checks if the record type is valid for the input type
func IsValidRecordType(inputType InputType, recordType string) bool {
	validTypes := map[InputType][]string{
		InputTypeDomain: {"A", "AAAA", "NS", "MX", "CNAME", "TXT", "DNSSEC", "ALL"},
		InputTypeIPv4:   {"PTR", "BLACKLIST", "ALL"},
		InputTypeIPv6:   {"PTR", "ALL"},
	}

	types, ok := validTypes[inputType]
	if !ok {
		return false
	}

	for _, t := range types {
		recordType = strings.ToUpper(recordType)
		if t == recordType {
			return true
		}
	}

	return false
}

// GetSuggestedRecordTypes returns suggested record types based on input
func GetSuggestedRecordTypes(inputType InputType) []string {
	switch inputType {
	case InputTypeDomain:
		return []string{"A", "AAAA", "NS", "MX", "CNAME", "TXT", "DNSSEC", "ALL"}
	case InputTypeIPv4:
		return []string{"PTR", "BLACKLIST"}
	case InputTypeIPv6:
		return []string{"PTR"}
	default:
		return []string{}
	}
}
