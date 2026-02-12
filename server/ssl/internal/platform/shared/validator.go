package shared

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
	"tools.bctechvibe.io.vn/server/ssl/internal/config"
)

var domainRegex = regexp.MustCompile(
	`(?i)^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$`,
)

// NormalizeDomain extracts and normalizes domain from various formats
func NormalizeDomain(input string) string {
	d := strings.TrimSpace(input)

	// Try decode percent-encoding
	if strings.Contains(d, "%") {
		if ud, err := url.QueryUnescape(d); err == nil {
			d = ud
		}
	}

	// Ensure a scheme so url.Parse treats host correctly
	parseTarget := d
	if !strings.Contains(d, "://") {
		parseTarget = "http://" + d
	}

	u, err := url.Parse(parseTarget)
	if err == nil && u.Host != "" {
		host := u.Hostname()
		// remove IPv6 brackets, trailing dot and normalize
		host = strings.Trim(host, "[]")
		host = strings.TrimSuffix(host, ".")
		return strings.ToLower(strings.TrimSpace(host))
	}

	// Fallback: strip path/query/fragment, possible port, trailing dot
	if i := strings.IndexAny(d, "/?#"); i != -1 {
		d = d[:i]
	}
	// remove enclosing brackets and any trailing port
	d = strings.Trim(d, "[]")
	if h, _, err := net.SplitHostPort(d); err == nil {
		d = h
	} else {
		// if SplitHostPort failed but there's a colon and a dot (likely host:port), remove last :port
		if strings.Contains(d, ":") && strings.Contains(d, ".") {
			if i := strings.LastIndex(d, ":"); i != -1 {
				d = d[:i]
			}
		}
	}
	d = strings.TrimSuffix(d, ".")
	return strings.ToLower(strings.TrimSpace(d))
}

// ValidDomain validates if input is a valid domain
func ValidDomain(input string) bool {
	d := NormalizeDomain(input)

	if d == "" {
		return false
	}

	if len(d) > config.MaxDomainLength {
		return false
	}

	// Reject IP
	if net.ParseIP(d) != nil {
		return false
	}

	// Must contain dot
	if !strings.Contains(d, ".") {
		return false
	}

	ascii, err := idna.ToASCII(d)
	if err != nil {
		return false
	}

	if len(ascii) > config.MaxDomainLength {
		return false
	}

	return domainRegex.MatchString(ascii)
}

// ParseDomain normalizes and validates basic form, returns punycode ASCII (normalized) or error
func ParseDomain(input string) (string, error) {
	d := strings.TrimSpace(input)

	// Decode percent-encoding
	if ud, err := url.QueryUnescape(d); err == nil {
		d = ud
	}

	// case-insensitive scheme check
	parseTarget := d
	if !strings.Contains(strings.ToLower(d), "://") {
		parseTarget = "http://" + d
	}

	u, err := url.Parse(parseTarget)
	if err == nil && u.Host != "" {
		host := u.Hostname()
		host = strings.Trim(host, "[]")
		host = strings.TrimSuffix(host, ".")
		d = strings.ToLower(strings.TrimSpace(host))
	} else {
		// fallback: remove path, brackets, possible port (keep safe)
		if i := strings.IndexAny(d, "/?#"); i != -1 {
			d = d[:i]
		}
		d = strings.Trim(d, "[]")
		if h, _, err := net.SplitHostPort(d); err == nil {
			d = h
		} else if strings.Contains(d, ":") && strings.Contains(d, ".") {
			if i := strings.LastIndex(d, ":"); i != -1 {
				d = d[:i]
			}
		}
		d = strings.TrimSuffix(d, ".")
		d = strings.ToLower(strings.TrimSpace(d))
	}

	if d == "" {
		return "", fmt.Errorf("empty host")
	}
	if len(d) > config.MaxDomainLength {
		return "", fmt.Errorf("domain too long")
	}
	if net.ParseIP(d) != nil {
		return "", fmt.Errorf("is ip")
	}
	if !strings.Contains(d, ".") {
		return "", fmt.Errorf("no dot")
	}
	ascii, err := idna.ToASCII(d)
	if err != nil {
		return "", err
	}
	if len(ascii) > config.MaxDomainLength {
		return "", fmt.Errorf("ascii too long")
	}
	if !domainRegex.MatchString(ascii) {
		return "", fmt.Errorf("invalid format")
	}
	return ascii, nil
}
