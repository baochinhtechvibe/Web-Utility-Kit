/* ====================================================
File: models.go

Chức năng chính:
- Định nghĩa toàn bộ cấu trúc dữ liệu (data models)
- Dùng để chuẩn hoá dữ liệu trả về cho API SSL Checker
==================================================== */

package models

import "time"

/* ===========================
   TLS Scan Result
=========================== */

type TLSScanResult struct {
	Version string `json:"version"`
	Cipher  string `json:"cipher"`
	Secure  bool   `json:"secure"`
}

type CertLevel string

/* ===========================
   Trusted Result
=========================== */
type TrustCode string

const (
	// OK
	TrustOK TrustCode = "ok"

	// Self-signed (SSL Shopper style)
	TrustSelfSignedLeaf  TrustCode = "self_signed"          // OpenSSL 18
	TrustSelfSignedChain TrustCode = "self_signed_in_chain" // OpenSSL 19

	// Chain / Issuer
	TrustMissingIssuer TrustCode = "missing_issuer" // 20
	TrustBadChain      TrustCode = "bad_chain"      // 21
	TrustUntrustedRoot TrustCode = "untrusted_root"

	// Expiration
	TrustCertExpired  TrustCode = "cert_expired"
	TrustChainExpired TrustCode = "chain_expired"

	// Hostname
	TrustNameMismatch TrustCode = "name_mismatch" // 10

	// Fallback
	TrustUnknown TrustCode = "unknown"
)

type TrustIssue struct {
	Code    TrustCode `json:"code"`
	Message string    `json:"message"`
}

const (
	CertLevelDomain       CertLevel = "Domain"
	CertLevelIntermediate CertLevel = "Intermediate"
	CertLevelRoot         CertLevel = "Root"
	CertLevelUnknown      CertLevel = "Unknown"
)

/* ===========================
   Certificate Detail
=========================== */
// CertDetail represents detailed information about an X.509 certificate
// Level indicates the certificate type: "domain", "intermediate", or "root"
type CertDetail struct {
	CommonName string    `json:"common_name"`
	Issuer     string    `json:"issuer"`
	Level      CertLevel `json:"level"`

	Organization []string `json:"organization,omitempty"`
	Country      []string `json:"country,omitempty"`
	Locality     []string `json:"locality,omitempty"`
	Province     []string `json:"province,omitempty"`

	SANs []string `json:"sans"`

	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`

	SerialNumberDec string `json:"serial_dec"`
	SerialNumberHex string `json:"serial_hex"`

	SignatureAlgo string `json:"signature_algo"`

	FingerprintSHA1   string `json:"fingerprint_sha1"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`

	IsCA bool `json:"is_ca"`
}

/* ===========================
   Main SSL Response
=========================== */

type SSLCheckResponse struct {

	/* ---- Basic Info ---- */
	Hostname string `json:"hostname" validate:"required,hostname"`
	IP       string `json:"ip" validate:"required,ip"`

	ServerType string `json:"server_type"`

	/* ---- Validity ---- */

	Valid    bool  `json:"valid"`
	DaysLeft int64 `json:"days_left"`

	/* ---- Verification ---- */

	HostnameOK  bool         `json:"hostname_ok"`
	Trusted     bool         `json:"trusted"`
	TrustIssues []TrustIssue `json:"trust_issue,omitempty"`
	TrustReason string       `json:"trust_reason,omitempty"`

	OCSP     *OCSPDetail `json:"ocsp,omitempty"`
	OCSPGood bool        `json:"ocsp_good"`

	/* ---- TLS ---- */

	TLSVersion string          `json:"tls_version"`
	TLSScan    []TLSScanResult `json:"tls_scan"`

	/* ---- Grade */

	Grade  string `json:"grade"`
	Status string `json:"status"`

	/* ---- Chain */

	CertChain []CertDetail `json:"cert_chain"`

	HasRoot bool `json:"has_root"`

	/* ---- Meta */

	CheckTime time.Time `json:"check_time"`
	Success   bool      `json:"success"`
}
