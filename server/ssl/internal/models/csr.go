package models

/* ===========================
   CSR Decode Result
=========================== */

type CSRDecodeResponse struct {
	/* ---- Basic Info ---- */
	CommonName string `json:"common_name"`

	/* ---- Subject Info ---- */
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	State              []string `json:"state,omitempty"`
	Locality           []string `json:"locality,omitempty"`

	/* ---- Extensions ---- */
	Sans            []string `json:"sans"`
	HasSANExtension bool     `json:"has_san_extension"	`
	DnsNames        []string `json:"dns_names,omitempty"`
	IPAddresses     []string `json:"ip_addresses,omitempty"`
	EmailAddresses  []string `json:"email_addresses,omitempty"`
	URIs            []string `json:"uris,omitempty"`

	/* ---- Key Info ---- */
	KeySize   int    `json:"key_size"`
	Algorithm string `json:"algorithm"`

	/* ---- Meta ---- */
	Success bool `json:"success"`
}
