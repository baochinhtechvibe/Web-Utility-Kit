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
	Sans []string `json:"sans,omitempty"` // DNS Names, IP Addresses, Email Addresses

	/* ---- Key Info ---- */
	KeySize   int    `json:"key_size"`
	Algorithm string `json:"algorithm"`

	/* ---- Meta ---- */
	CSR     string `json:"csr,omitempty"` // Optional: echo back original CSR
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}
