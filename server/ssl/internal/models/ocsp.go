package models

import "time"

type OCSPStatus string

const (
	OCSPGood    OCSPStatus = "good"
	OCSPRevoked OCSPStatus = "revoked"
	OCSPUnknown OCSPStatus = "unknown"
	OCSPError   OCSPStatus = "error"
	OCSPNoCheck OCSPStatus = "no_check"
)

type OCSPDetail struct {
	// Status is the source of truth for OCSP result.
	Status OCSPStatus `json:"status"`
	// Good is kept for backward compatibility; prefer using Status.
	Good bool `json:"good"`
	// Checked indicates whether an OCSP request was actually performed.
	Checked bool `json:"checked"`

	Server    string `json:"server,omitempty"`
	Responder string `json:"responder,omitempty"`

	RevocationReason string `json:"revocation_reason,omitempty"`

	ThisUpdate time.Time `json:"this_update,omitempty"`
	NextUpdate time.Time `json:"next_update,omitempty"`
	ProducedAt time.Time `json:"produced_at,omitempty"`

	Error string `json:"error,omitempty"`
}
