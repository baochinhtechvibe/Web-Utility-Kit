package checker

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
)

func buildFingerprint(cert *x509.Certificate) (string, string) {

	sha1Sum := sha1.Sum(cert.Raw)
	sha256Sum := sha256.Sum256(cert.Raw)

	return formatHex(sha1Sum[:]),
		formatHex(sha256Sum[:])
}

func formatHex(b []byte) string {
	var out strings.Builder

	for i, v := range b {
		if i > 0 {
			out.WriteString(":")
		}
		out.WriteString(hex.EncodeToString([]byte{v}))
	}

	return out.String()
}
