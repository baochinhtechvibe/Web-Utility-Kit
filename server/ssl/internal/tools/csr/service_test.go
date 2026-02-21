package csr

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

func TestDecode(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"My Org"},
			Country:      []string{"VN"},
		},
		DNSNames: []string{"www.example.com", "api.example.com"},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	svc := New()
	resp, err := svc.Decode(context.Background(), string(csrPEM))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if resp.CommonName != "example.com" {
		t.Errorf("Expected CN example.com, got %s", resp.CommonName)
	}
	if len(resp.DnsNames) != 2 {
		t.Errorf("Expected 2 DNSNames, got %d", len(resp.DnsNames))
	}
	// Verify Sans includes the combo
	if len(resp.Sans) != 2 {
		t.Errorf("Expected 2 Sans, got %v", resp.Sans)
	}
	if resp.Algorithm != "RSA" {
		t.Errorf("Expected Algorithm RSA, got %s", resp.Algorithm)
	}
}

func TestDecodeLiteralSlashN(t *testing.T) {
	input := `-----BEGIN CERTIFICATE REQUEST-----\nMIIDAjCCAeoCAQAwgYAxCzAJBgNVBAYTAlZOMQwwCgYDVQQIDANIQ00xGTAXBgNVBAcMEEhPIENISSBNSU5IIENJVFkxJDAiBgNVBAoMG0PDlE5HIFRZIFROSEggVUxUUkEgUEFDSUZJQzELMAkGA1UECwwCSVQxFTATBgNVBAMMDGNvcm9zLmNvbS52bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALd1dC2MsphLfC2Q6HXWsWaigZRzl4n6ooe/BRJbmU010fjO5FC5nfDB4udN5cbXFN3rNZnAnQuTIwstMNyPf+RPf8vb9XfiJ3XJiFSgN1kg1cQc1u0tDWc8wWKU4mBVifBdwQtLnRMoCHYeE62Kw7fVdEB5oqw3igBWxP0j8X9seo7xGthZUhuN+OQRA74xdGgcrhUOkbzohnFVB6t2TY/voMNr3cDhgib1bLif3PQJvQPlWdtosrSuTUiJeY1GojN5RJ2UTHh8mzonpmrR0PSINlYxLVNLjF9ALUVUa438ZMCb9bm0tpDgjjMHIrg1Qwo0MNcRgv8C8t2WrdY7cPcCAwEAAaA8MDoGCSqGSIb3DQEJDjEtMCswKQYDVR0RBCIwIIIMY29yb3MuY29tLnZughB3d3cuY29yb3MuY29tLnZuMA0GCSqGSIb3DQEBCwUAA4IBAQAf1wN6bvMjGXbarLGfBx4PmsougdaXe6iUUiOIcXjo3X3PqmH4ib0Bz7sfiXhbXorV1FNN679FX15Ae9vlBKj9DukeJBob3sR9ebBIrOIsW1R8Fk4KIQPEX3ZH0oTpaHIbNdFtMe8P8PKVqkpL+bIekvPiomA0rpQZECyYVqjuoAERzdhUov3czGo4XeyeItEXxzmNGWNCYsHbbDbWrumvvY8HcGpRbMRsvvLhOqIUFys8fyCM86wG5cv0LaP60re4cZwkjRYhBy+PNO9OdXpkroPoQB7cXXovLDbAA6HirDhJoulRj8ZJayi68sN/gys5TzfQgLLAdc8Eh9cRjqjp\n-----END CERTIFICATE REQUEST-----`

	svc := New()
	resp, err := svc.Decode(context.Background(), input)

	if err != nil {
		t.Fatalf("Decode failed for literal \\n input: %v", err)
	}

	if resp.CommonName != "coros.com.vn" {
		t.Errorf("Expected CN coros.com.vn, got %s", resp.CommonName)
	}
	if len(resp.Sans) != 2 || resp.Sans[0] != "coros.com.vn" {
		t.Errorf("Expected Sans to contain coros.com.vn, got %v", resp.Sans)
	}
}

func TestDecodeNoSans(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "nosans.com"},
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	svc := New()
	resp, _ := svc.Decode(context.Background(), string(csrPEM))

	if len(resp.Sans) != 1 || resp.Sans[0] != "N/A" {
		t.Errorf("Expected Sans N/A, got %v", resp.Sans)
	}
}
