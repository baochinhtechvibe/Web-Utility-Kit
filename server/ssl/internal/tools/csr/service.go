package csr

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"tools.bctechvibe.io.vn/server/ssl/internal/models"
)

type Service struct{}

func New() *Service {
	return &Service{}
}

func (s *Service) Decode(ctx context.Context, csrPEM string) (*models.CSRDecodeResponse, error) {
	// Preprocess: Fix common formatting issues from JSON/UI inputs
	// Replace literal \n and \r sequences with actual characters
	csrPEM = strings.ReplaceAll(csrPEM, `\n`, "\n")
	csrPEM = strings.ReplaceAll(csrPEM, `\r`, "\r")
	csrPEM = strings.TrimSpace(csrPEM)

	// 1. Decode PEM
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing CSR")
	}

	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid PEM type: %s", block.Type)
	}

	// 2. Parse CSR
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	// 3. Extract Info
	resp := &models.CSRDecodeResponse{
		Success:            true,
		CommonName:         req.Subject.CommonName,
		Organization:       req.Subject.Organization,
		OrganizationalUnit: req.Subject.OrganizationalUnit,
		Country:            req.Subject.Country,
		State:              req.Subject.Province,
		Locality:           req.Subject.Locality,
		Sans:               req.DNSNames,
		CSR:                csrPEM,
	}

	// Add IP Addresses to SANs
	for _, ip := range req.IPAddresses {
		resp.Sans = append(resp.Sans, ip.String())
	}

	// Add Email Addresses to SANs
	for _, email := range req.EmailAddresses {
		resp.Sans = append(resp.Sans, email)
	}

	// 4. Extract Key Info
	switch pub := req.PublicKey.(type) {
	case *rsa.PublicKey:
		resp.Algorithm = "RSA Encryption"
		resp.KeySize = pub.Size() * 8 // bytes to bits
	case *ecdsa.PublicKey:
		resp.Algorithm = "ECDSA Encryption"
		resp.KeySize = pub.Params().BitSize
	default:
		resp.Algorithm = "Unknown Algorithm"
		resp.KeySize = 0
	}

	return resp, nil
}
