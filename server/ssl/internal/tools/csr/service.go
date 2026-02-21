package csr

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"

	"tools.bctechvibe.io.vn/server/ssl/internal/models"
)

var (
	ErrInvalidPEM = errors.New("PEM block không hợp lệ")
	ErrInvalidCSR = errors.New("CSR không thể parse được")
)

type Service struct{}

func New() *Service {
	return &Service{}
}

func (s *Service) Decodev1(ctx context.Context, csrPEM string) (*models.CSRDecodeResponse, error) {
	// Preprocess: Fix common formatting issues from JSON/UI inputs
	// Replace literal \n sequences with actual characters (from JSON payload)
	csrPEM = strings.ReplaceAll(csrPEM, `\n`, "\n")
	csrPEM = strings.ReplaceAll(csrPEM, "\r\n", "\n") // Windows CRLF
	csrPEM = strings.TrimSpace(csrPEM)

	// Guard: Kích thước CSR tối đa (100KB)
	// Check after trim/preprocess to ensure checking the actual parsed string length
	const maxCSRSize = 100 * 1024
	if len(csrPEM) > maxCSRSize {
		return nil, errors.New("CSR vượt quá kích thước cho phép")
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 1. Decode PEM
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: failed to decode PEM block", ErrInvalidPEM)
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, fmt.Errorf("%w: multiple PEM blocks detected", ErrInvalidPEM)
	}

	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: invalid PEM type %s", ErrInvalidPEM, block.Type)
	}

	// 2. Parse CSR
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCSR, err.Error())
	}

	if err := req.CheckSignature(); err != nil {
		log.Printf("Kiểm tra chữ ký CSR thất bại: %v", err)
		return nil, fmt.Errorf("%w: signature verification failed", ErrInvalidCSR)
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
		DnsNames:           req.DNSNames,
		EmailAddresses:     req.EmailAddresses,
	}

	// Convert IP Addresses to strings
	for _, ip := range req.IPAddresses {
		resp.IPAddresses = append(resp.IPAddresses, ip.String())
	}

	// Convert URIs to strings
	for _, uri := range req.URIs {
		resp.URIs = append(resp.URIs, uri.String())
	}

	// Tổng hợp tất cả các SANs
	resp.Sans = make([]string, 0)
	resp.Sans = append(resp.Sans, req.DNSNames...)
	resp.Sans = append(resp.Sans, resp.IPAddresses...)
	resp.Sans = append(resp.Sans, req.EmailAddresses...)
	resp.Sans = append(resp.Sans, resp.URIs...)

	if len(resp.Sans) == 0 {
		resp.Sans = []string{"N/A"}
	}

	// 4. Extract Key Info
	resp.Algorithm = req.PublicKeyAlgorithm.String()

	switch pub := req.PublicKey.(type) {
	case *rsa.PublicKey:
		resp.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		resp.KeySize = pub.Params().BitSize
	default:
		resp.KeySize = 0
	}

	return resp, nil
}

func (s *Service) Decode(ctx context.Context, csrPEM string) (*models.CSRDecodeResponse, error) {
	// Preprocess
	csrPEM = strings.ReplaceAll(csrPEM, `\n`, "\n")
	csrPEM = strings.ReplaceAll(csrPEM, "\r\n", "\n")
	csrPEM = strings.TrimSpace(csrPEM)

	const maxCSRSize = 100 * 1024
	if len(csrPEM) > maxCSRSize {
		return nil, errors.New("CSR vượt quá kích thước cho phép")
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Decode PEM
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: failed to decode PEM block", ErrInvalidPEM)
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, fmt.Errorf("%w: multiple PEM blocks detected", ErrInvalidPEM)
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: invalid PEM type %s", ErrInvalidPEM, block.Type)
	}

	// Parse CSR
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCSR, err.Error())
	}

	if err := req.CheckSignature(); err != nil {
		log.Printf("Kiểm tra chữ ký CSR thất bại: %v", err)
		return nil, fmt.Errorf("%w: signature verification failed", ErrInvalidCSR)
	}

	// SAN data presence (semantic)
	hasSANData :=
		len(req.DNSNames) > 0 ||
			len(req.IPAddresses) > 0 ||
			len(req.EmailAddresses) > 0 ||
			len(req.URIs) > 0

	// Aggregate SANs (single list for frontend)
	sans := make([]string, 0,
		len(req.DNSNames)+
			len(req.IPAddresses)+
			len(req.EmailAddresses)+
			len(req.URIs),
	)

	sans = append(sans, req.DNSNames...)
	sans = append(sans, req.EmailAddresses...)

	for _, ip := range req.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range req.URIs {
		sans = append(sans, uri.String())
	}

	// Build response
	resp := &models.CSRDecodeResponse{
		Success:            true,
		CommonName:         req.Subject.CommonName,
		Organization:       req.Subject.Organization,
		OrganizationalUnit: req.Subject.OrganizationalUnit,
		Country:            req.Subject.Country,
		State:              req.Subject.Province,
		Locality:           req.Subject.Locality,

		Sans:            sans,
		HasSANExtension: hasSANData,

		Algorithm: req.PublicKeyAlgorithm.String(),
	}

	switch pub := req.PublicKey.(type) {
	case *rsa.PublicKey:
		resp.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		resp.KeySize = pub.Params().BitSize
	default:
		resp.KeySize = 0
	}

	return resp, nil
}
