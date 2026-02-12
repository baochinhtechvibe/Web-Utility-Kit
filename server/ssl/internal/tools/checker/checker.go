package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"tools.bctechvibe.io.vn/server/ssl/internal/config"
	"tools.bctechvibe.io.vn/server/ssl/internal/models"
)

var ErrNoIP = errors.New("no valid ip")

// ===========================
// TRUST ANALYSIS
// ===========================

type TrustResult struct {
	Trusted bool
	Issues  []models.TrustIssue
}

type ExpiredCertInfo struct {
	Cert    *x509.Certificate
	DaysAgo int64
}

func detectChainLevel(
	index int,
	total int,
) models.CertLevel {

	// Leaf cert
	if index == 0 {
		return models.CertLevelDomain
	}

	// Last cert
	if index == total-1 {
		return models.CertLevelRoot
	}

	// Middle certs
	return models.CertLevelIntermediate
}

func findIssuer(
	leaf *x509.Certificate,
	candidates []*x509.Certificate,
) *x509.Certificate {

	for _, c := range candidates {

		// Issuer DN phải match
		if leaf.Issuer.String() != c.Subject.String() {
			continue
		}

		// Verify chữ ký
		if err := leaf.CheckSignatureFrom(c); err == nil {
			return c
		}
	}

	return nil
}

func isSelfSigned(cert *x509.Certificate) bool {

	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}

	return cert.CheckSignatureFrom(cert) == nil
}

func isOpenSSLSelfSignedLeaf(
	leaf *x509.Certificate,
	certs []*x509.Certificate,
) bool {

	// Subject == Issuer
	if leaf.Subject.String() != leaf.Issuer.String() {
		return false
	}

	// Không tìm được issuer hợp lệ trong chain
	for i := 1; i < len(certs); i++ {

		if leaf.CheckSignatureFrom(certs[i]) == nil {
			return false
		}
	}

	return true
}

func hasSelfSignedInChain(certs []*x509.Certificate) bool {

	// skip leaf
	for i := 1; i < len(certs); i++ {

		if isSelfSigned(certs[i]) {
			return true
		}
	}

	return false
}

/* ===========================
   DNS RESOLUTION
=========================== */

func resolveIP(ctx context.Context, domain string) (string, error) {

	type result struct {
		ips []net.IP
		err error
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ch := make(chan result, 2)

	go func() {
		ips, err := lookupWithDNS(ctx, domain, "8.8.8.8:53")
		ch <- result{ips, err}
	}()

	go func() {
		r := &net.Resolver{}
		ips, err := r.LookupIP(ctx, "ip", domain)
		ch <- result{ips, err}
	}()

	var lastErr error

	for i := 0; i < 2; i++ {
		select {
		case res := <-ch:
			if res.err == nil && len(res.ips) > 0 {
				return pickIP(res.ips)
			}
			if res.err != nil {
				lastErr = res.err
			}
		case <-ctx.Done():
			return "", ErrNoIP
		}
	}

	if lastErr != nil {
		return "", lastErr
	}

	return "", ErrNoIP
}

func pickIP(ips []net.IP) (string, error) {

	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return v4.String(), nil
		}
	}

	for _, ip := range ips {
		if ip.To16() != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return ip.String(), nil
		}
	}

	return "", ErrNoIP
}

func lookupWithDNS(
	parent context.Context,
	domain, dnsAddr string,
) ([]net.IP, error) {

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", dnsAddr)
		},
	}

	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()

	return r.LookupIP(ctx, "ip", domain)
}

/* ===========================
   TLS HELPERS
=========================== */

func detectTLSVersion(state tls.ConnectionState) string {

	switch state.Version {
	case tls.VersionTLS13:
		return config.TLSVersion13
	case tls.VersionTLS12:
		return config.TLSVersion12
	case tls.VersionTLS11:
		return config.TLSVersion11
	case tls.VersionTLS10:
		return config.TLSVersion10
	default:
		return "Unknown"
	}
}

/* ===========================
   MAIN SCANNER
=========================== */

func Scan(
	ctx context.Context,
	domain string,
) (*models.SSLCheckResponse, error) {

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	ip, err := resolveIP(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("dns resolve failed: %w", err)
	}

	dialer := &net.Dialer{Timeout: config.TLSDialTimeout}

	addrDomain := net.JoinHostPort(domain, "443")
	addrIP := net.JoinHostPort(ip, "443")

	baseConf := &tls.Config{ServerName: domain}

	var (
		conn *tls.Conn
	)

	conn, err = dialTLS(ctx, dialer, addrDomain, baseConf)
	if err != nil {
		conn, err = dialTLS(ctx, dialer, addrIP, baseConf)
	}

	if err != nil {

		log.Printf("[SSL] strict TLS failed (%s): %v", domain, err)

		insecure := baseConf.Clone()
		insecure.InsecureSkipVerify = true

		conn, err = dialTLS(ctx, dialer, addrDomain, insecure)
		if err != nil {
			conn, err = dialTLS(ctx, dialer, addrIP, insecure)
		}

		if err != nil {
			return nil, fmt.Errorf("tls dial failed: %w", err)
		}
	}

	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates

	if len(certs) == 0 {
		return nil, errors.New("no certificates found")
	}

	serverType := detectServerType(ctx, domain)
	tlsVersion := detectTLSVersion(state)
	hostnameOK := certs[0].VerifyHostname(domain) == nil

	// Analyze certificate trust
	trust := analyzeTrust(certs, domain)

	trusted := trust.Trusted
	var trustReason string
	if len(trust.Issues) > 0 {
		var msgs []string
		for _, i := range trust.Issues {
			msgs = append(msgs, i.Message)
		}
		trustReason = strings.Join(msgs, " ")
	}

	// [UPDATED] Gọi hàm buildFullCertChain đã refactor
	chain := buildFullCertChain(certs, trusted)

	mainCert := certs[0]
	now := time.Now()

	daysLeft := int64(time.Until(mainCert.NotAfter).Hours() / 24)
	valid := now.After(mainCert.NotBefore) && now.Before(mainCert.NotAfter)

	return &models.SSLCheckResponse{
		Hostname:    domain,
		IP:          ip,
		ServerType:  serverType,
		Valid:       valid,
		DaysLeft:    daysLeft,
		TLSVersion:  tlsVersion,
		HostnameOK:  hostnameOK,
		Trusted:     trusted,
		TrustIssues: trust.Issues,
		TrustReason: trustReason,
		CertChain:   chain,
		CheckTime:   time.Now(),
		Success:     true,
	}, nil
}

// ===========================
// TRUST ANALYZER
// ===========================

func analyzeTrust(certs []*x509.Certificate, domain string) TrustResult {

	var issues []models.TrustIssue
	now := time.Now()

	// =========================
	// 1. Expired
	// =========================

	total := len(certs)

	// ---- Leaf cert expired (Website)
	leaf := certs[0]

	if now.After(leaf.NotAfter) {

		days := int64(now.Sub(leaf.NotAfter).Hours() / 24)

		issues = append(issues, models.TrustIssue{
			Code: models.TrustCertExpired, // NEW CODE
			Message: fmt.Sprintf(
				`Chứng chỉ của website đã hết hạn (%d ngày trước).`,
				days,
			),
		})
	}

	// ---- Intermediate / Root expired
	for i := 1; i < total; i++ {

		cert := certs[i]

		if now.After(cert.NotAfter) {

			days := int64(now.Sub(cert.NotAfter).Hours() / 24)

			issues = append(issues, models.TrustIssue{
				Code: models.TrustChainExpired,
				Message: fmt.Sprintf(
					"Một trong các chứng chỉ trung gian hoặc gốc đã hết hạn (%d ngày trước).",
					days,
				),
			})
		}
	}

	// =========================
	// 2. Chain verify
	// =========================

	if _, err := buildVerifiedChain(certs); err != nil {

		if hasFatalCause(issues) {
			goto HOSTNAME_CHECK
		}

		leaf := certs[0]

		if isOpenSSLSelfSignedLeaf(leaf, certs) {
			issues = append(issues, models.TrustIssue{
				Code:    models.TrustSelfSignedLeaf,
				Message: "Chứng chỉ website là chứng chỉ tự ký (self-signed), không được CA tin cậy xác thực: 18 (self-signed certificate)",
			})
		} else if hasSelfSignedInChain(certs) {
			issues = append(issues, models.TrustIssue{
				Code:    models.TrustSelfSignedChain,
				Message: "Chuỗi chứng chỉ có chứa chứng chỉ tự ký, làm mất độ tin cậy của website: 19 (self-signed certificate in certificate chain)",
			})
		} else if strings.Contains(err.Error(), "unable to get issuer") {
			issues = append(issues, models.TrustIssue{
				Code:    models.TrustMissingIssuer,
				Message: "Chuỗi chứng chỉ bị thiếu chứng chỉ trung gian (intermediate), khiến trình duyệt không thể xác thực.",
			})
		} else if strings.Contains(err.Error(), "unknown authority") {
			issues = append(issues, models.TrustIssue{
				Code:    models.TrustUntrustedRoot,
				Message: "Chứng chỉ được ký bởi tổ chức chứng thực không nằm trong danh sách tin cậy của hệ thống.",
			})
		} else {
			issues = append(issues, models.TrustIssue{
				Code:    models.TrustBadChain,
				Message: "Chuỗi chứng chỉ không hợp lệ hoặc bị hỏng, không thể xác minh.",
			})
		}
	}

HOSTNAME_CHECK:

	// =========================
	// 3. Hostname
	// =========================

	if err := certs[0].VerifyHostname(domain); err != nil {
		issues = append(issues, models.TrustIssue{
			Code: models.TrustNameMismatch,
			Message: fmt.Sprintf(
				"Không có tên thông dụng nào trong chứng chỉ trùng khớp với hostname đã nhập (%s). Bạn có thể gặp lỗi khi truy cập trang web này bằng trình duyệt web.",
				domain,
			),
		})
	}

	// =========================
	// 4. Result
	// =========================

	trusted := true

	for _, issue := range issues {
		if isFatalTrustIssue(issue.Code) {
			trusted = false
			break
		}
	}

	return TrustResult{
		Trusted: trusted,
		Issues:  issues,
	}
}

func isFatalTrustIssue(code models.TrustCode) bool {

	switch code {

	case models.TrustSelfSignedLeaf,
		models.TrustSelfSignedChain,
		models.TrustMissingIssuer,
		models.TrustBadChain,
		models.TrustUntrustedRoot,
		models.TrustCertExpired,
		models.TrustChainExpired,
		// models.TrustNameMismatch,
		models.TrustUnknown:

		return true
	}

	return false
}

func hasFatalCause(issues []models.TrustIssue) bool {

	for _, i := range issues {

		switch i.Code {

		case models.TrustSelfSignedLeaf,
			models.TrustSelfSignedChain,
			models.TrustMissingIssuer,
			models.TrustBadChain,
			models.TrustUntrustedRoot,
			models.TrustCertExpired,
			models.TrustChainExpired,
			models.TrustNameMismatch,
			models.TrustUnknown:

			return true
		}
	}

	return false
}

/* ===========================
   TLS DIAL
=========================== */

func dialTLS(
	ctx context.Context,
	dialer *net.Dialer,
	addr string,
	conf *tls.Config,
) (*tls.Conn, error) {

	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(raw, conf)

	if err = conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}

	return conn, nil
}

// [MODIFIED] Logic xây dựng chain hiển thị (đã lọc Root hệ thống)
func buildFullCertChain(
	certs []*x509.Certificate,
	trusted bool,
) []models.CertDetail {

	var chainCerts []*x509.Certificate

	// 1. Thử lấy Verified Chain (thường sẽ đầy đủ từ Leaf -> ... -> System Root)
	verified, err := buildVerifiedChain(certs)
	if err == nil && len(verified) > 0 {
		chainCerts = verified
	} else {
		// Fallback: dùng raw list nếu không verify được
		chainCerts = certs
	}

	// =================================================================
	// LOGIC MỚI: Ẩn Root CA của hệ thống (Browser/Store)
	// =================================================================
	// Nếu chuỗi có > 1 cert và cert cuối cùng là Root tự ký (Issuer == Subject),
	// ta sẽ loại bỏ nó để chỉ hiển thị đến cấp Intermediate/Cross-Root cao nhất.
	if len(chainCerts) > 1 {
		lastIdx := len(chainCerts) - 1
		lastCert := chainCerts[lastIdx]

		// Kiểm tra Self-Signed (Dấu hiệu của System Root)
		if lastCert.Subject.String() == lastCert.Issuer.String() {
			// Cắt bỏ phần tử cuối cùng
			chainCerts = chainCerts[:lastIdx]
		}
	}

	out := make([]models.CertDetail, 0, len(chainCerts))
	total := len(chainCerts)

	for i, cert := range chainCerts {

		fp1, fp256 := buildFingerprint(cert)

		// Tính level dựa trên mảng đã rút gọn
		level := detectChainLevel(i, total)

		out = append(out, models.CertDetail{
			CommonName: cert.Subject.CommonName,
			Issuer:     cert.Issuer.CommonName,
			Level:      level,

			Organization: cert.Subject.Organization,
			Country:      cert.Subject.Country,
			Locality:     cert.Subject.Locality,
			Province:     cert.Subject.Province,
			SANs:         cert.DNSNames,

			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,

			SerialNumberDec: cert.SerialNumber.String(),
			SerialNumberHex: cert.SerialNumber.Text(16),

			SignatureAlgo: cert.SignatureAlgorithm.String(),

			FingerprintSHA1:   fp1,
			FingerprintSHA256: fp256,

			IsCA: cert.IsCA,
		})
	}

	return out
}

func buildVerifiedChain(
	certs []*x509.Certificate,
) ([]*x509.Certificate, error) {

	if len(certs) == 0 {
		return nil, errors.New("empty certificate chain")
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	intermediates := x509.NewCertPool()

	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		return nil, err
	}

	if len(chains) == 0 {
		return nil, errors.New("verify returned empty chain")
	}

	return chains[0], nil
}
