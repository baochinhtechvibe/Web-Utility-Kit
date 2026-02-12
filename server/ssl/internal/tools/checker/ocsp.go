package checker

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
	"tools.bctechvibe.io.vn/server/ssl/internal/config"
	"tools.bctechvibe.io.vn/server/ssl/internal/models"
)

func ocspRevocationReasonToString(reason int) string {
	switch reason {
	case ocsp.Unspecified:
		return "unspecified"
	case ocsp.KeyCompromise:
		return "key_compromise"
	case ocsp.CACompromise:
		return "ca_compromise"
	case ocsp.AffiliationChanged:
		return "affiliation_changed"
	case ocsp.Superseded:
		return "superseded"
	case ocsp.CessationOfOperation:
		return "cessation_of_operation"
	case ocsp.CertificateHold:
		return "certificate_hold"
	case ocsp.RemoveFromCRL:
		return "remove_from_crl"
	case ocsp.PrivilegeWithdrawn:
		return "privilege_withdrawn"
	case ocsp.AACompromise:
		return "aa_compromise"
	default:
		return "unknown"
	}
}

/*
==================================================
 MAIN ENTRY
==================================================
*/

func checkOCSP(cert, issuer *x509.Certificate) *models.OCSPDetail {

	// 1️⃣ Cache
	if cached, ok := getOCSPFromCache(cert); ok {
		return cached
	}

	// 2️⃣ Real check
	detail := checkOCSPRemote(cert, issuer)

	// 3️⃣ Cache TTL
	ttl := getOCSPTTL(detail)
	setOCSPCache(cert, detail, ttl)

	return detail
}

/*
==================================================
 REMOTE OCSP
==================================================
*/

func checkOCSPRemote(
	cert, issuer *x509.Certificate,
) *models.OCSPDetail {

	if len(cert.OCSPServer) == 0 {
		return &models.OCSPDetail{
			Status:  models.OCSPNoCheck,
			Good:    false,
			Checked: false,
			Error:   "certificate has no OCSP server",
		}
	}

	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return &models.OCSPDetail{
			Status:  models.OCSPError,
			Good:    false,
			Checked: true,
			Error:   "create OCSP request failed: " + err.Error(),
		}
	}

	client := &http.Client{Timeout: config.OCSPCheckTimeout}

	var lastErr error

	for _, server := range cert.OCSPServer {

		if d := checkOCSPByPOST(client, server, req, cert, issuer); d != nil {
			return d
		}

		if d := checkOCSPByGET(client, server, req, cert, issuer); d != nil {
			return d
		}

		lastErr = fmt.Errorf("no valid response from %s", server)
	}

	return &models.OCSPDetail{
		Status:  models.OCSPError,
		Good:    false,
		Checked: true,
		Error:   lastErr.Error(),
	}
}

/*
==================================================
 POST
==================================================
*/

func checkOCSPByPOST(
	client *http.Client,
	server string,
	req []byte,
	cert *x509.Certificate,
	issuer *x509.Certificate,
) *models.OCSPDetail {

	resp, err := client.Post(
		server,
		"application/ocsp-request",
		bytes.NewReader(req),
	)

	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	return parseOCSPResponse(resp, cert, issuer, server)
}

/*
==================================================
 GET (RFC fallback)
==================================================
*/

func checkOCSPByGET(
	client *http.Client,
	server string,
	req []byte,
	cert *x509.Certificate,
	issuer *x509.Certificate,
) *models.OCSPDetail {

	encoded := base64.StdEncoding.EncodeToString(req)
	escaped := url.PathEscape(encoded)
	getURL := strings.TrimRight(server, "/") + "/" + escaped

	resp, err := client.Get(getURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	return parseOCSPResponse(resp, cert, issuer, server)
}

/*
==================================================
 PARSER
==================================================
*/

func parseOCSPResponse(
	resp *http.Response,
	cert *x509.Certificate,
	issuer *x509.Certificate,
	server string,
) *models.OCSPDetail {

	if resp.StatusCode != http.StatusOK {
		return &models.OCSPDetail{
			Status:  models.OCSPError,
			Good:    false,
			Checked: true,
			Server:  server,
			Error:   fmt.Sprintf("http status %d", resp.StatusCode),
		}
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "ocsp") {
		return &models.OCSPDetail{
			Status:  models.OCSPError,
			Good:    false,
			Checked: true,
			Server:  server,
			Error:   "invalid content-type: " + ct,
		}
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return &models.OCSPDetail{
			Status:  models.OCSPError,
			Good:    false,
			Checked: true,
			Server:  server,
			Error:   err.Error(),
		}
	}

	ocspResp, err := ocsp.ParseResponseForCert(data, cert, issuer)
	if err != nil {
		return &models.OCSPDetail{
			Status:  models.OCSPError,
			Good:    false,
			Checked: true,
			Server:  server,
			Error:   err.Error(),
		}
	}

	if !validateOCSPTime(ocspResp) {
		return &models.OCSPDetail{
			Status:  models.OCSPError,
			Good:    false,
			Checked: true,
			Server:  server,
			Error:   "OCSP response expired or not yet valid",
		}
	}

	out := &models.OCSPDetail{
		Server:     server,
		Checked:    true,
		ThisUpdate: ocspResp.ThisUpdate,
		NextUpdate: ocspResp.NextUpdate,
		ProducedAt: ocspResp.ProducedAt,
	}

	switch ocspResp.Status {
	case ocsp.Good:
		out.Status = models.OCSPGood
		out.Good = true

	case ocsp.Revoked:
		out.Status = models.OCSPRevoked
		out.Good = false
		out.RevocationReason = ocspRevocationReasonToString(ocspResp.RevocationReason)

	case ocsp.Unknown:
		out.Status = models.OCSPUnknown
		out.Good = false
	}

	return out
}

/*
==================================================
 TIME VALIDATION
==================================================
*/

func validateOCSPTime(resp *ocsp.Response) bool {

	now := time.Now()

	if now.Before(resp.ThisUpdate.Add(-5 * time.Minute)) {
		return false
	}

	if !resp.NextUpdate.IsZero() &&
		now.After(resp.NextUpdate.Add(5*time.Minute)) {
		return false
	}

	return true
}

/*
==================================================
 TTL
==================================================
*/

func getOCSPTTL(d *models.OCSPDetail) time.Duration {

	if d == nil {
		return 5 * time.Minute
	}

	if d.Status == models.OCSPGood && !d.NextUpdate.IsZero() {
		ttl := time.Until(d.NextUpdate)
		if ttl <= 0 {
			return 5 * time.Minute
		}
		return ttl
	}

	if d.Status == models.OCSPGood {
		return 6 * time.Hour
	}

	return 5 * time.Minute
}
