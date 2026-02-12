package checker

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"time"

	"tools.bctechvibe.io.vn/server/ssl/internal/config"
	"tools.bctechvibe.io.vn/server/ssl/internal/models"
)

func scanTLSv1(domain string) []models.TLSScanResult {

	var results []models.TLSScanResult

	versions := []struct {
		Name string
		ID   uint16
	}{
		{config.TLSVersion13, tls.VersionTLS13},
		{config.TLSVersion12, tls.VersionTLS12},
		{config.TLSVersion11, tls.VersionTLS11},
		{config.TLSVersion10, tls.VersionTLS10},
	}

	for _, v := range versions {
		dialer := &net.Dialer{
			Timeout: config.TLSScanTimeout,
		}

		conn, err := tls.DialWithDialer(
			dialer,
			"tcp",
			domain+":443",
			&tls.Config{
				ServerName: domain,
				MinVersion: v.ID,
				MaxVersion: v.ID,
			},
		)

		if err != nil {
			log.Printf("TLS scan: %s not supported: %v", v.Name, err)
			continue
		}

		state := conn.ConnectionState()
		conn.Close()

		cipher := tls.CipherSuiteName(state.CipherSuite)
		secure := isSecureCipher(cipher)

		results = append(results, models.TLSScanResult{
			Version: v.Name,
			Cipher:  cipher,
			Secure:  secure,
		})
	}

	return results
}

func scanTLSv2(domain string) []models.TLSScanResult {

	var results []models.TLSScanResult

	versions := []struct {
		Name string
		ID   uint16
	}{
		{config.TLSVersion13, tls.VersionTLS13},
		{config.TLSVersion12, tls.VersionTLS12},
		{config.TLSVersion11, tls.VersionTLS11},
		{config.TLSVersion10, tls.VersionTLS10},
	}

	for _, v := range versions {

		dialer := &net.Dialer{
			Timeout: config.TLSScanTimeout,
		}

		conn, err := tls.DialWithDialer(
			dialer,
			"tcp",
			domain+":443",
			&tls.Config{
				ServerName:         domain,
				MinVersion:         v.ID,
				MaxVersion:         v.ID,
				InsecureSkipVerify: true, // QUAN TRỌNG
			},
		)

		if err != nil {
			log.Printf("TLS scan: %s not supported: %v", v.Name, err)
			continue
		}

		_ = conn.SetDeadline(
			time.Now().Add(config.TLSScanTimeout),
		)

		state := conn.ConnectionState()
		_ = conn.Close()

		cipher := tls.CipherSuiteName(state.CipherSuite)

		secure := true
		if v.ID != tls.VersionTLS13 {
			secure = isSecureCipher(cipher)
		}

		results = append(results, models.TLSScanResult{
			Version: v.Name,
			Cipher:  cipher,
			Secure:  secure,
		})
	}

	if results == nil {
		results = []models.TLSScanResult{}
	}

	return results
}

func scanTLS(
	ctx context.Context,
	domain string,
) []models.TLSScanResult {

	var results []models.TLSScanResult

	versions := []struct {
		Name string
		ID   uint16
	}{
		{config.TLSVersion13, tls.VersionTLS13},
		{config.TLSVersion12, tls.VersionTLS12},
		{config.TLSVersion11, tls.VersionTLS11},
		{config.TLSVersion10, tls.VersionTLS10},
	}

	for _, v := range versions {

		// Stop if context cancelled
		select {
		case <-ctx.Done():
			log.Printf("[TLS] scan cancelled: %v", ctx.Err())
			return results
		default:
		}

		dialer := &net.Dialer{
			Timeout: config.TLSScanTimeout,
		}

		// Use DialContext instead
		rawConn, err := dialer.DialContext(
			ctx,
			"tcp",
			domain+":443",
		)

		if err != nil {
			log.Printf("[TLS] %s dial failed: %v", v.Name, err)
			continue
		}

		conf := &tls.Config{
			ServerName:         domain,
			MinVersion:         v.ID,
			MaxVersion:         v.ID,
			InsecureSkipVerify: true,
		}

		tlsConn := tls.Client(rawConn, conf)

		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			_ = rawConn.Close()
			log.Printf("[TLS] %s handshake failed: %v", v.Name, err)
			continue
		}

		state := tlsConn.ConnectionState()
		_ = tlsConn.Close()

		cipher := tls.CipherSuiteName(state.CipherSuite)

		secure := true
		if v.ID != tls.VersionTLS13 {
			secure = isSecureCipher(cipher)
		}

		results = append(results, models.TLSScanResult{
			Version: v.Name,
			Cipher:  cipher,
			Secure:  secure,
		})
	}

	if results == nil {
		results = []models.TLSScanResult{}
	}

	return results
}
