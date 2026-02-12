package checker

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"
)

func verifyChainOffline(certs []*x509.Certificate) error {

	if len(certs) == 0 {
		return errors.New("empty certificate chain")
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	// Load system roots
	sysRoots, err := x509.SystemCertPool()
	if err != nil {
		log.Printf("Warning: failed to load system cert pool: %v, using empty pool", err)
		// Continue with empty pool, it's not fatal
	}

	if sysRoots != nil {
		roots = sysRoots
	}

	// Add intermediates
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	_, err = certs[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return nil
}
