package checker

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"time"

	"tools.bctechvibe.io.vn/server/ssl/internal/models"
)

/*
====================================
 OCSP CACHE ENTRY
====================================
*/

type ocspCacheEntry struct {
	detail   *models.OCSPDetail
	expireAt time.Time
}

/*
====================================
 GLOBAL CACHE
====================================
*/

var ocspCache = struct {
	mu    sync.RWMutex
	items map[string]*ocspCacheEntry
}{
	items: make(map[string]*ocspCacheEntry),
}

/*
====================================
 FINGERPRINT KEY
====================================
*/

func getCertCacheKey(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

/*
====================================
 CACHE GET
====================================
*/

func getOCSPFromCache(
	cert *x509.Certificate,
) (*models.OCSPDetail, bool) {

	if cert == nil {
		return nil, false
	}

	key := getCertCacheKey(cert)

	ocspCache.mu.RLock()
	entry, ok := ocspCache.items[key]
	ocspCache.mu.RUnlock()

	if !ok || entry == nil {
		return nil, false
	}

	// Expired
	if time.Now().After(entry.expireAt) {
		ocspCache.mu.Lock()
		delete(ocspCache.items, key)
		ocspCache.mu.Unlock()
		return nil, false
	}

	return entry.detail, true
}

/*
====================================
 CACHE SET
====================================
*/

func setOCSPCache(
	cert *x509.Certificate,
	detail *models.OCSPDetail,
	ttl time.Duration,
) {

	if cert == nil || detail == nil || ttl <= 0 {
		return
	}

	key := getCertCacheKey(cert)

	ocspCache.mu.Lock()
	ocspCache.items[key] = &ocspCacheEntry{
		detail:   detail,
		expireAt: time.Now().Add(ttl),
	}
	ocspCache.mu.Unlock()
}

/*
====================================
 CACHE DELETE
====================================
*/

func deleteOCSPCache(key string) {
	ocspCache.mu.Lock()
	delete(ocspCache.items, key)
	ocspCache.mu.Unlock()
}
