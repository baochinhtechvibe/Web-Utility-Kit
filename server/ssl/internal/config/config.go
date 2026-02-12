package config

import "time"

// Server configuration
const (
	ServerPort = ":3102"
)

// TLS & HTTP timeouts
const (
	TLSDialTimeout   = 8 * time.Second
	HTTPHeadTimeout  = 5 * time.Second
	OCSPCheckTimeout = 5 * time.Second
	TLSScanTimeout   = 6 * time.Second
	ContextTimeout   = 10 * time.Second
)

// Cache configuration
const (
	CacheTTL             = 5 * time.Minute
	CacheCleanupInterval = 2 * 30 * time.Second // TTL / 2
)

// Rate limiter configuration
const (
	RateLimitRequests = 10
	RateLimitWindow   = time.Second
)

// Rate limiter advanced configuration (PRO)
const (

	// Max number of tracked IPs in memory (anti OOM / DDoS)
	// Recommend:
	//  - Dev: 10k
	//  - Prod: 100k - 500k
	MaxRateLimitBuckets = 100_000

	// Trust proxy headers (X-Forwarded-For, CF-Connecting-IP...)
	// true  = Behind Nginx / Cloudflare / LB
	// false = Direct access / Dev
	TrustProxy = false
)

// Circuit breaker configuration
const (
	CircuitBreakerThreshold     = 5
	CircuitBreakerBlockDuration = 10 * time.Minute
	CircuitBreakerCleanupWindow = 20 * time.Minute
)

// TLS versions
const (
	TLSVersion13 = "TLS 1.3"
	TLSVersion12 = "TLS 1.2"
	TLSVersion11 = "TLS 1.1"
	TLSVersion10 = "TLS 1.0"
)

// Certificate status
const (
	StatusOK       = "ok"
	StatusWarning  = "warning"
	StatusCritical = "critical"
)

// Grades
const (
	GradeAPlus = "A+"
	GradeA     = "A"
	GradeB     = "B"
	GradeC     = "C"
	GradeF     = "F"
)

// Domain validation
const (
	MaxDomainLength = 253
	MinDomainLength = 1
)

// Certificate expiry thresholds (days)
const (
	CertExpirySoonThreshold = 30
	CertExpiryWarningDays   = 180
)
