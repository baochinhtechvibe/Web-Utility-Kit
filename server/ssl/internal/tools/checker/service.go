package checker

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/singleflight"
	"tools.bctechvibe.io.vn/server/ssl/internal/config"
	"tools.bctechvibe.io.vn/server/ssl/internal/models"
	"tools.bctechvibe.io.vn/server/ssl/internal/platform/breaker"
	"tools.bctechvibe.io.vn/server/ssl/internal/platform/cache"
	"tools.bctechvibe.io.vn/server/ssl/internal/platform/shared"
)

type Service struct {
	cache   *cache.MemoryCache
	breaker *breaker.CircuitBreaker

	// group to coalesce concurrent scans for same domain
	sf singleflight.Group

	// allow overriding scanner for tests (optional)
	// return concrete type to match Scan
	scanFunc func(ctx context.Context, domain string) (*models.SSLCheckResponse, error)

	mu sync.Mutex
}

func New() *Service {
	s := &Service{
		cache:   cache.NewMemoryCacheWithCleanup(config.CacheTTL, config.CacheCleanupInterval),
		breaker: breaker.New(),
	}
	s.scanFunc = Scan // default
	return s
}

// NewWithDeps for easier testing
func NewWithDeps(c *cache.MemoryCache, b *breaker.CircuitBreaker) *Service {
	s := &Service{
		cache:   c,
		breaker: b,
	}
	s.scanFunc = Scan
	return s
}

// Check now accepts caller's context so timeouts/cancellation propagate
func (s *Service) Check(ctx context.Context, domain string) (*models.SSLCheckResponse, error) {
	// check cache first
	if r, ok := s.cache.Get(domain); ok {
		if resp, ok := r.(*models.SSLCheckResponse); ok {
			return resp, nil
		}
		// unexpected cached type, ignore and continue
	}

	// breaker
	if !s.breaker.Allow(domain) {
		return nil, shared.ErrBlocked
	}

	// coalesce concurrent scans
	v, err, _ := s.sf.Do(domain, func() (interface{}, error) {
		// call the injected scan func (uses ctx)
		res, err := s.scanFunc(ctx, domain)
		if err != nil {
			s.breaker.Fail(domain)
			return nil, err
		}
		s.breaker.Success(domain)
		s.cache.Set(domain, res)
		return res, nil
	})
	if err != nil {
		return nil, err
	}

	resp, ok := v.(*models.SSLCheckResponse)
	if !ok {
		return nil, fmt.Errorf("invalid scan result type")
	}
	return resp, nil
}
