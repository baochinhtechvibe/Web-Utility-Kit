package breaker

import (
	"sync"
	"time"

	"tools.bctechvibe.io.vn/server/ssl/internal/config"
)

type CircuitBreaker struct {
	mu            sync.RWMutex
	fails         map[string]int
	blocks        map[string]time.Time
	cleanupTicker *time.Ticker
	done          chan bool
}

func New() *CircuitBreaker {
	cb := &CircuitBreaker{
		fails:         make(map[string]int),
		blocks:        make(map[string]time.Time),
		cleanupTicker: time.NewTicker(config.CircuitBreakerCleanupWindow),
		done:          make(chan bool),
	}

	go cb.cleanupRoutine()
	return cb
}

func (c *CircuitBreaker) Allow(domain string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if t, ok := c.blocks[domain]; ok {
		if time.Now().Before(t) {
			return false
		}
	}

	return true
}

func (c *CircuitBreaker) Fail(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.fails[domain]++

	if c.fails[domain] >= config.CircuitBreakerThreshold {
		c.blocks[domain] = time.Now().Add(config.CircuitBreakerBlockDuration)
	}
}

func (c *CircuitBreaker) Success(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.fails[domain] = 0
}

func (c *CircuitBreaker) cleanupRoutine() {
	for {
		select {
		case <-c.cleanupTicker.C:
			c.cleanup()
		case <-c.done:
			c.cleanupTicker.Stop()
			return
		}
	}
}

func (c *CircuitBreaker) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for domain, blockTime := range c.blocks {
		if now.After(blockTime) {
			delete(c.blocks, domain)
			delete(c.fails, domain)
		}
	}
}

func (c *CircuitBreaker) Stop() {
	close(c.done)
}
