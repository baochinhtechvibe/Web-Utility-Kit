package middleware

import (
	"hash/fnv"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/* ===============================
   CONFIG
================================*/

const (
	shardCount = 32
)

/* ===============================
   STRUCTS
================================*/

type tokenBucket struct {
	count int
	last  time.Time
	mu    sync.Mutex
}

type bucketShard struct {
	buckets map[string]*tokenBucket
	mu      sync.RWMutex
	size    int64
}

type RateLimiter struct {
	shards []bucketShard

	limit  int
	window time.Duration

	maxPerShard int

	// Security
	trustProxy bool

	// Whitelist
	whitelist   map[string]struct{}
	whitelistMu sync.RWMutex

	blocked int64

	cleanup  *time.Ticker
	stopChan chan struct{}
	stopOnce sync.Once
}

/* ===============================
   CONSTRUCTOR
================================*/

func NewRateLimiter(
	limit int,
	window time.Duration,
	maxBuckets int,
	trustProxy bool,
) *RateLimiter {

	if window <= 0 {
		window = time.Second
	}

	if maxBuckets <= 0 {
		maxBuckets = 100_000
	}

	interval := window / 2
	if interval < time.Second {
		interval = time.Second
	}

	rl := &RateLimiter{
		shards:      make([]bucketShard, shardCount),
		limit:       limit,
		window:      window,
		maxPerShard: maxBuckets / shardCount,
		trustProxy:  trustProxy,

		whitelist: make(map[string]struct{}),

		cleanup:  time.NewTicker(interval),
		stopChan: make(chan struct{}),
	}

	for i := range rl.shards {
		rl.shards[i].buckets = make(map[string]*tokenBucket)
	}

	go rl.cleanupLoop()

	return rl
}

/* ===============================
   WHITELIST
================================*/

func (rl *RateLimiter) AddWhitelist(ip string) {
	if ip == "" {
		return
	}

	rl.whitelistMu.Lock()
	rl.whitelist[ip] = struct{}{}
	rl.whitelistMu.Unlock()
}

func (rl *RateLimiter) isWhitelisted(ip string) bool {
	rl.whitelistMu.RLock()
	_, ok := rl.whitelist[ip]
	rl.whitelistMu.RUnlock()

	return ok
}

/* ===============================
   IP
================================*/

func (rl *RateLimiter) GetClientIP(
	addr string,
	h http.Header,
) string {

	if rl.trustProxy {

		for _, k := range []string{
			"X-Forwarded-For",
			"X-Real-IP",
			"CF-Connecting-IP",
		} {

			v := h.Get(k)

			if v == "" {
				continue
			}

			ips := strings.Split(v, ",")

			for _, ip := range ips {

				ip = strings.TrimSpace(ip)

				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
	}

	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}

	return addr
}

/* ===============================
   CORE
================================*/

func (rl *RateLimiter) IsAllowed(ip string) bool {

	if ip == "" {
		return false
	}

	if rl.isWhitelisted(ip) {
		return true
	}

	shard := rl.getShard(ip)

	// Read first
	shard.mu.RLock()
	b, ok := shard.buckets[ip]
	shard.mu.RUnlock()

	if !ok {

		shard.mu.Lock()

		// Double-check
		if b, ok = shard.buckets[ip]; !ok {

			if atomic.LoadInt64(&shard.size) >= int64(rl.maxPerShard) {
				rl.evictOldest(shard, 10)
			}

			b = &tokenBucket{
				count: 1,
				last:  time.Now(),
			}

			shard.buckets[ip] = b
			atomic.AddInt64(&shard.size, 1)
		}

		shard.mu.Unlock()

		return true
	}

	// Update bucket
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	if now.Sub(b.last) > rl.window {
		b.count = 1
		b.last = now
		return true
	}

	b.count++
	b.last = now

	if b.count > rl.limit {
		atomic.AddInt64(&rl.blocked, 1)
		return false
	}

	return true
}

/* ===============================
   SHARD
================================*/

func (rl *RateLimiter) getShard(ip string) *bucketShard {

	h := fnv.New32a()
	h.Write([]byte(ip))

	idx := int(h.Sum32() % uint32(shardCount))

	return &rl.shards[idx]
}

/* ===============================
   CLEANUP
================================*/

func (rl *RateLimiter) cleanupLoop() {

	for {
		select {

		case <-rl.cleanup.C:
			rl.cleanupExpired()

		case <-rl.stopChan:
			rl.cleanup.Stop()
			return
		}
	}
}

func (rl *RateLimiter) cleanupExpired() {

	expire := time.Now().Add(-rl.window * 2)

	for i := range rl.shards {

		shard := &rl.shards[i]

		type victim struct {
			ip string
			b  *tokenBucket
		}

		var candidates []victim

		// Phase 1: collect
		shard.mu.RLock()

		for ip, b := range shard.buckets {
			candidates = append(candidates, victim{ip, b})
		}

		shard.mu.RUnlock()

		if len(candidates) == 0 {
			continue
		}

		var toDelete []string

		// Phase 2: check
		for _, v := range candidates {

			v.b.mu.Lock()
			last := v.b.last
			v.b.mu.Unlock()

			if last.Before(expire) {
				toDelete = append(toDelete, v.ip)
			}
		}

		if len(toDelete) == 0 {
			continue
		}

		// Phase 3: delete
		shard.mu.Lock()

		for _, ip := range toDelete {

			if _, ok := shard.buckets[ip]; ok {
				delete(shard.buckets, ip)
				atomic.AddInt64(&shard.size, -1)
			}
		}

		shard.mu.Unlock()
	}
}

/* ===============================
   EVICTION
================================*/

func (rl *RateLimiter) evictOldest(
	shard *bucketShard,
	n int,
) {

	if n <= 0 {
		return
	}

	type entry struct {
		ip   string
		last time.Time
	}

	var list []entry

	for ip, b := range shard.buckets {

		b.mu.Lock()
		last := b.last
		b.mu.Unlock()

		list = append(list, entry{ip, last})
	}

	if len(list) <= n {
		return
	}

	// Sort by oldest
	for i := 0; i < n; i++ {

		min := i

		for j := i + 1; j < len(list); j++ {
			if list[j].last.Before(list[min].last) {
				min = j
			}
		}

		list[i], list[min] = list[min], list[i]
	}

	for i := 0; i < n; i++ {

		if _, ok := shard.buckets[list[i].ip]; ok {

			delete(shard.buckets, list[i].ip)
			atomic.AddInt64(&shard.size, -1)
		}
	}
}

/* ===============================
   STOP
================================*/

func (rl *RateLimiter) Stop() {

	rl.stopOnce.Do(func() {
		close(rl.stopChan)
	})
}
