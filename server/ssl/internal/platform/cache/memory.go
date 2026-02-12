package cache

import (
	"sync"
	"time"
)

type CacheItem struct {
	Data      interface{}
	ExpiresAt time.Time
}

type MemoryCache struct {
	store         map[string]*CacheItem
	mu            sync.RWMutex
	ttl           time.Duration
	cleanupTicker *time.Ticker
	done          chan bool
}

func NewMemoryCache(ttl time.Duration) *MemoryCache {
	return NewMemoryCacheWithCleanup(ttl, 0)
}

func NewMemoryCacheWithCleanup(ttl, cleanupInterval time.Duration) *MemoryCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if cleanupInterval <= 0 {
		cleanupInterval = ttl / 2
	}
	mc := &MemoryCache{
		store:         make(map[string]*CacheItem),
		ttl:           ttl,
		cleanupTicker: time.NewTicker(cleanupInterval),
		done:          make(chan bool),
	}

	// Start cleanup routine
	go mc.cleanupRoutine()

	return mc
}

func (mc *MemoryCache) Get(key string) (interface{}, bool) {
	mc.mu.RLock()

	item, exists := mc.store[key]
	if !exists {
		mc.mu.RUnlock()
		return nil, false
	}

	if time.Now().After(item.ExpiresAt) {
		mc.mu.RUnlock()
		mc.Delete(key)
		return nil, false
	}

	mc.mu.RUnlock()
	return item.Data, true
}

func (mc *MemoryCache) Set(key string, value interface{}) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.store[key] = &CacheItem{
		Data:      value,
		ExpiresAt: time.Now().Add(mc.ttl),
	}
}

func (mc *MemoryCache) Delete(key string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	delete(mc.store, key)
}

// cleanupRoutine removes expired items periodically
func (mc *MemoryCache) cleanupRoutine() {
	for {
		select {
		case <-mc.cleanupTicker.C:
			mc.cleanup()
		case <-mc.done:
			mc.cleanupTicker.Stop()
			return
		}
	}
}

// cleanup removes all expired items
func (mc *MemoryCache) cleanup() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	now := time.Now()
	for key, item := range mc.store {
		if now.After(item.ExpiresAt) {
			delete(mc.store, key)
		}
	}
}

// Stop stops the cleanup routine
func (mc *MemoryCache) Stop() {
	close(mc.done)
}
