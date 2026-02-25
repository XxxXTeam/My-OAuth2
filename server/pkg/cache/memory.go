package cache

import (
	"context"
	"sync"
	"time"
)

type memoryEntry struct {
	data      []byte
	expiresAt time.Time
}

func (e *memoryEntry) isExpired() bool {
	return time.Now().After(e.expiresAt)
}

// MemoryCache is an in-process cache with TTL support
type MemoryCache struct {
	mu         sync.RWMutex
	items      map[string]*memoryEntry
	defaultTTL time.Duration
	stopCh     chan struct{}
	closeOnce  sync.Once
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache(defaultTTL time.Duration) *MemoryCache {
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}
	mc := &MemoryCache{
		items:      make(map[string]*memoryEntry),
		defaultTTL: defaultTTL,
		stopCh:     make(chan struct{}),
	}
	go mc.cleanupLoop()
	return mc
}

func (mc *MemoryCache) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			mc.cleanup()
		case <-mc.stopCh:
			return
		}
	}
}

func (mc *MemoryCache) cleanup() {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	now := time.Now()
	for k, v := range mc.items {
		if now.After(v.expiresAt) {
			delete(mc.items, k)
		}
	}
}

func (mc *MemoryCache) Get(_ context.Context, key string) ([]byte, error) {
	mc.mu.RLock()
	entry, ok := mc.items[key]
	mc.mu.RUnlock()

	if !ok || entry.isExpired() {
		if ok && entry.isExpired() {
			// Lazy delete
			mc.mu.Lock()
			delete(mc.items, key)
			mc.mu.Unlock()
		}
		return nil, ErrNotFound
	}

	// Return a copy
	result := make([]byte, len(entry.data))
	copy(result, entry.data)
	return result, nil
}

func (mc *MemoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = mc.defaultTTL
	}
	data := make([]byte, len(value))
	copy(data, value)

	mc.mu.Lock()
	mc.items[key] = &memoryEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}
	mc.mu.Unlock()
	return nil
}

func (mc *MemoryCache) Delete(_ context.Context, key string) error {
	mc.mu.Lock()
	delete(mc.items, key)
	mc.mu.Unlock()
	return nil
}

func (mc *MemoryCache) Exists(_ context.Context, key string) (bool, error) {
	mc.mu.RLock()
	entry, ok := mc.items[key]
	mc.mu.RUnlock()

	if !ok || entry.isExpired() {
		return false, nil
	}
	return true, nil
}

func (mc *MemoryCache) Close() error {
	mc.closeOnce.Do(func() {
		close(mc.stopCh)
	})
	return nil
}

func (mc *MemoryCache) Ping(_ context.Context) error {
	return nil // Always healthy
}
