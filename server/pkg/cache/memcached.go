package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
)

// MemcachedCache implements Cache using Memcached
type MemcachedCache struct {
	client     *memcache.Client
	prefix     string
	defaultTTL time.Duration
}

// NewMemcachedCache creates a Memcached-backed cache.
// servers should be a list of "host:port" strings, e.g. ["localhost:11211"].
func NewMemcachedCache(servers []string, prefix string, defaultTTL time.Duration) (*MemcachedCache, error) {
	if len(servers) == 0 {
		servers = []string{"localhost:11211"}
	}
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}

	client := memcache.New(servers...)
	client.Timeout = 3 * time.Second
	client.MaxIdleConns = 10

	// Verify connection
	if err := client.Ping(); err != nil {
		return nil, fmt.Errorf("cache: memcached ping failed: %w", err)
	}

	return &MemcachedCache{
		client:     client,
		prefix:     prefix,
		defaultTTL: defaultTTL,
	}, nil
}

func (mc *MemcachedCache) key(k string) string {
	return mc.prefix + k
}

func (mc *MemcachedCache) Get(_ context.Context, key string) ([]byte, error) {
	item, err := mc.client.Get(mc.key(key))
	if err != nil {
		if err == memcache.ErrCacheMiss {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("cache: memcached get error: %w", err)
	}
	return item.Value, nil
}

func (mc *MemcachedCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = mc.defaultTTL
	}
	item := &memcache.Item{
		Key:        mc.key(key),
		Value:      value,
		Expiration: int32(ttl.Seconds()),
	}
	if err := mc.client.Set(item); err != nil {
		return fmt.Errorf("cache: memcached set error: %w", err)
	}
	return nil
}

func (mc *MemcachedCache) Delete(_ context.Context, key string) error {
	err := mc.client.Delete(mc.key(key))
	if err != nil && err != memcache.ErrCacheMiss {
		return fmt.Errorf("cache: memcached delete error: %w", err)
	}
	return nil
}

func (mc *MemcachedCache) Exists(_ context.Context, key string) (bool, error) {
	_, err := mc.client.Get(mc.key(key))
	if err != nil {
		if err == memcache.ErrCacheMiss {
			return false, nil
		}
		return false, fmt.Errorf("cache: memcached exists error: %w", err)
	}
	return true, nil
}

func (mc *MemcachedCache) Close() error {
	// gomemcache does not have a Close method; connections are pooled and reused.
	return nil
}

func (mc *MemcachedCache) Ping(_ context.Context) error {
	return mc.client.Ping()
}
