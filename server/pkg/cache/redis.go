package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache implements Cache using Redis
type RedisCache struct {
	client     *redis.Client
	prefix     string
	defaultTTL time.Duration
}

// NewRedisCache creates a Redis-backed cache
func NewRedisCache(redisURL, prefix string, defaultTTL time.Duration) (*RedisCache, error) {
	if redisURL == "" {
		redisURL = "redis://localhost:6379/0"
	}
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("cache: invalid redis URL: %w", err)
	}

	// Tune pool settings
	opts.PoolSize = 20
	opts.MinIdleConns = 5
	opts.ConnMaxIdleTime = 5 * time.Minute
	opts.DialTimeout = 5 * time.Second
	opts.ReadTimeout = 3 * time.Second
	opts.WriteTimeout = 3 * time.Second

	client := redis.NewClient(opts)

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("cache: redis ping failed: %w", err)
	}

	return &RedisCache{
		client:     client,
		prefix:     prefix,
		defaultTTL: defaultTTL,
	}, nil
}

func (rc *RedisCache) key(k string) string {
	return rc.prefix + k
}

func (rc *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := rc.client.Get(ctx, rc.key(key)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("cache: redis get error: %w", err)
	}
	return data, nil
}

func (rc *RedisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = rc.defaultTTL
	}
	if err := rc.client.Set(ctx, rc.key(key), value, ttl).Err(); err != nil {
		return fmt.Errorf("cache: redis set error: %w", err)
	}
	return nil
}

func (rc *RedisCache) Delete(ctx context.Context, key string) error {
	if err := rc.client.Del(ctx, rc.key(key)).Err(); err != nil {
		return fmt.Errorf("cache: redis del error: %w", err)
	}
	return nil
}

func (rc *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	n, err := rc.client.Exists(ctx, rc.key(key)).Result()
	if err != nil {
		return false, fmt.Errorf("cache: redis exists error: %w", err)
	}
	return n > 0, nil
}

func (rc *RedisCache) Close() error {
	return rc.client.Close()
}

func (rc *RedisCache) Ping(ctx context.Context) error {
	return rc.client.Ping(ctx).Err()
}

// --- Redis-based distributed rate limiter ---

// RedisRateLimiter provides distributed rate limiting via Redis
type RedisRateLimiter struct {
	client *redis.Client
	prefix string
}

// NewRedisRateLimiter creates a rate limiter backed by Redis
func NewRedisRateLimiter(client *redis.Client, prefix string) *RedisRateLimiter {
	return &RedisRateLimiter{client: client, prefix: prefix}
}

// NewRedisRateLimiterFromCache creates a rate limiter from RedisCache
func NewRedisRateLimiterFromCache(rc *RedisCache) *RedisRateLimiter {
	return &RedisRateLimiter{client: rc.client, prefix: rc.prefix + "rl:"}
}

// Allow checks if a request is allowed using sliding window rate limiting
// rate: max requests per window, window: time window duration
func (rl *RedisRateLimiter) Allow(ctx context.Context, key string, rate int, window time.Duration) (bool, error) {
	fullKey := rl.prefix + key

	// Lua script for atomic sliding window rate limiting
	script := redis.NewScript(`
		local key = KEYS[1]
		local limit = tonumber(ARGV[1])
		local window = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])

		-- Remove expired entries
		redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

		-- Count current entries
		local count = redis.call('ZCARD', key)

		if count < limit then
			-- Add current request
			redis.call('ZADD', key, now, now .. '-' .. math.random(1000000))
			redis.call('PEXPIRE', key, window)
			return 1
		end
		return 0
	`)

	nowMs := time.Now().UnixMilli()
	result, err := script.Run(ctx, rl.client, []string{fullKey},
		rate, window.Milliseconds(), nowMs).Int()
	if err != nil {
		return false, fmt.Errorf("rate limiter: redis error: %w", err)
	}

	return result == 1, nil
}

// GetClient exposes the underlying Redis client for advanced use
func (rc *RedisCache) GetClient() *redis.Client {
	return rc.client
}
