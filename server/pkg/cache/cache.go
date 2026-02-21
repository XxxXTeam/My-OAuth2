/*
 * Package cache 缓存抽象层
 * 功能：提供统一的缓存接口，支持多种后端（memory、redis、memcached、badger、file）
 */
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

/*
 * Cache 缓存接口定义
 * 功能：所有缓存后端必须实现此接口，支持 Get/Set/Delete/Exists/Close/Ping 操作
 */
type Cache interface {
	/* Get 根据 key 获取值，不存在时返回 ErrNotFound */
	Get(ctx context.Context, key string) ([]byte, error)

	/* Set 存储值，TTL=0 表示使用默认 TTL */
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	/* Delete 删除指定 key */
	Delete(ctx context.Context, key string) error

	/* Exists 检查 key 是否存在 */
	Exists(ctx context.Context, key string) (bool, error)

	/* Close 释放缓存资源 */
	Close() error

	/* Ping 检查缓存连接健康状态 */
	Ping(ctx context.Context) error
}

/* ErrNotFound 缓存 key 不存在时返回的错误 */
var ErrNotFound = fmt.Errorf("cache: key not found")

/*
 * Config 缓存配置
 * 功能：指定缓存驱动、连接信息、key 前缀和默认 TTL
 */
type Config struct {
	Driver           string        `json:"driver"`            // "memory", "redis", "memcached", "badger", "file"
	RedisURL         string        `json:"redis_url"`         // Redis connection URL (e.g. redis://localhost:6379/0)
	MemcachedServers []string      `json:"memcached_servers"` // Memcached server list (e.g. ["localhost:11211"])
	BadgerPath       string        `json:"badger_path"`       // BadgerDB data directory
	FileDir          string        `json:"file_dir"`          // File cache root directory
	Prefix           string        `json:"prefix"`            // Key prefix for namespacing
	DefaultTTL       time.Duration `json:"default_ttl"`       // Default TTL for cache entries
}

/*
 * New 根据配置创建缓存实例
 * 功能：根据 Driver 字段创建对应的缓存后端实例
 * @param cfg - 缓存配置，nil 时默认使用内存缓存
 */
func New(cfg *Config) (Cache, error) {
	if cfg == nil {
		cfg = &Config{Driver: "memory"}
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "oauth2:"
	}

	switch cfg.Driver {
	case "redis":
		return NewRedisCache(cfg.RedisURL, cfg.Prefix, cfg.DefaultTTL)
	case "memcached":
		return NewMemcachedCache(cfg.MemcachedServers, cfg.Prefix, cfg.DefaultTTL)
	case "badger":
		return NewBadgerCache(cfg.BadgerPath, cfg.Prefix, cfg.DefaultTTL)
	case "file":
		return NewFileCache(cfg.FileDir, cfg.Prefix, cfg.DefaultTTL)
	case "memory", "":
		return NewMemoryCache(cfg.DefaultTTL), nil
	default:
		return nil, fmt.Errorf("unsupported cache driver: %s (supported: memory, redis, memcached, badger, file)", cfg.Driver)
	}
}

/* ========== 泛型缓存操作辅助函数 ========== */

/*
 * GetJSON 获取并反序列化 JSON 缓存值
 * @param ctx - 上下文
 * @param c   - 缓存实例
 * @param key - 缓存 key
 * @return T  - 反序列化后的值
 */
func GetJSON[T any](ctx context.Context, c Cache, key string) (T, error) {
	var result T
	data, err := c.Get(ctx, key)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return result, fmt.Errorf("cache: unmarshal error: %w", err)
	}
	return result, nil
}

/*
 * SetJSON 序列化并存储 JSON 缓存值
 * @param ctx   - 上下文
 * @param c     - 缓存实例
 * @param key   - 缓存 key
 * @param value - 要存储的值
 * @param ttl   - 过期时间
 */
func SetJSON(ctx context.Context, c Cache, key string, value any, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("cache: marshal error: %w", err)
	}
	return c.Set(ctx, key, data, ttl)
}
