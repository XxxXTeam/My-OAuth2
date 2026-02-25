package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

/*
 * RateLimiter 基于令牌桶的限流器
 * 功能：按 IP 限制请求速率，支持突发容量，自动清理过期记录
 * 支持优雅关停：通过 Stop() 方法停止后台清理协程
 */
type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     int           // 每秒允许的请求数
	burst    int           // 突发容量
	cleanup  time.Duration // 清理间隔
	stopCh   chan struct{} // 关停信号通道
}

type visitor struct {
	tokens     float64
	lastAccess time.Time
	mu         sync.Mutex
}

/*
 * NewRateLimiter 创建限流器实例
 * @param rate  - 每秒允许的请求数
 * @param burst - 突发容量（允许短时间内超过 rate 的最大请求数）
 */
func NewRateLimiter(rate, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		burst:    burst,
		cleanup:  time.Minute * 5,
		stopCh:   make(chan struct{}),
	}
	go rl.cleanupVisitors()
	return rl
}

/*
 * Stop 优雅关停限流器，停止后台清理协程
 * 调用后 cleanup goroutine 会退出，释放资源
 */
func (rl *RateLimiter) Stop() {
	select {
	case <-rl.stopCh:
		/* 已关停，避免重复 close */
	default:
		close(rl.stopCh)
	}
}

/* cleanupVisitors 后台定期清理过期的访客记录，支持通过 stopCh 优雅退出 */
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.mu.Lock()
			for ip, v := range rl.visitors {
				v.mu.Lock()
				if time.Since(v.lastAccess) > rl.cleanup {
					delete(rl.visitors, ip)
				}
				v.mu.Unlock()
			}
			rl.mu.Unlock()
		}
	}
}

/* getVisitor 获取或创建访客记录（双重检查锁模式） */
func (rl *RateLimiter) getVisitor(ip string) *visitor {
	rl.mu.RLock()
	v, exists := rl.visitors[ip]
	rl.mu.RUnlock()

	if exists {
		return v
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if v, exists = rl.visitors[ip]; exists {
		return v
	}

	v = &visitor{
		tokens:     float64(rl.burst),
		lastAccess: time.Now(),
	}
	rl.visitors[ip] = v
	return v
}

/*
 * RateLimitResult 限流检查结果
 * 功能：携带剩余令牌数和限流配置，用于设置 X-RateLimit-* 响应头
 */
type RateLimitResult struct {
	Allowed   bool
	Remaining int
	Limit     int
}

/*
 * Check 检查是否允许请求（令牌桶算法），返回详细结果
 * @param ip - 客户端 IP
 * @return RateLimitResult - 包含是否允许、剩余令牌数、限流上限
 */
func (rl *RateLimiter) Check(ip string) RateLimitResult {
	v := rl.getVisitor(ip)
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(v.lastAccess).Seconds()
	v.lastAccess = now

	// 补充令牌
	v.tokens += elapsed * float64(rl.rate)
	if v.tokens > float64(rl.burst) {
		v.tokens = float64(rl.burst)
	}

	// 检查是否有可用令牌
	if v.tokens >= 1 {
		v.tokens--
		return RateLimitResult{Allowed: true, Remaining: int(v.tokens), Limit: rl.burst}
	}

	return RateLimitResult{Allowed: false, Remaining: 0, Limit: rl.burst}
}

/*
 * Allow 检查是否允许请求（令牌桶算法）
 * @param ip   - 客户端 IP
 * @return bool - 允许返回 true
 */
func (rl *RateLimiter) Allow(ip string) bool {
	return rl.Check(ip).Allowed
}

/*
 * RateLimitMiddleware 返回通用限流中间件
 * @param rate  - 每秒请求数
 * @param burst - 突发容量
 */
func RateLimitMiddleware(rate, burst int) gin.HandlerFunc {
	limiter := NewRateLimiter(rate, burst)
	return func(c *gin.Context) {
		ip := c.ClientIP()
		result := limiter.Check(ip)

		/* 设置标准限流响应头 (IETF draft-ietf-httpapi-ratelimit-headers) */
		c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))

		if !result.Allowed {
			c.Header("Retry-After", "1")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "TOO_MANY_REQUESTS",
					"message": "Rate limit exceeded. Please try again later.",
				},
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

/* EndpointRateLimiter 针对特定 API 端点的限流器 */
type EndpointRateLimiter struct {
	limiters map[string]*RateLimiter
	mu       sync.RWMutex
	config   map[string]RateLimitConfig
}

/* RateLimitConfig 端点限流配置 */
type RateLimitConfig struct {
	Rate  int // 每秒请求数
	Burst int // 突发容量
}

/*
 * NewEndpointRateLimiter 创建端点限流器实例
 * @param config - 端点 → 限流配置映射
 */
func NewEndpointRateLimiter(config map[string]RateLimitConfig) *EndpointRateLimiter {
	return &EndpointRateLimiter{
		limiters: make(map[string]*RateLimiter),
		config:   config,
	}
}

/* getLimiter 获取端点限流器（不存在则使用默认配置创建） */
func (erl *EndpointRateLimiter) getLimiter(endpoint string) *RateLimiter {
	erl.mu.RLock()
	limiter, exists := erl.limiters[endpoint]
	erl.mu.RUnlock()

	if exists {
		return limiter
	}

	// 获取配置
	config, ok := erl.config[endpoint]
	if !ok {
		// 使用默认配置
		config = RateLimitConfig{Rate: 100, Burst: 200}
	}

	erl.mu.Lock()
	defer erl.mu.Unlock()

	// Double-check
	if limiter, exists = erl.limiters[endpoint]; exists {
		return limiter
	}

	limiter = NewRateLimiter(config.Rate, config.Burst)
	erl.limiters[endpoint] = limiter
	return limiter
}

/* EndpointRateLimitMiddleware 端点级别的限流中间件（按 IP+端点 组合限流） */
func EndpointRateLimitMiddleware(config map[string]RateLimitConfig) gin.HandlerFunc {
	erl := NewEndpointRateLimiter(config)
	return func(c *gin.Context) {
		endpoint := c.FullPath()
		limiter := erl.getLimiter(endpoint)

		// 使用 IP + endpoint 作为限流key
		key := c.ClientIP() + ":" + endpoint
		if !limiter.Allow(key) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "TOO_MANY_REQUESTS",
					"message": "Rate limit exceeded for this endpoint. Please try again later.",
				},
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

/* AuthRateLimiter 认证接口专用限流（每分钟 10 次，突发 20 次） */
func AuthRateLimiter() gin.HandlerFunc {
	// 登录/注册：每分钟最多10次请求，突发20次
	return RateLimitMiddleware(10, 20)
}

/* APIRateLimiter 普通 API 限流（每秒 100 次，突发 200 次） */
func APIRateLimiter() gin.HandlerFunc {
	// 普通API：每秒100次请求，突发200次
	return RateLimitMiddleware(100, 200)
}

/* StrictRateLimiter 敏感操作专用限流（每分钟 5 次，突发 10 次） */
func StrictRateLimiter() gin.HandlerFunc {
	// 敏感操作：每分钟最多5次请求，突发10次
	return RateLimitMiddleware(5, 10)
}
