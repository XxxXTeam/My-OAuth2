package middleware

import (
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

/*
 * CORS 跨域中间件
 * 功能：处理跨域请求，支持 Cookie credentials 认证
 * 安全策略：
 *   - 校验请求 Origin 是否在允许列表中
 *   - 同源请求（无 Origin 头）直接放行
 *   - 支持 credentials 时必须指定具体 origin，不使用通配符 *
 * 参考：rs/cors、gin-contrib/cors 的实现模式
 */
func CORSWithConfig(allowedOrigins ...string) gin.HandlerFunc {
	/* 构建允许的 origin 集合，用于快速查找 */
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[strings.TrimRight(o, "/")] = true
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		/* 没有 Origin 头 = 同源请求，直接放行 */
		if origin == "" {
			c.Next()
			return
		}

		/* 校验 origin 是否被允许 */
		allowed := isOriginAllowed(origin, originSet)

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-CSRF-Token, X-Trace-ID")
			c.Header("Access-Control-Expose-Headers", "X-Trace-ID, Content-Disposition, X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After")
			c.Header("Access-Control-Max-Age", "86400")
			/* Vary 需包含所有影响 CORS 响应的请求头，确保 CDN/代理正确缓存 */
			c.Header("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
		}

		/* 预检请求直接返回 */
		if c.Request.Method == "OPTIONS" {
			if allowed {
				c.AbortWithStatus(204)
			} else {
				c.AbortWithStatus(403)
			}
			return
		}

		c.Next()
	}
}

/*
 * isOriginAllowed 检查 origin 是否在允许列表中
 * 规则：
 *   - 空列表 = 允许所有来源（开发模式）
 *   - 精确匹配
 *   - 仅在 Gin 为 debug 模式时，localhost/127.0.0.1 的任意端口自动允许
 */
func isOriginAllowed(origin string, allowedSet map[string]bool) bool {
	/* 没有配置允许列表 → 允许所有（适用于开发环境） */
	if len(allowedSet) == 0 {
		return true
	}

	cleanOrigin := strings.TrimRight(origin, "/")

	/* 精确匹配 */
	if allowedSet[cleanOrigin] {
		return true
	}

	/*
	 * 仅在 debug 模式下允许 localhost/127.0.0.1 任意端口
	 * 生产环境必须通过 allowedOrigins 显式配置
	 */
	if gin.Mode() == gin.DebugMode {
		if parsed, err := url.Parse(cleanOrigin); err == nil {
			host := parsed.Hostname()
			if host == "localhost" || host == "127.0.0.1" {
				return true
			}
		}
	}

	return false
}
