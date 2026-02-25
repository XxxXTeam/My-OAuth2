package middleware

import (
	"io"

	"github.com/gin-gonic/gin"
)

/*
 * SecurityHeaders 安全响应头中间件
 * 功能：为所有响应添加安全头，防止常见 Web 攻击
 * - X-Content-Type-Options: 防止 MIME 嗅探
 * - X-Frame-Options: 防止点击劫持
 * - X-XSS-Protection: 启用浏览器 XSS 过滤
 * - Referrer-Policy: 控制 Referer 泄露
 * - Permissions-Policy: 限制浏览器特性
 * - Strict-Transport-Security: 强制 HTTPS（HSTS）
 * - Content-Security-Policy: 限制资源加载来源
 * - Cache-Control: API 响应不缓存敏感数据
 * - X-Permitted-Cross-Domain-Policies: 阻止 Adobe Flash/PDF 跨域策略
 * - Cross-Origin-Opener-Policy: 防止跨源窗口引用
 */
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()")

		/* HSTS: 强制 HTTPS，max-age=1年，包含子域 */
		if c.GetHeader("X-Forwarded-Proto") == "https" || c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		/*
		 * CSP: 限制资源来源
		 * script-src 'unsafe-inline': Next.js SSR 和暗黑模式初始化脚本需要内联执行
		 * style-src 'unsafe-inline': SPA 动态样式需要
		 * img-src https:: 允许外部头像和 OAuth 提供商图标
		 */
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")

		/* 阻止 Adobe 跨域策略文件 */
		c.Header("X-Permitted-Cross-Domain-Policies", "none")

		/* 防止跨源窗口引用泄露 */
		c.Header("Cross-Origin-Opener-Policy", "same-origin")

		/* API 响应禁止缓存敏感数据 */
		path := c.Request.URL.Path
		if len(path) >= 4 && path[:4] == "/api" {
			c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
			c.Header("Pragma", "no-cache")
		}

		c.Next()
	}
}

/*
 * RequestSizeLimit 请求体大小限制中间件
 * 功能：限制请求体大小，防止大文件攻击
 */
func RequestSizeLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			c.AbortWithStatusJSON(413, gin.H{
				"success": false,
				"error":   gin.H{"code": "BAD_REQUEST", "message": "Request body too large"},
			})
			return
		}
		c.Request.Body = newLimitedReader(c.Request.Body, maxBytes)
		c.Next()
	}
}

type limitedReader struct {
	r         interface{ Read([]byte) (int, error) }
	remaining int64
}

func newLimitedReader(r interface{ Read([]byte) (int, error) }, limit int64) *limitedReader {
	return &limitedReader{r: r, remaining: limit}
}

func (lr *limitedReader) Read(p []byte) (int, error) {
	if lr.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > lr.remaining {
		p = p[:lr.remaining]
	}
	n, err := lr.r.Read(p)
	lr.remaining -= int64(n)
	return n, err
}

func (lr *limitedReader) Close() error {
	if closer, ok := lr.r.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
