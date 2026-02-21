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
 * - Cache-Control: API 响应不缓存敏感数据
 */
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

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
