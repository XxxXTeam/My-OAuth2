package middleware

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
)

/*
 * Timeout 请求超时中间件
 * 功能：为每个请求注入 context deadline，数据库查询和外部 HTTP 调用会自动感知超时
 * 说明：不使用 goroutine 包装 c.Next()，因为 gin.Context 不是 goroutine-safe
 *       SSE/WebSocket 等长连接自动跳过
 */
func Timeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		/* SSE 和 WebSocket 等长连接不设超时 */
		if isLongConnection(c) {
			c.Next()
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

/* isLongConnection 判断是否为长连接请求（SSE/WebSocket） */
func isLongConnection(c *gin.Context) bool {
	/* SSE 事件流 */
	if c.GetHeader("Accept") == "text/event-stream" {
		return true
	}
	/* WebSocket 升级请求 */
	if c.GetHeader("Upgrade") == "websocket" {
		return true
	}
	return false
}
