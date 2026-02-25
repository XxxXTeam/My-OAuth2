package middleware

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"server/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/* formatBytes 将字节数转为可读格式（B/KB/MB） */
func formatBytes(size int) string {
	if size < 0 {
		return "0B"
	}
	if size < 1024 {
		return fmt.Sprintf("%dB", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(size)/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(size)/1024/1024)
}

// TraceID middleware injects trace ID into context
func TraceID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get trace ID from header or generate new one
		traceID := c.GetHeader("X-Trace-ID")
		if traceID == "" {
			traceID = uuid.New().String()
		}

		// Set trace ID in context
		ctx := context.WithValue(c.Request.Context(), logger.TraceIDKey, traceID)
		c.Request = c.Request.WithContext(ctx)

		// Set trace ID in response header
		c.Header("X-Trace-ID", traceID)

		// Store in gin context for easy access
		c.Set("trace_id", traceID)

		c.Next()
	}
}

/*
 * shouldLogRequest 白名单判断是否需要记录日志
 * 只记录业务路由（API/OAuth/OIDC等），跳过所有静态资源和SPA页面请求
 */
func shouldLogRequest(path string) bool {
	logPrefixes := []string{
		"/api/",
		"/oauth/",
		"/token/",
		"/.well-known/",
	}
	for _, prefix := range logPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	if path == "/health" {
		return true
	}
	return false
}

// RequestLogger middleware logs HTTP requests
func RequestLogger() gin.HandlerFunc {
	log := logger.Default()

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		/* 只记录业务路由日志，跳过静态资源和SPA页面 */
		if !shouldLogRequest(path) {
			c.Next()
			return
		}

		// Start timer
		start := time.Now()
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get trace ID
		traceID, _ := c.Get("trace_id")

		// Build path with query
		if raw != "" {
			path = path + "?" + raw
		}

		statusCode := c.Writer.Status()
		method := c.Request.Method
		clientIP := c.ClientIP()
		responseSize := c.Writer.Size()

		/* HTTP 方法颜色 */
		methodColor := "\033[34m" // 蓝色
		switch method {
		case "GET":
			methodColor = "\033[32m" // 绿色
		case "POST":
			methodColor = "\033[34m" // 蓝色
		case "PUT":
			methodColor = "\033[33m" // 黄色
		case "DELETE":
			methodColor = "\033[31m" // 红色
		}

		/* 状态码颜色 */
		statusColor := "\033[32m" // 绿色
		switch {
		case statusCode >= 500:
			statusColor = "\033[1;31m" // 红色加粗
		case statusCode >= 400:
			statusColor = "\033[33m" // 黄色
		case statusCode >= 300:
			statusColor = "\033[36m" // 青色
		}

		/* 响应体大小可读格式 */
		sizeStr := formatBytes(responseSize)

		/* 构建带颜色的紧凑 HTTP 日志（含响应体大小） */
		httpMsg := fmt.Sprintf("%s%s\033[0m %s%d\033[0m \033[1;37m%s\033[0m \033[90m%s\033[0m \033[90m%s\033[0m \033[90m%s\033[0m",
			methodColor, method,
			statusColor, statusCode,
			path,
			latency.String(),
			sizeStr,
			clientIP,
		)

		/* 追加用户信息 */
		l := log
		if tid, ok := traceID.(string); ok {
			l = l.WithTraceID(tid)
		}
		if userID, exists := c.Get("user_id"); exists {
			httpMsg += fmt.Sprintf(" \033[36muid\033[0m=%v", userID)
		}

		/* 慢请求告警阈值：超过 3 秒标记为慢请求 */
		const slowRequestThreshold = 3 * time.Second
		if latency > slowRequestThreshold {
			httpMsg += fmt.Sprintf(" \033[1;33m⚠ SLOW(%s)\033[0m", latency.Round(time.Millisecond))
		}

		/* 根据状态码选择日志等级，使用 LogHTTP 输出 [HTTP] 标签替代误导性的 middleware 文件位置 */
		switch {
		case statusCode >= 500:
			l.LogHTTP(logger.LevelError, httpMsg, "error", c.Errors.String())
		case statusCode >= 400:
			l.LogHTTP(logger.LevelWarn, httpMsg)
		default:
			l.LogHTTP(logger.LevelInfo, httpMsg)
		}
	}
}

/*
 * RecoveryWithLogger panic 恢复中间件
 * 功能：捕获 handler 中的 panic，记录完整堆栈跟踪和请求上下文，返回统一错误响应
 * 增强：记录 query string、Content-Type、request body 片段（前 512 字节）
 * 参考：gin-gonic/gin Recovery() + 增强日志信息
 */
func RecoveryWithLogger() gin.HandlerFunc {
	log := logger.Default()

	return func(c *gin.Context) {
		/* 预读 request body 片段用于 panic 时记录（仅 POST/PUT/PATCH 且非 multipart） */
		var bodySnippet string
		if c.Request.Body != nil && c.Request.ContentLength > 0 {
			ct := c.ContentType()
			method := c.Request.Method
			if (method == "POST" || method == "PUT" || method == "PATCH") &&
				!strings.HasPrefix(ct, "multipart/") {
				maxRead := int64(512)
				if c.Request.ContentLength < maxRead {
					maxRead = c.Request.ContentLength
				}
				buf := make([]byte, maxRead)
				n, _ := io.ReadFull(c.Request.Body, buf)
				bodySnippet = string(buf[:n])
				/* 恢复 body 以便后续 handler 读取 */
				c.Request.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf[:n]), c.Request.Body))
			}
		}

		defer func() {
			if err := recover(); err != nil {
				traceID, _ := c.Get("trace_id")
				tid := ""
				l := log
				if t, ok := traceID.(string); ok {
					tid = t
					l = l.WithTraceID(tid)
				}

				/* 获取堆栈跟踪（8KB 以捕获更深调用链） */
				stack := make([]byte, 8192)
				stack = stack[:runtime.Stack(stack, false)]

				logArgs := []any{
					"error", fmt.Sprintf("%v", err),
					"method", c.Request.Method,
					"path", c.Request.URL.Path,
					"query", c.Request.URL.RawQuery,
					"content_type", c.ContentType(),
					"ip", c.ClientIP(),
					"user_agent", c.Request.UserAgent(),
				}
				if bodySnippet != "" {
					logArgs = append(logArgs, "body_snippet", bodySnippet)
				}
				logArgs = append(logArgs, "stack", string(stack))

				l.Error("🔥 Panic recovered", logArgs...)

				/* 响应中包含 trace_id 方便关联日志 */
				errResp := gin.H{
					"success": false,
					"error": gin.H{
						"code":    "INTERNAL_ERROR",
						"message": "Internal Server Error",
					},
				}
				if tid != "" {
					errResp["trace_id"] = tid
				}
				c.AbortWithStatusJSON(500, errResp)
			}
		}()
		c.Next()
	}
}
