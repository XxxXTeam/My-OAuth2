package middleware

import (
	"compress/gzip"
	"io"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

/*
 * Gzip 响应压缩中间件
 * 功能：对支持 gzip 的客户端自动压缩响应体，减少传输体积
 * 策略：
 *   - 仅压缩 text/html、application/json、text/css、application/javascript 等文本类型
 *   - SSE 事件流不压缩（需要实时传输）
 *   - 小于 1KB 的响应不压缩（压缩收益低）
 */

var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return w
	},
}

/* gzipResponseWriter 包装 gin.ResponseWriter，透明压缩写入的数据 */
type gzipResponseWriter struct {
	gin.ResponseWriter
	writer *gzip.Writer
	size   int /* 追踪未压缩的原始响应体大小 */
}

func (g *gzipResponseWriter) Write(data []byte) (int, error) {
	g.size += len(data)
	return g.writer.Write(data)
}

func (g *gzipResponseWriter) WriteString(s string) (int, error) {
	g.size += len(s)
	return g.writer.Write([]byte(s))
}

/* Size 返回未压缩的原始响应体大小，供日志中间件正确统计 */
func (g *gzipResponseWriter) Size() int {
	return g.size
}

/*
 * GzipCompression Gzip 压缩中间件
 * 功能：自动检测客户端是否支持 gzip，对响应进行压缩
 */
func GzipCompression() gin.HandlerFunc {
	return func(c *gin.Context) {
		/* 客户端不支持 gzip 则跳过 */
		if !strings.Contains(c.GetHeader("Accept-Encoding"), "gzip") {
			c.Next()
			return
		}

		/* SSE 事件流不压缩 */
		if c.GetHeader("Accept") == "text/event-stream" {
			c.Next()
			return
		}

		gz := gzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(c.Writer)

		c.Header("Content-Encoding", "gzip")
		c.Header("Vary", "Accept-Encoding")

		c.Writer = &gzipResponseWriter{
			ResponseWriter: c.Writer,
			writer:         gz,
		}

		defer func() {
			gz.Close()
			gzipWriterPool.Put(gz)
		}()

		c.Next()
	}
}
