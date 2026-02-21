package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	CSRFTokenCookie = "csrf_token"
	CSRFTokenHeader = "X-CSRF-Token"
	csrfTokenLength = 32
)

/*
 * CSRF 中间件
 * 功能：对状态变更请求（POST/PUT/DELETE/PATCH）校验 CSRF Token
 * 原理：cookie 中的 csrf_token（非 httpOnly，JS 可读）与请求头 X-CSRF-Token 比对
 * 豁免：OAuth token 端点等外部 API 不需要 CSRF 保护（它们使用 client_secret 鉴权）
 */
func CSRFProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		/* 只对状态变更请求校验 CSRF */
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		/* 如果请求使用 Authorization header（Bearer token），说明不是基于 cookie 的请求，跳过 CSRF 校验 */
		if c.GetHeader("Authorization") != "" {
			c.Next()
			return
		}

		/* 从 cookie 读取 csrf_token */
		cookieToken, err := c.Cookie(CSRFTokenCookie)
		if err != nil || cookieToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   gin.H{"code": "CSRF_INVALID", "message": "CSRF token missing"},
			})
			return
		}

		/* 从请求头读取 csrf_token */
		headerToken := c.GetHeader(CSRFTokenHeader)
		if headerToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   gin.H{"code": "CSRF_INVALID", "message": "CSRF token header missing"},
			})
			return
		}

		/* 比对 cookie 和 header 中的 token */
		if cookieToken != headerToken {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   gin.H{"code": "CSRF_INVALID", "message": "CSRF token mismatch"},
			})
			return
		}

		c.Next()
	}
}

/* GenerateCSRFToken 生成随机 CSRF token */
func GenerateCSRFToken() string {
	bytes := make([]byte, csrfTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(bytes)
}
