package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings" 

	"github.com/gin-gonic/gin"
)

const (
	CSRFTokenCookie = "csrf_token"
	CSRFTokenHeader = "X-CSRF-Token"
	csrfTokenLength = 32
)

/*
 * CSRF 中间件
 * 功能：对状态变更请求（POST/PUT/DELETE/PATCH）执行双重校验
 *   1. Origin/Referer 头校验：确保请求来自受信任的来源
 *   2. Cookie-Header Token 比对：常量时间比较 cookie 和请求头中的 CSRF token
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

		/*
		 * 第一层：Origin/Referer 头校验
		 * 确保请求来源的 host 与当前服务 host 一致，阻止跨站伪造
		 */
		if !validateOrigin(c) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   gin.H{"code": "CSRF_ORIGIN", "message": "Cross-origin request blocked"},
			})
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

		/* 比对 cookie 和 header 中的 token（使用常量时间比较，防止时序攻击） */
		if !hmac.Equal([]byte(cookieToken), []byte(headerToken)) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   gin.H{"code": "CSRF_INVALID", "message": "CSRF token mismatch"},
			})
			return
		}

		c.Next()
	}
}

/*
 * validateOrigin 校验请求的 Origin 或 Referer 是否与当前 Host 一致
 * 规则：
 *   - 优先检查 Origin 头（preflight 和 AJAX 请求会携带）
 *   - 回退检查 Referer 头
 *   - 两者都缺失时放行（部分浏览器隐私模式不发送）
 * @param c - Gin 上下文
 * @return bool - 来源合法返回 true
 */
func validateOrigin(c *gin.Context) bool {
	requestHost := c.Request.Host

	/* 检查 Origin 头 */
	origin := c.GetHeader("Origin")
	if origin != "" {
		parsed, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(parsed.Host, requestHost)
	}

	/* 回退：检查 Referer 头 */
	referer := c.GetHeader("Referer")
	if referer != "" {
		parsed, err := url.Parse(referer)
		if err != nil {
			return false
		}
		return strings.EqualFold(parsed.Host, requestHost)
	}

	/* 两者都缺失：允许通过（依赖 CSRF token 校验兜底） */
	return true
}

/* GenerateCSRFToken 生成随机 CSRF token */
func GenerateCSRFToken() string {
	bytes := make([]byte, csrfTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(bytes)
}
