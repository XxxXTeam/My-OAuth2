package middleware

import (
	"net/http"
	"strings"

	ctx "server/internal/context"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
)

const (
	AuthorizationHeader = "Authorization"
	BearerPrefix        = "Bearer "
	AccessTokenCookie   = "access_token"
	RefreshTokenCookie  = "refresh_token"
)

/*
 * extractToken 从请求中提取 token
 * 优先级：Authorization Header > Cookie
 * 不再支持查询字符串传递 token，提高安全性
 */
func extractToken(c *gin.Context) string {
	/* 1. 优先从 Authorization header 提取 */
	authHeader := c.GetHeader(AuthorizationHeader)
	if authHeader != "" && strings.HasPrefix(authHeader, BearerPrefix) {
		return strings.TrimPrefix(authHeader, BearerPrefix)
	}

	/* 2. 回退到 httpOnly Cookie */
	if token, err := c.Cookie(AccessTokenCookie); err == nil && token != "" {
		return token
	}

	return ""
}

/* authError 返回统一格式的鉴权错误 */
func authError(c *gin.Context, code, message string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"success": false,
		"error":   gin.H{"code": code, "message": message},
	})
}

/*
 * Auth 创建 JWT 鉴权中间件
 * 支持 Authorization Header 和 httpOnly Cookie 两种方式
 * 使用 ValidateAccessToken 确保 refresh token 不能当 access token 使用
 * 可选传入 Blacklist 实例，启用 token 吊销检查
 */
func Auth(jwtManager *jwt.Manager, blacklist ...*jwt.Blacklist) gin.HandlerFunc {
	var bl *jwt.Blacklist
	if len(blacklist) > 0 {
		bl = blacklist[0]
	}

	return func(c *gin.Context) {
		tokenString := extractToken(c)
		if tokenString == "" {
			authError(c, "UNAUTHORIZED", "Authorization required")
			return
		}

		claims, err := jwtManager.ValidateAccessToken(tokenString)
		if err != nil {
			switch err {
			case jwt.ErrExpiredToken:
				authError(c, "TOKEN_EXPIRED", "Token has expired")
			case jwt.ErrTokenTypeMismatch:
				authError(c, "TOKEN_INVALID", "Invalid token type")
			default:
				authError(c, "TOKEN_INVALID", "Invalid token")
			}
			return
		}

		/* JWT 黑名单检查：JTI 级别吊销 + 用户级别全局吊销 */
		if bl != nil {
			if bl.IsRevoked(claims.ID) {
				authError(c, "TOKEN_REVOKED", "Token has been revoked")
				return
			}
			if claims.IssuedAt != nil && bl.IsUserTokenRevoked(claims.UserID.String(), claims.IssuedAt.Time) {
				authError(c, "TOKEN_REVOKED", "Token has been revoked")
				return
			}
		}

		ctx.SetUser(c, claims.UserID, claims.Email, claims.Username, claims.Role)
		c.Next()
	}
}

/*
 * OptionalAuth 可选鉴权中间件
 * token 有效时设置用户信息，无 token 或无效时不拦截
 */
func OptionalAuth(jwtManager *jwt.Manager, blacklist ...*jwt.Blacklist) gin.HandlerFunc {
	var bl *jwt.Blacklist
	if len(blacklist) > 0 {
		bl = blacklist[0]
	}

	return func(c *gin.Context) {
		tokenString := extractToken(c)
		if tokenString == "" {
			c.Next()
			return
		}

		claims, err := jwtManager.ValidateAccessToken(tokenString)
		if err != nil {
			c.Next()
			return
		}

		/* 黑名单检查（可选） */
		if bl != nil {
			if bl.IsRevoked(claims.ID) || (claims.IssuedAt != nil && bl.IsUserTokenRevoked(claims.UserID.String(), claims.IssuedAt.Time)) {
				c.Next()
				return
			}
		}

		ctx.SetUser(c, claims.UserID, claims.Email, claims.Username, claims.Role)
		c.Next()
	}
}

/* AdminOnly 管理员权限中间件 */
func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ctx.IsAdmin(c) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   gin.H{"code": "ADMIN_REQUIRED", "message": "Admin access required"},
			})
			return
		}
		c.Next()
	}
}

/* CORS 已迁移到 cors.go */
