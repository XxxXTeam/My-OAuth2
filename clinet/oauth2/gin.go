package oauth2

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

/* Gin 上下文键常量 */
const (
	GinTokenKey    = "oauth2_token"     /* Token 上下文键 */
	GinUserInfoKey = "oauth2_user_info" /* 用户信息上下文键 */
)

/*
 * GinMiddleware 创建 Gin 框架的 OAuth2 令牌校验中间件
 * 功能：从 Authorization Header 提取 Bearer Token，存入 Gin 上下文，可选获取用户信息
 * @return gin.HandlerFunc - Gin 中间件函数
 */
func (c *Client) GinMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Extract token from Authorization header
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization header",
			})
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization header format",
			})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Create a temporary token
		token := &Token{AccessToken: tokenString}

		// Store token in context
		ctx.Set(GinTokenKey, token)

		// Optionally fetch user info
		if c.config.UserInfoURL != "" {
			// Create a temporary client with this token
			tempStore := NewMemoryTokenStore()
			tempStore.SetToken(token)

			oldStore := c.tokenStore
			c.tokenStore = tempStore

			userInfo, err := c.GetUserInfo(ctx.Request.Context())
			c.tokenStore = oldStore

			if err != nil {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid token",
				})
				return
			}
			ctx.Set(GinUserInfoKey, userInfo)
		}

		ctx.Next()
	}
}

// GinToken extracts the token from Gin context
func GinToken(ctx *gin.Context) *Token {
	token, exists := ctx.Get(GinTokenKey)
	if !exists {
		return nil
	}
	return token.(*Token)
}

// GinUserInfo extracts the user info from Gin context
func GinUserInfo(ctx *gin.Context) *UserInfo {
	userInfo, exists := ctx.Get(GinUserInfoKey)
	if !exists {
		return nil
	}
	return userInfo.(*UserInfo)
}

// GinRequireAuth is a Gin middleware that requires authentication
func GinRequireAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token := GinToken(ctx)
		if token == nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
			})
			return
		}
		ctx.Next()
	}
}
