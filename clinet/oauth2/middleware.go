package oauth2

import (
	"context"
	"net/http"
	"strings"
)

/* ContextKey 上下文键类型 */
type ContextKey string

/* 上下文键常量 */
const (
	TokenContextKey    ContextKey = "oauth2_token"     /* Token 上下文键 */
	UserInfoContextKey ContextKey = "oauth2_user_info" /* 用户信息上下文键 */
)

/*
 * Middleware 创建标准 HTTP 中间件，校验 OAuth2 令牌
 * 功能：从 Authorization Header 提取 Bearer Token，存入上下文，可选获取用户信息
 * @param next - 下一个 HTTP Handler
 * @return http.Handler - 包装后的 Handler
 */
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized: missing authorization header", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized: invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Create a temporary token for validation
		token := &Token{AccessToken: tokenString}

		// Store token in context
		ctx := context.WithValue(r.Context(), TokenContextKey, token)

		// Optionally fetch user info
		if c.config.UserInfoURL != "" {
			// Create a temporary client with this token
			tempStore := NewMemoryTokenStore()
			tempStore.SetToken(token)

			oldStore := c.tokenStore
			c.tokenStore = tempStore

			userInfo, err := c.GetUserInfo(r.Context())
			c.tokenStore = oldStore

			if err != nil {
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}
			ctx = context.WithValue(ctx, UserInfoContextKey, userInfo)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TokenFromContext extracts the token from the context
func TokenFromContext(ctx context.Context) *Token {
	token, _ := ctx.Value(TokenContextKey).(*Token)
	return token
}

// UserInfoFromContext extracts the user info from the context
func UserInfoFromContext(ctx context.Context) *UserInfo {
	userInfo, _ := ctx.Value(UserInfoContextKey).(*UserInfo)
	return userInfo
}

// RequireAuth is a middleware that requires authentication
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := TokenFromContext(r.Context())
		if token == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
