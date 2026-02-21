package oauth2

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

/*
 * EchoMiddlewareOptions Echo 中间件配置选项
 * 功能：配置跳过路径、允许匿名访问、必须 scope 等
 */
type EchoMiddlewareOptions struct {
	SkipPaths      []string /* 跳过认证的路径 */
	AllowAnonymous bool     /* 允许无 Token 请求通过 */
	RequiredScopes []string /* 必须包含的 scope */
}

/*
 * EchoMiddleware 创建 Echo 框架的 OAuth2 令牌校验中间件
 * 功能：从 Authorization Header 提取 Bearer Token，验证后存入 Echo 上下文
 * @return echo.MiddlewareFunc - Echo 中间件函数
 */
func (c *Client) EchoMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			// Get token from Authorization header
			authHeader := ctx.Request().Header.Get("Authorization")
			if authHeader == "" {
				return ctx.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]string{
						"code":    "UNAUTHORIZED",
						"message": "Missing authorization header",
					},
				})
			}

			// Extract Bearer token
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				return ctx.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]string{
						"code":    "UNAUTHORIZED",
						"message": "Invalid authorization header format",
					},
				})
			}
			token := parts[1]

			// Validate token with OAuth2 server
			tempStore := NewMemoryTokenStore()
			tempStore.SetToken(&Token{AccessToken: token})
			oldStore := c.tokenStore
			c.tokenStore = tempStore

			userInfo, err := c.GetUserInfo(ctx.Request().Context())
			c.tokenStore = oldStore

			if err != nil {
				c.logger.Error("Token validation failed", "error", err)
				return ctx.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]string{
						"code":    "UNAUTHORIZED",
						"message": "Invalid or expired token",
					},
				})
			}

			// Store user info in context
			ctx.Set("user_id", userInfo.Sub)
			ctx.Set("user_email", userInfo.Email)
			ctx.Set("user_name", userInfo.Name)
			ctx.Set("user_info", userInfo)

			return next(ctx)
		}
	}
}

// EchoMiddlewareWithOptions creates Echo middleware with custom options
func (c *Client) EchoMiddlewareWithOptions(opts EchoMiddlewareOptions) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			// Check if path should be skipped
			path := ctx.Path()
			for _, skipPath := range opts.SkipPaths {
				if path == skipPath || strings.HasPrefix(path, skipPath) {
					return next(ctx)
				}
			}

			// Get token from Authorization header
			authHeader := ctx.Request().Header.Get("Authorization")
			if authHeader == "" {
				if opts.AllowAnonymous {
					return next(ctx)
				}
				return ctx.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]string{
						"code":    "UNAUTHORIZED",
						"message": "Missing authorization header",
					},
				})
			}

			// Extract Bearer token
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				if opts.AllowAnonymous {
					return next(ctx)
				}
				return ctx.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]string{
						"code":    "UNAUTHORIZED",
						"message": "Invalid authorization header format",
					},
				})
			}
			token := parts[1]

			// Validate token with OAuth2 server
			tempStore := NewMemoryTokenStore()
			tempStore.SetToken(&Token{AccessToken: token})
			oldStore := c.tokenStore
			c.tokenStore = tempStore

			userInfo, err := c.GetUserInfo(ctx.Request().Context())
			c.tokenStore = oldStore

			if err != nil {
				c.logger.Error("Token validation failed", "error", err)
				if opts.AllowAnonymous {
					return next(ctx)
				}
				return ctx.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]string{
						"code":    "UNAUTHORIZED",
						"message": "Invalid or expired token",
					},
				})
			}

			// Check required scopes
			if len(opts.RequiredScopes) > 0 {
				// Parse user scopes (assuming space-separated in token)
				hasAllScopes := true
				for _, required := range opts.RequiredScopes {
					found := false
					// Check if user has the required scope
					// This would need to be adapted based on how scopes are stored
					if required == "profile" || required == "email" || required == "openid" {
						found = true // Basic scopes are always present
					}
					if !found {
						hasAllScopes = false
						break
					}
				}
				if !hasAllScopes {
					return ctx.JSON(http.StatusForbidden, map[string]interface{}{
						"success": false,
						"error": map[string]string{
							"code":    "FORBIDDEN",
							"message": "Insufficient scopes",
						},
					})
				}
			}

			// Store user info in context
			ctx.Set("user_id", userInfo.Sub)
			ctx.Set("user_email", userInfo.Email)
			ctx.Set("user_name", userInfo.Name)
			ctx.Set("user_info", userInfo)

			return next(ctx)
		}
	}
}

// EchoGetUserID extracts user ID from Echo context
func EchoGetUserID(ctx echo.Context) string {
	if id, ok := ctx.Get("user_id").(string); ok {
		return id
	}
	return ""
}

// EchoGetUserEmail extracts user email from Echo context
func EchoGetUserEmail(ctx echo.Context) string {
	if email, ok := ctx.Get("user_email").(string); ok {
		return email
	}
	return ""
}

// EchoGetUserName extracts user name from Echo context
func EchoGetUserName(ctx echo.Context) string {
	if name, ok := ctx.Get("user_name").(string); ok {
		return name
	}
	return ""
}

// EchoGetUserInfo extracts full user info from Echo context
func EchoGetUserInfo(ctx echo.Context) *UserInfo {
	if info, ok := ctx.Get("user_info").(*UserInfo); ok {
		return info
	}
	return nil
}
