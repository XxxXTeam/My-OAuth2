package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"server/internal/config"
	"server/internal/middleware"
	"server/internal/model"
	"server/internal/service"
	"server/pkg/password"
	"server/pkg/sanitize"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/*
 * AuthHandler 用户认证请求处理器
 * 功能：处理注册、登录、Token 刷新、登出等认证相关 HTTP 请求
 */
type AuthHandler struct {
	authService    *service.AuthService
	cfg            *config.Config
	webhookService *service.WebhookService
}

/*
 * NewAuthHandler 创建认证处理器实例
 * @param authService - 认证服务
 * @param cfg         - 系统配置（可选）
 */
func NewAuthHandler(authService *service.AuthService, cfg ...*config.Config) *AuthHandler {
	h := &AuthHandler{authService: authService}
	if len(cfg) > 0 {
		h.cfg = cfg[0]
	}
	return h
}

/* SetWebhookService 注入 Webhook 服务（用于触发用户注册/登录事件） */
func (h *AuthHandler) SetWebhookService(ws *service.WebhookService) {
	h.webhookService = ws
}

/* RegisterRequest 用户注册请求体 */
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Username string `json:"username" binding:"required,min=3,max=50"`
	Password string `json:"password" binding:"required,min=8"`
}

/* LoginRequest 用户登录请求体 */
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

/* RefreshRequest Token 刷新请求体 */
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

/* UserResponse API 响应中的用户数据结构 */
type UserResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Username      string `json:"username"`
	Role          string `json:"role"`
	Avatar        string `json:"avatar,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     string `json:"created_at"`
}

/*
 * Register 用户注册
 * @route POST /api/auth/register
 * @param email    - 邮箱
 * @param username - 用户名（3-50 字符）
 * @param password - 密码（最少 8 字符）
 */
func (h *AuthHandler) Register(c *gin.Context) {
	/* 检查注册开关 */
	if h.cfg != nil && !h.cfg.Server.AllowRegistration {
		Error(c, http.StatusForbidden, ErrCodeRegistrationClosed, "Registration is currently disabled")
		return
	}

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, ErrCodeBadRequest, err.Error())
		return
	}

	/* 输入清洗：防止 XSS 和非法字符 */
	req.Email = sanitize.Email(req.Email)
	req.Username = sanitize.StripHTML(req.Username)
	username, valid := sanitize.Username(req.Username)
	if !valid {
		Error(c, http.StatusBadRequest, ErrCodeBadRequest, "Username can only contain letters, numbers, underscores, hyphens and CJK characters (3-50 chars)")
		return
	}
	req.Username = username

	user, err := h.authService.Register(&service.RegisterInput{
		Email:    req.Email,
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		if errors.Is(err, service.ErrEmailExists) {
			Error(c, http.StatusConflict, ErrCodeEmailExists, "Email already exists")
			return
		}
		if errors.Is(err, service.ErrUsernameExists) {
			Error(c, http.StatusConflict, ErrCodeUsernameExists, "Username already exists")
			return
		}
		if errors.Is(err, service.ErrPasswordTooWeak) {
			Error(c, http.StatusBadRequest, ErrCodeWeakPassword, "Password must be 8-72 characters")
			return
		}
		Error(c, http.StatusInternalServerError, ErrCodeInternalError, "Failed to create user")
		return
	}

	// Trigger webhook (direct registration has no app context, use nil UUID)
	if h.webhookService != nil {
		go h.webhookService.TriggerEvent(context.Background(), uuid.Nil, model.WebhookEventUserRegistered, map[string]any{
			"user_id":  user.ID.String(),
			"email":    user.Email,
			"username": user.Username,
			"source":   "direct",
		})
	}

	Created(c, UserResponse{
		ID:            user.ID.String(),
		Email:         user.Email,
		Username:      user.Username,
		Role:          string(user.Role),
		Avatar:        user.Avatar,
		EmailVerified: user.EmailVerified,
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

/*
 * Login 用户登录
 * @route POST /api/auth/login
 * 功能：校验邮箱密码，签发 JWT 令牌对，设置 httpOnly Cookie，触发登录 Webhook
 */
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, ErrCodeBadRequest, err.Error())
		return
	}

	user, tokens, err := h.authService.Login(&service.LoginInput{
		Email:     req.Email,
		Password:  req.Password,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			Error(c, http.StatusUnauthorized, ErrCodeInvalidCredentials, "Invalid email or password")
			return
		}
		if errors.Is(err, service.ErrAccountLocked) {
			Error(c, http.StatusTooManyRequests, "ACCOUNT_LOCKED", "Account temporarily locked due to too many failed attempts. Please try again later.")
			return
		}
		Error(c, http.StatusInternalServerError, ErrCodeInternalError, "Failed to login")
		return
	}

	// Trigger webhook
	if h.webhookService != nil {
		go h.webhookService.TriggerEvent(context.Background(), uuid.Nil, model.WebhookEventUserLogin, map[string]any{
			"user_id":  user.ID.String(),
			"email":    user.Email,
			"username": user.Username,
			"source":   "direct",
		})
	}

	/* 设置 httpOnly Cookie 和 CSRF Token */
	h.setAuthCookies(c, tokens)

	Success(c, gin.H{
		"user": UserResponse{
			ID:            user.ID.String(),
			Email:         user.Email,
			Username:      user.Username,
			Role:          string(user.Role),
			Avatar:        user.Avatar,
			EmailVerified: user.EmailVerified,
			CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
		"tokens": tokens,
	})
}

/*
 * Refresh Token 刷新
 * @route POST /api/auth/refresh
 * 功能：使用 refresh_token 签发新的令牌对，支持 body 和 Cookie 两种传递方式
 */
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		/* 如果没有 body，尝试从 Cookie 获取 refresh_token */
		if token, cookieErr := c.Cookie(middleware.RefreshTokenCookie); cookieErr == nil && token != "" {
			req.RefreshToken = token
		} else {
			Error(c, http.StatusBadRequest, ErrCodeBadRequest, "refresh_token is required")
			return
		}
	}

	tokens, err := h.authService.RefreshTokens(req.RefreshToken)
	if err != nil {
		Error(c, http.StatusUnauthorized, ErrCodeTokenExpired, "Invalid or expired refresh token")
		return
	}

	/* 更新 Cookie */
	h.setAuthCookies(c, tokens)

	Success(c, tokens)
}

/*
 * Logout 用户登出
 * @route POST /api/auth/logout
 * 功能：撤销 DB 中该用户的所有 refresh token 并清除鉴权 Cookie
 */
func (h *AuthHandler) Logout(c *gin.Context) {
	/* 从当前 JWT 中提取用户 ID，撤销该用户所有 auth refresh token */
	tokenString := ""
	if authHeader := c.GetHeader("Authorization"); authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	} else if token, err := c.Cookie(middleware.AccessTokenCookie); err == nil && token != "" {
		tokenString = token
	}
	if tokenString != "" {
		if claims, err := h.authService.GetJWTManager().ValidateAccessToken(tokenString); err == nil {
			h.authService.LogoutUser(claims.UserID)
		}
	}

	/* 清除所有鉴权 Cookie */
	h.clearAuthCookies(c)

	Success(c, gin.H{"message": "Logged out successfully"})
}

/*
 * isRequestSecure 检测当前请求是否通过 HTTPS
 * 优先检查反向代理头，回退到 TLS 连接状态
 */
func isRequestSecure(c *gin.Context) bool {
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		return strings.EqualFold(proto, "https")
	}
	return c.Request.TLS != nil
}

/*
 * setCookie 使用 http.SetCookie 设置 Cookie，支持 SameSite 属性
 * Gin 内置的 c.SetCookie 不支持 SameSite，现代浏览器会按 Lax 处理未设置的情况，
 * 但显式设置可以避免跨浏览器行为不一致
 */
func setCookie(c *gin.Context, name, value string, maxAge int, path string, secure, httpOnly bool, sameSite http.SameSite) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		Secure:   secure,
		HttpOnly: httpOnly,
		SameSite: sameSite,
	})
}

/*
 * setAuthCookies 设置鉴权相关的 Cookie
 * access_token:  httpOnly, 浏览器无法通过 JS 访问，防止 XSS
 * refresh_token: httpOnly, 只在刷新路径发送
 * csrf_token:    非 httpOnly，JS 可读取后放入请求头
 *
 * Secure 标志根据实际请求协议决定（支持反向代理），而非仅看 server.mode，
 * 避免 HTTP 环境下设置 Secure Cookie 导致浏览器不发送
 */
func (h *AuthHandler) setAuthCookies(c *gin.Context, tokens *service.AuthTokens) {
	secure := isRequestSecure(c)
	sameSite := http.SameSiteLaxMode

	/* access_token - httpOnly Cookie */
	setCookie(c,
		middleware.AccessTokenCookie,
		tokens.AccessToken,
		int(tokens.ExpiresIn),
		"/",
		secure,
		true, /* httpOnly */
		sameSite,
	)

	/* refresh_token - httpOnly Cookie，限制路径 */
	refreshMaxAge := 30 * 24 * 3600 /* 30 天 */
	if h.cfg != nil {
		refreshMaxAge = h.cfg.JWT.RefreshTokenTTLDays * 24 * 3600
	}
	setCookie(c,
		middleware.RefreshTokenCookie,
		tokens.RefreshToken,
		refreshMaxAge,
		"/api/auth",
		secure,
		true, /* httpOnly */
		sameSite,
	)

	/* CSRF Token - 非 httpOnly，前端 JS 可读 */
	csrfToken := middleware.GenerateCSRFToken()
	setCookie(c,
		middleware.CSRFTokenCookie,
		csrfToken,
		int(tokens.ExpiresIn),
		"/",
		secure,
		false, /* 非 httpOnly */
		sameSite,
	)
}

/*
 * CheckPasswordStrength 密码强度实时校验（公开接口，无需认证）
 * @route POST /api/auth/check-password
 * 功能：前端注册/修改密码时实时检测密码强度，返回评分和具体项目
 */
func (h *AuthHandler) CheckPasswordStrength(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "password is required")
		return
	}
	result := password.CheckStrength(req.Password)
	validationErr := password.ValidateStrength(req.Password)
	resp := gin.H{
		"score":        result.Score,
		"level":        result.Level,
		"has_upper":    result.HasUpper,
		"has_lower":    result.HasLower,
		"has_digit":    result.HasDigit,
		"has_special":  result.HasSpecial,
		"length_valid": result.LengthValid,
		"valid":        validationErr == nil,
	}
	if validationErr != nil {
		resp["error"] = validationErr.Error()
	}
	Success(c, resp)
}

/* clearAuthCookies 清除所有鉴权 Cookie */
func (h *AuthHandler) clearAuthCookies(c *gin.Context) {
	secure := isRequestSecure(c)
	sameSite := http.SameSiteLaxMode

	setCookie(c, middleware.AccessTokenCookie, "", -1, "/", secure, true, sameSite)
	setCookie(c, middleware.RefreshTokenCookie, "", -1, "/api/auth", secure, true, sameSite)
	setCookie(c, middleware.CSRFTokenCookie, "", -1, "/", secure, false, sameSite)
}
