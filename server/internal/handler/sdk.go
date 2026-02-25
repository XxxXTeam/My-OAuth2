package handler

import (
	"context"
	"errors"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"
	"server/pkg/sanitize"

	"github.com/gin-gonic/gin"
)

/*
 * SDKHandler SDK 接入请求处理器
 * 功能：处理第三方应用通过 SDK 进行的用户注册、登录、Token 刷新/验证、用户同步等 HTTP 请求
 *       所有请求需携带 client_id + client_secret 进行客户端认证
 */
type SDKHandler struct {
	authService    *service.AuthService
	appRepo        *repository.ApplicationRepository
	jwtManager     *jwt.Manager
	webhookService *service.WebhookService
}

/*
 * NewSDKHandler 创建 SDK 处理器实例
 * @param authService - 认证服务
 * @param appRepo     - 应用仓储
 * @param jwtManager  - JWT 管理器
 */
func NewSDKHandler(authService *service.AuthService, appRepo *repository.ApplicationRepository, jwtManager *jwt.Manager) *SDKHandler {
	return &SDKHandler{
		authService: authService,
		appRepo:     appRepo,
		jwtManager:  jwtManager,
	}
}

/* SetWebhookService 注入 Webhook 服务（用于触发用户注册/登录事件） */
func (h *SDKHandler) SetWebhookService(ws *service.WebhookService) {
	h.webhookService = ws
}

/* SDKRegisterRequest SDK 用户注册请求体 */
type SDKRegisterRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	Email        string `json:"email" binding:"required,email"`
	Username     string `json:"username" binding:"required,min=3,max=50"`
	Password     string `json:"password" binding:"required,min=8"`
}

/* SDKLoginRequest SDK 用户登录请求体 */
type SDKLoginRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	Email        string `json:"email" binding:"required,email"`
	Password     string `json:"password" binding:"required"`
}

// SDKTokenResponse represents token response for SDK
type SDKTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	User         struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"user"`
}

// Register handles user registration via SDK
// POST /api/sdk/register
func (h *SDKHandler) Register(c *gin.Context) {
	var req SDKRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Validate client credentials
	app, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	/* 输入清洗 */
	req.Email = sanitize.Email(req.Email)
	if u, ok := sanitize.Username(req.Username); ok {
		req.Username = u
	} else {
		BadRequest(c, "Invalid username format")
		return
	}

	// Register user
	user, err := h.authService.Register(&service.RegisterInput{
		Email:    req.Email,
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		if errors.Is(err, service.ErrEmailExists) {
			Conflict(c, "Email already exists")
			return
		}
		if errors.Is(err, service.ErrUsernameExists) {
			Conflict(c, "Username already exists")
			return
		}
		InternalError(c, "Failed to create user")
		return
	}

	// Generate tokens for the app
	accessToken, _ := h.jwtManager.GenerateToken(user.ID, user.Email, user.Username, string(user.Role), jwt.TokenTypeAccess, 24*time.Hour)
	refreshToken, _ := h.jwtManager.GenerateToken(user.ID, user.Email, user.Username, string(user.Role), jwt.TokenTypeRefresh, 7*24*time.Hour)

	// Emit SSE event
	EmitAuthEvent(AuthEvent{
		Type:      "user_registered",
		AppID:     app.ID.String(),
		AppName:   app.Name,
		UserID:    user.ID.String(),
		Username:  user.Username,
		Email:     user.Email,
		Timestamp: time.Now(),
	})

	// Trigger webhook
	if h.webhookService != nil {
		go h.webhookService.TriggerEvent(context.Background(), app.ID, model.WebhookEventUserRegistered, map[string]any{
			"user_id":  user.ID.String(),
			"email":    user.Email,
			"username": user.Username,
			"source":   "sdk",
		})
	}

	resp := SDKTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    86400,
	}
	resp.User.ID = user.ID.String()
	resp.User.Email = user.Email
	resp.User.Username = user.Username
	resp.User.Role = string(user.Role)

	Created(c, resp)
}

// Login handles user login via SDK
// POST /api/sdk/login
func (h *SDKHandler) Login(c *gin.Context) {
	var req SDKLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Validate client credentials
	app, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	// Login user
	user, _, err := h.authService.Login(&service.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			Unauthorized(c, "Invalid email or password")
			return
		}
		InternalError(c, "Failed to login")
		return
	}

	// Generate tokens for the app
	accessToken, _ := h.jwtManager.GenerateToken(user.ID, user.Email, user.Username, string(user.Role), jwt.TokenTypeAccess, 24*time.Hour)
	refreshToken, _ := h.jwtManager.GenerateToken(user.ID, user.Email, user.Username, string(user.Role), jwt.TokenTypeRefresh, 7*24*time.Hour)

	// Emit SSE event
	EmitAuthEvent(AuthEvent{
		Type:      "user_login",
		AppID:     app.ID.String(),
		AppName:   app.Name,
		UserID:    user.ID.String(),
		Username:  user.Username,
		Email:     user.Email,
		Timestamp: time.Now(),
	})

	// Trigger webhook
	if h.webhookService != nil {
		go h.webhookService.TriggerEvent(context.Background(), app.ID, model.WebhookEventUserLogin, map[string]any{
			"user_id":  user.ID.String(),
			"email":    user.Email,
			"username": user.Username,
			"source":   "sdk",
		})
	}

	resp := SDKTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    86400,
	}
	resp.User.ID = user.ID.String()
	resp.User.Email = user.Email
	resp.User.Username = user.Username
	resp.User.Role = string(user.Role)

	Success(c, resp)
}

// SignTokenRequest represents custom token signing request
type SignTokenRequest struct {
	ClientID     string                 `json:"client_id" binding:"required"`
	ClientSecret string                 `json:"client_secret" binding:"required"`
	UserID       string                 `json:"user_id" binding:"required"`
	Claims       map[string]interface{} `json:"claims"`
	ExpiresIn    int64                  `json:"expires_in"` // seconds, default 3600
}

// SignToken signs a custom token for the application
// POST /token/sign
func (h *SDKHandler) SignToken(c *gin.Context) {
	var req SignTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Validate client credentials
	_, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	// Get user
	userID, err := model.ParseUUID(req.UserID)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		NotFound(c, "User not found")
		return
	}

	// Set default expiration
	expiresIn := req.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	if expiresIn > 86400*30 { // Max 30 days
		expiresIn = 86400 * 30
	}

	// Generate custom token
	token, err := h.jwtManager.GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeAccess,
		time.Duration(expiresIn)*time.Second,
	)
	if err != nil {
		InternalError(c, "Failed to generate token")
		return
	}

	Success(c, gin.H{
		"token":      token,
		"token_type": "Bearer",
		"expires_in": expiresIn,
	})
}

// ========== 用户同步 API ==========

// SyncUserRequest 用户同步请求（接入应用注册的用户同步到OAuth系统）
type SyncUserRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`

	// 必填字段
	Email    string `json:"email" binding:"required,email"`
	Username string `json:"username" binding:"required,min=2,max=50"`

	// 外部系统ID（用于关联）
	ExternalID string `json:"external_id"`

	// 可选：设置密码（如果用户需要直接登录OAuth系统）
	Password string `json:"password,omitempty"`

	// OIDC标准字段
	GivenName   string `json:"given_name,omitempty"`
	FamilyName  string `json:"family_name,omitempty"`
	Nickname    string `json:"nickname,omitempty"`
	Gender      string `json:"gender,omitempty"`
	Birthdate   string `json:"birthdate,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Avatar      string `json:"avatar,omitempty"`

	// 元数据
	EmailVerified bool `json:"email_verified"`
}

// SyncUser 同步用户到OAuth系统
// POST /api/sdk/sync/user
func (h *SDKHandler) SyncUser(c *gin.Context) {
	var req SyncUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 验证应用凭据
	app, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	// 查找是否已存在用户
	existingUser, _ := h.authService.GetUserByEmail(req.Email)

	if existingUser != nil {
		// 用户已存在，更新资料
		h.updateUserProfile(existingUser, &req)

		Success(c, gin.H{
			"action": "updated",
			"user": gin.H{
				"id":       existingUser.ID.String(),
				"email":    existingUser.Email,
				"username": existingUser.Username,
			},
		})
		return
	}

	// 创建新用户
	passwordHash := ""
	if req.Password != "" {
		// 如果提供了密码，则哈希存储
		user, err := h.authService.Register(&service.RegisterInput{
			Email:    req.Email,
			Username: req.Username,
			Password: req.Password,
		})
		if err != nil {
			if errors.Is(err, service.ErrUsernameExists) {
				// 用户名已存在，尝试添加后缀
				suffix := req.ExternalID
				if len(suffix) > 6 {
					suffix = suffix[:6]
				}
				req.Username = req.Username + "_" + suffix
				user, err = h.authService.Register(&service.RegisterInput{
					Email:    req.Email,
					Username: req.Username,
					Password: req.Password,
				})
			}
			if err != nil {
				InternalError(c, "Failed to create user: "+err.Error())
				return
			}
		}
		h.updateUserProfile(user, &req)

		EmitAuthEvent(AuthEvent{
			Type:      "user_registered",
			AppID:     app.ID.String(),
			AppName:   app.Name,
			UserID:    user.ID.String(),
			Username:  user.Username,
			Email:     user.Email,
			Timestamp: time.Now(),
		})

		Created(c, gin.H{
			"action": "created",
			"user": gin.H{
				"id":       user.ID.String(),
				"email":    user.Email,
				"username": user.Username,
			},
		})
		return
	}

	// 无密码用户（只能通过OAuth登录）
	newUser := &model.User{
		Email:         req.Email,
		Username:      req.Username,
		PasswordHash:  passwordHash,
		EmailVerified: req.EmailVerified,
		GivenName:     req.GivenName,
		FamilyName:    req.FamilyName,
		Nickname:      req.Nickname,
		Gender:        req.Gender,
		PhoneNumber:   req.PhoneNumber,
		Avatar:        req.Avatar,
	}

	if req.Birthdate != "" {
		if t, err := time.Parse("2006-01-02", req.Birthdate); err == nil {
			newUser.Birthdate = &t
		}
	}

	if err := h.authService.CreateUser(newUser); err != nil {
		// 用户名冲突处理
		if errors.Is(err, service.ErrUsernameExists) && req.ExternalID != "" {
			suffix := req.ExternalID
			if len(suffix) > 6 {
				suffix = suffix[:6]
			}
			newUser.Username = req.Username + "_" + suffix
			err = h.authService.CreateUser(newUser)
		}
		if err != nil {
			InternalError(c, "Failed to create user: "+err.Error())
			return
		}
	}

	EmitAuthEvent(AuthEvent{
		Type:      "user_registered",
		AppID:     app.ID.String(),
		AppName:   app.Name,
		UserID:    newUser.ID.String(),
		Username:  newUser.Username,
		Email:     newUser.Email,
		Timestamp: time.Now(),
	})

	Created(c, gin.H{
		"action": "created",
		"user": gin.H{
			"id":       newUser.ID.String(),
			"email":    newUser.Email,
			"username": newUser.Username,
		},
	})
}

// updateUserProfile 更新用户资料
func (h *SDKHandler) updateUserProfile(user *model.User, req *SyncUserRequest) {
	updated := false

	if req.GivenName != "" && user.GivenName == "" {
		user.GivenName = req.GivenName
		updated = true
	}
	if req.FamilyName != "" && user.FamilyName == "" {
		user.FamilyName = req.FamilyName
		updated = true
	}
	if req.Nickname != "" && user.Nickname == "" {
		user.Nickname = req.Nickname
		updated = true
	}
	if req.Gender != "" && user.Gender == "" {
		user.Gender = req.Gender
		updated = true
	}
	if req.PhoneNumber != "" && user.PhoneNumber == "" {
		user.PhoneNumber = req.PhoneNumber
		updated = true
	}
	if req.Avatar != "" && user.Avatar == "" {
		user.Avatar = req.Avatar
		updated = true
	}
	if req.EmailVerified && !user.EmailVerified {
		user.EmailVerified = true
		updated = true
	}
	if req.Birthdate != "" && user.Birthdate == nil {
		if t, err := time.Parse("2006-01-02", req.Birthdate); err == nil {
			user.Birthdate = &t
			updated = true
		}
	}

	if updated {
		h.authService.UpdateUser(user)
	}
}

// GetUserRequest 获取用户请求
type GetUserRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	Email        string `json:"email,omitempty"`
	UserID       string `json:"user_id,omitempty"`
}

// GetUser 获取用户信息
// POST /api/sdk/user
func (h *SDKHandler) GetUser(c *gin.Context) {
	var req GetUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 验证应用凭据
	_, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	var user *model.User

	if req.UserID != "" {
		userID, err := model.ParseUUID(req.UserID)
		if err != nil {
			BadRequest(c, "Invalid user ID")
			return
		}
		user, err = h.authService.GetUserByID(userID)
	} else if req.Email != "" {
		user, err = h.authService.GetUserByEmail(req.Email)
	} else {
		BadRequest(c, "email or user_id is required")
		return
	}

	if err != nil || user == nil {
		NotFound(c, "User not found")
		return
	}

	Success(c, gin.H{
		"user": buildUserResponse(user),
	})
}

// BatchSyncRequest 批量同步请求
type BatchSyncRequest struct {
	ClientID     string            `json:"client_id" binding:"required"`
	ClientSecret string            `json:"client_secret" binding:"required"`
	Users        []SyncUserRequest `json:"users" binding:"required,min=1,max=100"`
}

// BatchSync 批量同步用户
// POST /api/sdk/sync/batch
func (h *SDKHandler) BatchSync(c *gin.Context) {
	var req BatchSyncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 验证应用凭据
	_, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	results := make([]gin.H, 0, len(req.Users))
	created := 0
	updated := 0
	failed := 0

	for _, userReq := range req.Users {
		userReq.ClientID = req.ClientID
		userReq.ClientSecret = req.ClientSecret

		existingUser, _ := h.authService.GetUserByEmail(userReq.Email)

		if existingUser != nil {
			h.updateUserProfile(existingUser, &userReq)
			results = append(results, gin.H{
				"email":  userReq.Email,
				"action": "updated",
				"id":     existingUser.ID.String(),
			})
			updated++
		} else {
			newUser := &model.User{
				Email:         userReq.Email,
				Username:      userReq.Username,
				EmailVerified: userReq.EmailVerified,
				GivenName:     userReq.GivenName,
				FamilyName:    userReq.FamilyName,
				Nickname:      userReq.Nickname,
				Avatar:        userReq.Avatar,
			}

			if err := h.authService.CreateUser(newUser); err != nil {
				results = append(results, gin.H{
					"email":  userReq.Email,
					"action": "failed",
					"error":  err.Error(),
				})
				failed++
			} else {
				results = append(results, gin.H{
					"email":  userReq.Email,
					"action": "created",
					"id":     newUser.ID.String(),
				})
				created++
			}
		}
	}

	Success(c, gin.H{
		"total":   len(req.Users),
		"created": created,
		"updated": updated,
		"failed":  failed,
		"results": results,
	})
}

// ========== SDK Token Refresh ==========

// SDKRefreshRequest SDK token 刷新请求
type SDKRefreshRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// RefreshToken 使用 refresh token 换取新的 token 对
// POST /api/sdk/refresh
func (h *SDKHandler) RefreshToken(c *gin.Context) {
	var req SDKRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 验证应用凭据
	_, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	// 刷新 token（复用 AuthService 的 Token Rotation 逻辑）
	tokens, err := h.authService.RefreshTokens(req.RefreshToken)
	if err != nil {
		Unauthorized(c, "Invalid or expired refresh token")
		return
	}

	Success(c, gin.H{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"token_type":    tokens.TokenType,
		"expires_in":    tokens.ExpiresIn,
	})
}

// ========== SDK Token Verify ==========

// SDKVerifyRequest SDK token 验证请求
type SDKVerifyRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	AccessToken  string `json:"access_token" binding:"required"`
}

// VerifyToken 验证 access token 有效性并返回用户信息
// POST /api/sdk/verify
func (h *SDKHandler) VerifyToken(c *gin.Context) {
	var req SDKVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 验证应用凭据
	_, err := h.appRepo.ValidateCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		Unauthorized(c, "Invalid client credentials")
		return
	}

	// 验证 access token
	claims, err := h.jwtManager.ValidateToken(req.AccessToken)
	if err != nil {
		Unauthorized(c, "Invalid or expired access token")
		return
	}

	// 获取用户完整信息
	user, err := h.authService.GetUserByID(claims.UserID)
	if err != nil {
		NotFound(c, "User not found")
		return
	}

	Success(c, gin.H{
		"valid": true,
		"user":  buildUserResponse(user),
		"claims": gin.H{
			"sub":   claims.UserID.String(),
			"email": claims.Email,
			"role":  claims.Role,
			"exp":   claims.ExpiresAt.Unix(),
			"iat":   claims.IssuedAt.Unix(),
		},
	})
}

// buildUserResponse 构建用户响应
func buildUserResponse(user *model.User) gin.H {
	resp := gin.H{
		"id":             user.ID.String(),
		"email":          user.Email,
		"username":       user.Username,
		"email_verified": user.EmailVerified,
		"role":           string(user.Role),
		"created_at":     user.CreatedAt,
	}

	if user.GivenName != "" {
		resp["given_name"] = user.GivenName
	}
	if user.FamilyName != "" {
		resp["family_name"] = user.FamilyName
	}
	if user.Nickname != "" {
		resp["nickname"] = user.Nickname
	}
	if user.Avatar != "" {
		resp["avatar"] = user.Avatar
	}
	if user.PhoneNumber != "" {
		resp["phone_number"] = user.PhoneNumber
	}

	return resp
}
