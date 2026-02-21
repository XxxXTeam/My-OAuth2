package handler

import (
	"context"
	"errors"
	ctx "server/internal/context"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/*
 * UserHandler 用户个人信息请求处理器
 * 功能：处理用户个人资料、密码修改、授权管理、邮箱验证等 HTTP 请求
 */
type UserHandler struct {
	authService    *service.AuthService
	userRepo       *repository.UserRepository
	userAuthRepo   *repository.UserAuthorizationRepository
	appRepo        *repository.ApplicationRepository
	oauthRepo      *repository.OAuthRepository
	emailVerifySvc *service.EmailVerificationService
	webhookService *service.WebhookService
}

/* SetWebhookService 注入 Webhook 服务（用于触发用户更新事件） */
func (h *UserHandler) SetWebhookService(ws *service.WebhookService) {
	h.webhookService = ws
}

/*
 * NewUserHandler 创建用户处理器实例
 * @param authService  - 认证服务
 * @param userRepo     - 用户仓储
 * @param userAuthRepo - 用户授权仓储
 */
func NewUserHandler(authService *service.AuthService, userRepo *repository.UserRepository, userAuthRepo *repository.UserAuthorizationRepository) *UserHandler {
	return &UserHandler{
		authService:  authService,
		userRepo:     userRepo,
		userAuthRepo: userAuthRepo,
	}
}

/* SetOAuthRepo 注入 OAuth 仓储和应用仓储（用于撤销授权时同时撤销 token） */
func (h *UserHandler) SetOAuthRepo(oauthRepo *repository.OAuthRepository, appRepo *repository.ApplicationRepository) {
	h.oauthRepo = oauthRepo
	h.appRepo = appRepo
}

/* SetEmailVerificationService 注入邮箱验证服务 */
func (h *UserHandler) SetEmailVerificationService(svc *service.EmailVerificationService) {
	h.emailVerifySvc = svc
}

// GetProfile returns the current user's profile
// GET /api/user/profile
func (h *UserHandler) GetProfile(c *gin.Context) {
	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		NotFound(c, "User not found")
		return
	}

	Success(c, buildFullUserResponse(user))
}

// UpdateProfileRequest represents the profile update request
// 使用 *string 指针类型以区分"未传"和"传空"，允许用户清空字段
type UpdateProfileRequest struct {
	Username       *string            `json:"username,omitempty"`
	Avatar         *string            `json:"avatar,omitempty"`
	GivenName      *string            `json:"given_name,omitempty"`
	FamilyName     *string            `json:"family_name,omitempty"`
	Nickname       *string            `json:"nickname,omitempty"`
	Gender         *string            `json:"gender,omitempty"`
	Birthdate      *string            `json:"birthdate,omitempty"` // YYYY-MM-DD format
	PhoneNumber    *string            `json:"phone_number,omitempty"`
	Address        *model.AddressInfo `json:"address,omitempty"`
	Locale         *string            `json:"locale,omitempty"`
	Zoneinfo       *string            `json:"zoneinfo,omitempty"`
	Website        *string            `json:"website,omitempty"`
	Bio            *string            `json:"bio,omitempty"`
	SocialAccounts map[string]string  `json:"social_accounts,omitempty"`
	Company        *string            `json:"company,omitempty"`
	Department     *string            `json:"department,omitempty"`
	JobTitle       *string            `json:"job_title,omitempty"`
}

// UpdateProfile updates the current user's profile
// PUT /api/user/profile
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		NotFound(c, "User not found")
		return
	}

	// Update fields if provided (nil = not sent, pointer to "" = clear field)
	if req.Username != nil && *req.Username != "" && *req.Username != user.Username {
		exists, err := h.userRepo.ExistsByUsername(*req.Username)
		if err != nil {
			InternalError(c, "Failed to check username")
			return
		}
		if exists {
			BadRequest(c, "Username already taken")
			return
		}
		user.Username = *req.Username
	}

	if req.Avatar != nil {
		user.Avatar = *req.Avatar
	}
	if req.GivenName != nil {
		user.GivenName = *req.GivenName
	}
	if req.FamilyName != nil {
		user.FamilyName = *req.FamilyName
	}
	if req.Nickname != nil {
		user.Nickname = *req.Nickname
	}
	if req.Gender != nil {
		user.Gender = *req.Gender
	}
	if req.Birthdate != nil {
		if *req.Birthdate == "" {
			user.Birthdate = nil
		} else if t, err := time.Parse("2006-01-02", *req.Birthdate); err == nil {
			user.Birthdate = &t
		}
	}
	if req.PhoneNumber != nil {
		user.PhoneNumber = *req.PhoneNumber
	}
	if req.Address != nil {
		user.SetAddress(req.Address)
	}
	if req.Locale != nil {
		user.Locale = *req.Locale
	}
	if req.Zoneinfo != nil {
		user.Zoneinfo = *req.Zoneinfo
	}
	if req.Website != nil {
		user.Website = *req.Website
	}
	if req.Bio != nil {
		user.Bio = *req.Bio
	}
	if req.SocialAccounts != nil {
		user.SetSocialAccounts(req.SocialAccounts)
	}
	if req.Company != nil {
		user.Company = *req.Company
	}
	if req.Department != nil {
		user.Department = *req.Department
	}
	if req.JobTitle != nil {
		user.JobTitle = *req.JobTitle
	}

	// Mark profile as completed if key fields are filled
	if user.GivenName != "" || user.Nickname != "" {
		user.ProfileCompleted = true
	}

	if err := h.userRepo.Update(user); err != nil {
		InternalError(c, "Failed to update profile")
		return
	}

	// Trigger webhook for user.updated
	if h.webhookService != nil {
		go h.webhookService.TriggerEvent(context.Background(), uuid.Nil, model.WebhookEventUserUpdated, map[string]any{
			"user_id":  user.ID.String(),
			"email":    user.Email,
			"username": user.Username,
		})
	}

	Success(c, buildFullUserResponse(user))
}

// buildFullUserResponse creates a complete user response with all fields
func buildFullUserResponse(user *model.User) gin.H {
	response := gin.H{
		"id":                user.ID.String(),
		"email":             user.Email,
		"username":          user.Username,
		"role":              string(user.Role),
		"avatar":            user.Avatar,
		"email_verified":    user.EmailVerified,
		"profile_completed": user.ProfileCompleted,
		"created_at":        user.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	if user.GivenName != "" {
		response["given_name"] = user.GivenName
	}
	if user.FamilyName != "" {
		response["family_name"] = user.FamilyName
	}
	if user.Nickname != "" {
		response["nickname"] = user.Nickname
	}
	if user.Gender != "" {
		response["gender"] = user.Gender
	}
	if user.Birthdate != nil {
		response["birthdate"] = user.Birthdate.Format("2006-01-02")
	}
	if user.PhoneNumber != "" {
		response["phone_number"] = user.PhoneNumber
	}
	if user.Address != "" {
		response["address"] = user.GetAddress()
	}
	if user.Locale != "" {
		response["locale"] = user.Locale
	}
	if user.Zoneinfo != "" {
		response["zoneinfo"] = user.Zoneinfo
	}
	if user.Website != "" {
		response["website"] = user.Website
	}
	if user.Bio != "" {
		response["bio"] = user.Bio
	}
	socialAccounts := user.GetSocialAccounts()
	if len(socialAccounts) > 0 {
		response["social_accounts"] = socialAccounts
	}
	if user.Company != "" {
		response["company"] = user.Company
	}
	if user.Department != "" {
		response["department"] = user.Department
	}
	if user.JobTitle != "" {
		response["job_title"] = user.JobTitle
	}
	if user.EmployeeID != "" {
		response["employee_id"] = user.EmployeeID
	}
	if user.Status != "" {
		response["status"] = user.Status
	} else {
		response["status"] = "active"
	}
	response["updated_at"] = user.UpdatedAt.Format("2006-01-02T15:04:05Z")
	if user.LastLoginAt != nil {
		response["last_login_at"] = user.LastLoginAt.Format("2006-01-02T15:04:05Z")
	}

	return response
}

// GetAuthorizations returns the current user's authorized apps
// GET /api/user/authorizations
func (h *UserHandler) GetAuthorizations(c *gin.Context) {
	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	auths, err := h.userAuthRepo.FindByUser(userID)
	if err != nil {
		InternalError(c, "Failed to fetch authorizations")
		return
	}

	// Convert to response format
	var result []map[string]interface{}
	for _, auth := range auths {
		item := map[string]interface{}{
			"id":            auth.ID.String(),
			"app_id":        auth.AppID.String(),
			"scope":         auth.Scope,
			"grant_type":    auth.GrantType,
			"authorized_at": auth.AuthorizedAt.Format("2006-01-02T15:04:05Z"),
			"revoked":       auth.Revoked,
		}
		if auth.App.ID.String() != "00000000-0000-0000-0000-000000000000" {
			item["app"] = map[string]interface{}{
				"id":          auth.App.ID.String(),
				"name":        auth.App.Name,
				"description": auth.App.Description,
			}
		}
		if auth.RevokedAt != nil {
			item["revoked_at"] = auth.RevokedAt.Format("2006-01-02T15:04:05Z")
		}
		result = append(result, item)
	}

	Success(c, gin.H{"authorizations": result})
}

// RevokeAuthorization revokes a user's authorization to an app
// DELETE /api/user/authorizations/:id
func (h *UserHandler) RevokeAuthorization(c *gin.Context) {
	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	authID := c.Param("id")
	if authID == "" {
		BadRequest(c, "Authorization ID is required")
		return
	}

	// Find the authorization and verify ownership
	auth, err := h.userAuthRepo.FindByID(parseUUID(authID))
	if err != nil {
		NotFound(c, "Authorization not found")
		return
	}

	// Verify the authorization belongs to the current user
	if auth.UserID != userID {
		Forbidden(c, "You can only revoke your own authorizations")
		return
	}

	if err := h.userAuthRepo.Revoke(auth.ID); err != nil {
		InternalError(c, "Failed to revoke authorization")
		return
	}

	/* 同时撤销该应用签发给该用户的所有 OAuth token（access_token + refresh_token） */
	if h.oauthRepo != nil && h.appRepo != nil {
		if app, appErr := h.appRepo.FindByID(auth.AppID); appErr == nil {
			if revokeErr := h.oauthRepo.RevokeTokensByClientAndUser(app.ClientID, userID); revokeErr != nil {
				/* 非关键错误，仅记录日志 */
				c.Error(revokeErr)
			}
		}
	}

	// Trigger webhook for oauth.revoked
	if h.webhookService != nil {
		go h.webhookService.TriggerEvent(context.Background(), auth.AppID, model.WebhookEventOAuthRevoked, map[string]any{
			"user_id":          userID.String(),
			"authorization_id": auth.ID.String(),
			"app_id":           auth.AppID.String(),
			"scope":            auth.Scope,
		})
	}

	Success(c, gin.H{"message": "Authorization revoked"})
}

// ChangePasswordRequest 修改密码请求
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// ChangePassword 修改用户密码
// PUT /api/user/password
func (h *UserHandler) ChangePassword(c *gin.Context) {
	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	if err := h.authService.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			BadRequest(c, "Old password is incorrect")
			return
		}
		InternalError(c, "Failed to change password")
		return
	}

	Success(c, gin.H{"message": "Password changed successfully"})
}

// SendEmailVerification 发送邮箱验证邮件
// POST /api/user/email/send-verify
func (h *UserHandler) SendEmailVerification(c *gin.Context) {
	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	if err := h.emailVerifySvc.RequestVerification(userID); err != nil {
		switch err {
		case service.ErrEmailAlreadyVerified:
			BadRequest(c, "Email already verified")
		case service.ErrVerifyTooManyRequests:
			TooManyRequests(c, "Too many verification requests, please try later")
		case service.ErrEmailServiceRequired:
			ServiceUnavailable(c, "Email service is currently unavailable")
		default:
			InternalError(c, "Failed to send verification email")
		}
		return
	}

	Success(c, gin.H{"message": "Verification email queued"})
}

// VerifyEmail 验证邮箱令牌
// POST /api/user/email/verify
func (h *UserHandler) VerifyEmail(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "Token is required")
		return
	}

	if err := h.emailVerifySvc.VerifyEmail(req.Token); err != nil {
		switch err {
		case service.ErrVerifyTokenInvalid:
			BadRequest(c, "Invalid or expired verification token")
		case service.ErrVerifyTokenExpired:
			BadRequest(c, "Verification token has expired")
		case service.ErrEmailAlreadyInUse:
			BadRequest(c, "Email is already in use by another account")
		default:
			InternalError(c, "Failed to verify email")
		}
		return
	}

	Success(c, gin.H{"message": "Email verified successfully"})
}

// RequestEmailChange 请求更换邮箱
// POST /api/user/email/change
func (h *UserHandler) RequestEmailChange(c *gin.Context) {
	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	var req struct {
		NewEmail string `json:"new_email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "Valid email address is required")
		return
	}

	if err := h.emailVerifySvc.RequestEmailChange(userID, req.NewEmail); err != nil {
		switch err {
		case service.ErrEmailAlreadyInUse:
			BadRequest(c, "Email is already in use")
		case service.ErrVerifyTooManyRequests:
			TooManyRequests(c, "Too many requests, please try later")
		case service.ErrEmailServiceRequired:
			ServiceUnavailable(c, "Email service is currently unavailable")
		default:
			InternalError(c, "Failed to send verification email")
		}
		return
	}

	Success(c, gin.H{"message": "Verification email sent to new address"})
}

// parseUUID helper function
func parseUUID(s string) uuid.UUID {
	id, _ := uuid.Parse(s)
	return id
}
