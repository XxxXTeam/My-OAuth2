package handler

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"server/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/*
 * SocialAuthHandler 社交登录请求处理器
 * 功能：处理社交提供者列表、发起 OAuth 登录、回调处理、账号关联/解关联等 HTTP 请求
 */
type SocialAuthHandler struct {
	socialService *service.SocialAuthService
}

/*
 * NewSocialAuthHandler 创建社交登录处理器实例
 * @param socialService - 社交登录服务
 */
func NewSocialAuthHandler(socialService *service.SocialAuthService) *SocialAuthHandler {
	return &SocialAuthHandler{socialService: socialService}
}

/*
 * GetProviders 获取可用的社交登录提供者列表（隐藏敏感信息）
 * @route GET /api/auth/social/providers
 */
func (h *SocialAuthHandler) GetProviders(c *gin.Context) {
	providers, err := h.socialService.GetEnabledProviders()
	if err != nil {
		InternalError(c, "Failed to get providers")
		return
	}

	// 隐藏敏感信息
	result := make([]gin.H, 0, len(providers))
	for _, p := range providers {
		result = append(result, gin.H{
			"slug":        p.Slug,
			"name":        p.Name,
			"description": p.Description,
			"icon_url":    p.IconURL,
			"button_text": p.ButtonText,
		})
	}

	Success(c, gin.H{"providers": result})
}

/*
 * StartAuth 发起社交登录 OAuth 流程
 * @route GET /api/auth/social/:provider
 * 功能：生成 state 并重定向到提供者的授权页面
 */
func (h *SocialAuthHandler) StartAuth(c *gin.Context) {
	providerSlug := c.Param("provider")
	returnTo := c.Query("return_to")
	if returnTo == "" {
		returnTo = "/dashboard"
	}

	// 生成state参数防止CSRF
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		InternalError(c, "Failed to generate security state")
		return
	}
	state := hex.EncodeToString(stateBytes)

	// 存储state到session/cookie（SameSite=Lax 允许回调时携带）
	secure := isRequestSecure(c)
	setCookie(c, "oauth_state", state, 600, "/", secure, true, http.SameSiteLaxMode)
	setCookie(c, "oauth_return_to", returnTo, 600, "/", secure, true, http.SameSiteLaxMode)

	// 构建回调URL
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	redirectURI := scheme + "://" + c.Request.Host + "/api/auth/social/" + providerSlug + "/callback"

	authURL, err := h.socialService.GetAuthURL(providerSlug, state, redirectURI)
	if err != nil {
		if err == service.ErrProviderNotFound {
			NotFound(c, "Provider not found")
			return
		}
		if err == service.ErrProviderDisabled {
			BadRequest(c, "Provider is disabled")
			return
		}
		InternalError(c, "Failed to generate auth URL")
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// Callback 处理社交登录回调
// GET /api/auth/social/:provider/callback
func (h *SocialAuthHandler) Callback(c *gin.Context) {
	providerSlug := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")
	errorCode := c.Query("error")

	// 获取前端URL用于重定向
	frontendURL := c.GetHeader("Origin")
	if frontendURL == "" {
		scheme := "http"
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		frontendURL = scheme + "://" + c.Request.Host
	}

	// 获取返回地址
	returnTo, _ := c.Cookie("oauth_return_to")
	if returnTo == "" {
		returnTo = "/dashboard"
	}

	// 清理cookies
	cbSecure := isRequestSecure(c)
	setCookie(c, "oauth_state", "", -1, "/", cbSecure, true, http.SameSiteLaxMode)
	setCookie(c, "oauth_return_to", "", -1, "/", cbSecure, true, http.SameSiteLaxMode)

	// 错误处理函数
	redirectWithError := func(errMsg string) {
		c.Redirect(http.StatusTemporaryRedirect, frontendURL+"/login?error="+errMsg)
	}

	// 检查授权错误
	if errorCode != "" {
		redirectWithError("oauth_denied")
		return
	}

	// 验证state
	savedState, _ := c.Cookie("oauth_state")
	if savedState == "" || savedState != state {
		redirectWithError("invalid_state")
		return
	}

	if code == "" {
		redirectWithError("missing_code")
		return
	}

	// 构建回调URL
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	redirectURI := scheme + "://" + c.Request.Host + "/api/auth/social/" + providerSlug + "/callback"

	// 交换token
	tokenResp, err := h.socialService.ExchangeCodeForToken(c.Request.Context(), providerSlug, code, redirectURI)
	if err != nil {
		redirectWithError("token_exchange_failed")
		return
	}

	// 获取用户信息
	userInfo, err := h.socialService.GetUserInfo(c.Request.Context(), providerSlug, tokenResp.AccessToken)
	if err != nil {
		redirectWithError("userinfo_failed")
		return
	}

	// 登录或创建用户
	user, tokens, err := h.socialService.LoginOrCreateUser(
		c.Request.Context(),
		providerSlug,
		userInfo,
		tokenResp,
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil {
		redirectWithError("login_failed")
		return
	}
	redirectURL := frontendURL + "/auth/callback?access_token=" + tokens.AccessToken +
		"&refresh_token=" + tokens.RefreshToken +
		"&return_to=" + returnTo +
		"&user_id=" + user.ID.String()

	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// LinkAccountRequest 关联账号请求
type LinkAccountRequest struct {
	Code        string `json:"code" binding:"required"`
	RedirectURI string `json:"redirect_uri" binding:"required"`
}

// LinkAccount 关联社交账号到已登录用户
// POST /api/auth/social/:provider/link
func (h *SocialAuthHandler) LinkAccount(c *gin.Context) {
	providerSlug := c.Param("provider")

	// 从context获取当前用户ID
	userIDValue, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "Not authenticated")
		return
	}
	userID, ok := userIDValue.(uuid.UUID)
	if !ok {
		Unauthorized(c, "Invalid user ID")
		return
	}

	var req LinkAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	err := h.socialService.LinkAccount(
		c.Request.Context(),
		userID,
		providerSlug,
		req.Code,
		req.RedirectURI,
	)
	if err != nil {
		switch err {
		case service.ErrProviderNotFound:
			NotFound(c, "Provider not found")
		case service.ErrProviderDisabled:
			BadRequest(c, "Provider is disabled")
		case service.ErrIdentityAlreadyLinked:
			BadRequest(c, "This social account is already linked to another user")
		default:
			InternalError(c, "Failed to link account")
		}
		return
	}

	Success(c, gin.H{
		"message": "Account linked successfully",
	})
}

// UnlinkAccount 解除社交账号关联
// DELETE /api/auth/social/:provider/link
func (h *SocialAuthHandler) UnlinkAccount(c *gin.Context) {
	providerSlug := c.Param("provider")

	// 从context获取当前用户ID
	userIDValue, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "Not authenticated")
		return
	}
	userID, ok := userIDValue.(uuid.UUID)
	if !ok {
		Unauthorized(c, "Invalid user ID")
		return
	}

	err := h.socialService.UnlinkAccount(userID, providerSlug)
	if err != nil {
		switch err {
		case service.ErrProviderNotFound:
			NotFound(c, "Provider not found")
		case service.ErrIdentityNotFound:
			NotFound(c, "Social account not linked")
		case service.ErrCannotUnlinkOnly:
			BadRequest(c, "Cannot unlink your only login method. Please set a password first.")
		default:
			InternalError(c, "Failed to unlink account")
		}
		return
	}

	Success(c, gin.H{
		"message": "Account unlinked successfully",
	})
}

// GetLinkedAccounts 获取已关联的社交账号
// GET /api/auth/social/linked
func (h *SocialAuthHandler) GetLinkedAccounts(c *gin.Context) {
	userIDValue, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "Not authenticated")
		return
	}
	userID, ok := userIDValue.(uuid.UUID)
	if !ok {
		Unauthorized(c, "Invalid user ID")
		return
	}

	identities, err := h.socialService.GetUserLinkedProviders(userID)
	if err != nil {
		InternalError(c, "Failed to get linked accounts")
		return
	}

	// 转换为安全的响应格式
	result := make([]gin.H, 0, len(identities))
	for _, identity := range identities {
		item := gin.H{
			"provider_id":    identity.ProviderID,
			"external_email": identity.ExternalEmail,
			"linked_at":      identity.CreatedAt,
		}
		if identity.Provider != nil {
			item["provider_name"] = identity.Provider.Name
			item["provider_slug"] = identity.Provider.Slug
		}
		result = append(result, item)
	}

	Success(c, gin.H{
		"linked_accounts": result,
	})
}
