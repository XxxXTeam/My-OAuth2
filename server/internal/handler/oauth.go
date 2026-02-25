package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	gctx "server/internal/context"
	"server/internal/model"
	"server/internal/service"
	"server/pkg/audit"

	"github.com/gin-gonic/gin"
)

/*
 * OAuthHandler OAuth2 核心请求处理器
 * 功能：处理 OAuth2 授权、Token 签发/撤销、UserInfo、Introspection 等 HTTP 请求
 */
type OAuthHandler struct {
	oauthService   *service.OAuthService
	webhookService *service.WebhookService
	frontendURL    string
}

/*
 * NewOAuthHandler 创建 OAuth2 处理器实例
 * @param oauthService   - OAuth2 服务
 * @param webhookService - Webhook 服务
 * @param frontendURL    - 前端 URL（用于授权重定向）
 */
func NewOAuthHandler(oauthService *service.OAuthService, webhookService *service.WebhookService, frontendURL string) *OAuthHandler {
	return &OAuthHandler{
		oauthService:   oauthService,
		webhookService: webhookService,
		frontendURL:    frontendURL,
	}
}

/* AuthorizeRequest OAuth2 授权请求参数，支持 PKCE */
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" binding:"required"`
	ClientID            string `form:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" binding:"required"`
	Scope               string `form:"scope"`
	State               string `form:"state"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
}

/*
 * Authorize OAuth2 授权端点
 * @route GET /oauth/authorize
 * 功能：重定向到前端授权页面，携带所有授权参数
 */
func (h *OAuthHandler) Authorize(c *gin.Context) {
	// Redirect to frontend for authorization UI
	if h.frontendURL == "" {
		// Embedded frontend - no redirect needed, let SPA handle it
		// Return a signal that this should be handled by SPA
		c.Set("serve_spa", true)
		c.Next()
		return
	}
	// Separate frontend - redirect to full URL
	frontendAuthURL := fmt.Sprintf("%s/oauth/authorize?%s", h.frontendURL, c.Request.URL.RawQuery)
	c.Redirect(http.StatusFound, frontendAuthURL)
}

// IsEmbeddedFrontend returns whether we're using embedded frontend
func (h *OAuthHandler) IsEmbeddedFrontend() bool {
	return h.frontendURL == ""
}

// GetAppInfo returns application info for authorization page
// GET /api/oauth/app-info
func (h *OAuthHandler) GetAppInfo(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")

	if clientID == "" {
		BadRequest(c, "client_id is required")
		return
	}

	app, err := h.oauthService.GetApplication(clientID)
	if err != nil {
		NotFound(c, "Application not found")
		return
	}

	// Validate redirect URI if provided
	if redirectURI != "" {
		validURI := false
		for _, uri := range app.GetRedirectURIs() {
			if uri == redirectURI {
				validURI = true
				break
			}
		}
		if !validURI {
			BadRequest(c, "Invalid redirect_uri")
			return
		}
	}

	Success(c, gin.H{
		"app": gin.H{
			"id":          app.ID.String(),
			"name":        app.Name,
			"description": app.Description,
		},
	})
}

// AuthorizeSubmitRequest represents the authorization submission request
type AuthorizeSubmitRequest struct {
	ClientID            string `json:"client_id" binding:"required"`
	RedirectURI         string `json:"redirect_uri" binding:"required"`
	ResponseType        string `json:"response_type" binding:"required"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Consent             string `json:"consent" binding:"required"` // "allow" or "deny"
}

// AuthorizeSubmit handles authorization consent submission from frontend
// POST /api/oauth/authorize
func (h *OAuthHandler) AuthorizeSubmit(c *gin.Context) {
	var req AuthorizeSubmitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Validate response_type
	if req.ResponseType != "code" {
		BadRequest(c, "Only 'code' response type is supported")
		return
	}

	// Get the authenticated user
	userID, ok := gctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	// Get application info
	app, err := h.oauthService.GetApplication(req.ClientID)
	if err != nil {
		NotFound(c, "Application not found")
		return
	}

	// Handle deny
	if req.Consent != "allow" {
		audit.Log(audit.ActionTokenRevoke, audit.ResultSuccess, userID.String(), req.ClientID, c.ClientIP(), "event", "authorize_denied")
		redirectURL := h.buildRedirectURL(req.RedirectURI, map[string]string{
			"error":             "access_denied",
			"error_description": "User denied access",
			"state":             req.State,
		})
		Success(c, gin.H{
			"redirect_url": redirectURL,
		})
		return
	}

	// Create authorization code
	result, err := h.oauthService.Authorize(&service.AuthorizeInput{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		ResponseType:        req.ResponseType,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		UserID:              userID,
	})
	if err != nil {
		/* 区分客户端错误和服务端错误，PKCE/scope/redirect 等返回 400 */
		switch {
		case errors.Is(err, service.ErrInvalidClient),
			errors.Is(err, service.ErrInvalidRedirectURI),
			errors.Is(err, service.ErrInvalidScope):
			BadRequest(c, err.Error())
		default:
			/* PKCE 等自定义 errors.New 错误也归为客户端请求错误 */
			BadRequest(c, err.Error())
		}
		return
	}

	// Emit SSE event for authorization
	username, _ := gctx.GetUserUsername(c)
	EmitAuthEvent(AuthEvent{
		Type:      "oauth_authorized",
		AppID:     app.ID.String(),
		AppName:   app.Name,
		UserID:    userID.String(),
		Username:  username,
		Scope:     req.Scope,
		Timestamp: time.Now(),
	})

	// Trigger webhook for oauth.authorized
	if h.webhookService != nil {
		go h.webhookService.TriggerEvent(context.Background(), app.ID, model.WebhookEventOAuthAuthorized, map[string]any{
			"user_id":   userID.String(),
			"username":  username,
			"client_id": app.ClientID,
			"app_name":  app.Name,
			"scope":     req.Scope,
		})
	}

	// Return redirect URL with authorization code
	redirectURL := h.buildRedirectURL(result.RedirectURI, map[string]string{
		"code":  result.Code,
		"state": result.State,
	})

	audit.Log(audit.ActionTokenIssue, audit.ResultSuccess, userID.String(), req.ClientID, c.ClientIP(), "event", "authorize_approved", "scope", req.Scope)

	Success(c, gin.H{
		"redirect_url": redirectURL,
		"code":         result.Code,
		"state":        result.State,
	})
}

// TokenRequest represents the token request
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	RefreshToken string `form:"refresh_token"`
	CodeVerifier string `form:"code_verifier"`
	Scope        string `form:"scope"`       // For client_credentials grant
	DeviceCode   string `form:"device_code"` // For device_code grant
	// Token Exchange (RFC 8693)
	SubjectToken       string `form:"subject_token"`
	SubjectTokenType   string `form:"subject_token_type"`
	ActorToken         string `form:"actor_token"`
	ActorTokenType     string `form:"actor_token_type"`
	RequestedTokenType string `form:"requested_token_type"`
	Audience           string `form:"audience"`
	Resource           string `form:"resource"`
}

// Token handles the token endpoint
// POST /oauth/token
func (h *OAuthHandler) Token(c *gin.Context) {
	var req TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Try to get client credentials from Authorization header
	if req.ClientID == "" || req.ClientSecret == "" {
		clientID, clientSecret, ok := c.Request.BasicAuth()
		if ok {
			req.ClientID = clientID
			req.ClientSecret = clientSecret
		}
	}

	result, err := h.oauthService.Token(&service.TokenInput{
		GrantType:          req.GrantType,
		Code:               req.Code,
		RedirectURI:        req.RedirectURI,
		ClientID:           req.ClientID,
		ClientSecret:       req.ClientSecret,
		RefreshToken:       req.RefreshToken,
		CodeVerifier:       req.CodeVerifier,
		Scope:              req.Scope,
		DeviceCode:         req.DeviceCode,
		SubjectToken:       req.SubjectToken,
		SubjectTokenType:   req.SubjectTokenType,
		ActorToken:         req.ActorToken,
		ActorTokenType:     req.ActorTokenType,
		RequestedTokenType: req.RequestedTokenType,
		Audience:           req.Audience,
		Resource:           req.Resource,
	})
	if err != nil {
		h.handleTokenError(c, err)
		return
	}

	// Trigger webhook for token issued event
	if h.webhookService != nil && req.ClientID != "" {
		app, _ := h.oauthService.GetApplication(req.ClientID)
		if app != nil {
			eventType := model.WebhookEventTokenIssued
			if req.GrantType == "refresh_token" {
				eventType = model.WebhookEventTokenRefreshed
			}
			go h.webhookService.TriggerEvent(context.Background(), app.ID, eventType, map[string]any{
				"client_id":  req.ClientID,
				"grant_type": req.GrantType,
				"scope":      result.Scope,
				"token_type": result.TokenType,
				"expires_in": result.ExpiresIn,
				"issued_at":  time.Now().Unix(),
			})
		}
	}

	/* 审计日志：记录 token 签发 */
	actorID := req.ClientID
	if uid, ok := gctx.GetUserID(c); ok {
		actorID = uid.String()
	}
	audit.Log(audit.ActionTokenIssue, audit.ResultSuccess, actorID, req.ClientID, c.ClientIP(), "grant_type", req.GrantType)

	/* RFC 6749 Section 5.1: Token 响应必须包含 Cache-Control 和 Pragma 头 */
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, result)
}

// RevokeRequest represents the revoke request
type RevokeRequest struct {
	Token         string `form:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint"`
}

// Revoke handles the token revocation endpoint
// POST /oauth/revoke
func (h *OAuthHandler) Revoke(c *gin.Context) {
	var req RevokeRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	if err := h.oauthService.RevokeToken(req.Token, req.TokenTypeHint); err != nil {
		audit.Log(audit.ActionTokenRevoke, audit.ResultFailure, "client", "unknown", c.ClientIP(), "hint", req.TokenTypeHint)
		// Per RFC 7009, we should return 200 even if token is invalid
		c.JSON(http.StatusOK, gin.H{})
		return
	}

	audit.Log(audit.ActionTokenRevoke, audit.ResultSuccess, "client", "token_holder", c.ClientIP(), "hint", req.TokenTypeHint)
	c.JSON(http.StatusOK, gin.H{})
}

/*
 * UserInfo OIDC UserInfo 端点 (RFC 7662)
 * 功能：根据 access_token 的授权 scope 返回对应的用户信息
 *   - openid: sub (必须)
 *   - profile: name, family_name, given_name, nickname, preferred_username, picture, gender, birthdate, zoneinfo, locale, website, updated_at
 *   - email: email, email_verified
 *   - phone: phone_number, phone_number_verified
 *   - address: address
 * GET /oauth/userinfo
 */
func (h *OAuthHandler) UserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Missing access token",
		})
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	user, scope, err := h.oauthService.GetUserInfoWithScope(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Invalid or expired token",
		})
		return
	}

	/* 解析 scope 为 set，便于快速查找 */
	scopeSet := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		scopeSet[s] = true
	}

	/* sub 是必须返回的 (openid scope) */
	response := gin.H{
		"sub": user.ID.String(),
	}

	/* profile scope: 基本个人资料（始终返回所有标准声明，空值也返回） */
	hasProfile := scopeSet["profile"] || scopeSet["openid"]
	if hasProfile {
		response["name"] = user.GetFullName()
		response["preferred_username"] = user.Username
		response["nickname"] = user.Nickname
		response["given_name"] = user.GivenName
		response["family_name"] = user.FamilyName
		response["picture"] = user.Avatar
		response["gender"] = user.Gender
		response["locale"] = user.Locale
		response["zoneinfo"] = user.Zoneinfo
		response["website"] = user.Website
		response["bio"] = user.Bio
		response["updated_at"] = user.UpdatedAt.Unix()
		response["profile_completed"] = user.ProfileCompleted
		if user.Birthdate != nil {
			response["birthdate"] = user.Birthdate.Format("2006-01-02")
		} else {
			response["birthdate"] = ""
		}
		/* 扩展字段 */
		if user.Department != "" {
			response["department"] = user.Department
		}
		if user.JobTitle != "" {
			response["job_title"] = user.JobTitle
		}
		if user.Company != "" {
			response["company"] = user.Company
		}
		socialAccounts := user.GetSocialAccounts()
		if len(socialAccounts) > 0 {
			response["social_accounts"] = socialAccounts
		}
	}

	/* email scope */
	if scopeSet["email"] || scopeSet["openid"] {
		response["email"] = user.Email
		response["email_verified"] = user.EmailVerified
	}

	/* phone scope（始终返回声明，空值也返回） */
	if scopeSet["phone"] {
		response["phone_number"] = user.PhoneNumber
		response["phone_number_verified"] = user.PhoneVerified
	}

	/* address scope（始终返回声明，空值也返回） */
	if scopeSet["address"] {
		response["address"] = user.GetAddress()
	}

	c.JSON(http.StatusOK, response)
}

func (h *OAuthHandler) redirectWithError(c *gin.Context, redirectURI, state, errorCode, errorDesc string) {
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errorCode,
			"error_description": errorDesc,
		})
		return
	}

	params := map[string]string{
		"error":             errorCode,
		"error_description": errorDesc,
	}
	if state != "" {
		params["state"] = state
	}

	c.Redirect(http.StatusFound, h.buildRedirectURL(redirectURI, params))
}

/*
 * buildRedirectURL 构建 OAuth2 重定向 URL
 * 功能：将参数追加到 redirect_uri 的查询字符串中
 * 安全：验证 URL scheme 仅允许 http/https 和自定义协议（移动端），阻止 javascript: 伪协议
 */
func (h *OAuthHandler) buildRedirectURL(baseURL string, params map[string]string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}

	/* 阻止 javascript:、data: 等危险协议的开放重定向攻击 */
	scheme := strings.ToLower(u.Scheme)
	if scheme == "javascript" || scheme == "data" || scheme == "vbscript" {
		return ""
	}

	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()

	return u.String()
}

func (h *OAuthHandler) handleAuthError(c *gin.Context, redirectURI, state string, err error) {
	var errorCode, errorDesc string

	switch {
	case errors.Is(err, service.ErrInvalidClient):
		errorCode = "invalid_client"
		errorDesc = "Unknown client"
	case errors.Is(err, service.ErrInvalidRedirectURI):
		errorCode = "invalid_request"
		errorDesc = "Invalid redirect URI"
	case errors.Is(err, service.ErrInvalidScope):
		errorCode = "invalid_scope"
		errorDesc = "Invalid scope"
	default:
		/* PKCE / 自定义错误：直接使用错误消息作为描述 */
		errorCode = "invalid_request"
		errorDesc = err.Error()
	}

	h.redirectWithError(c, redirectURI, state, errorCode, errorDesc)
}

func (h *OAuthHandler) handleTokenError(c *gin.Context, err error) {
	var errorCode string
	var status int

	switch {
	case errors.Is(err, service.ErrInvalidClient):
		errorCode = "invalid_client"
		status = http.StatusUnauthorized
	case errors.Is(err, service.ErrInvalidGrant):
		errorCode = "invalid_grant"
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrAuthCodeExpired):
		errorCode = "invalid_grant"
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrAuthCodeUsed):
		errorCode = "invalid_grant"
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrInvalidCodeVerifier):
		errorCode = "invalid_grant"
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrTokenRevoked):
		errorCode = "invalid_grant"
		status = http.StatusBadRequest
	// Device flow specific errors (RFC 8628)
	case errors.Is(err, service.ErrAuthorizationPending):
		errorCode = "authorization_pending"
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrSlowDown):
		errorCode = "slow_down"
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrAccessDenied):
		errorCode = "access_denied"
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrExpiredToken):
		errorCode = "expired_token"
		status = http.StatusBadRequest
	default:
		errorCode = "server_error"
		status = http.StatusInternalServerError
	}

	/* 服务端内部错误不暴露原始错误信息，防止信息泄露 */
	desc := err.Error()
	if status == http.StatusInternalServerError {
		desc = "An internal error occurred"
	}
	c.JSON(status, gin.H{
		"error":             errorCode,
		"error_description": desc,
	})
}

// Introspect handles token introspection (RFC 7662)
// POST /oauth/introspect
func (h *OAuthHandler) Introspect(c *gin.Context) {
	// 获取token
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	// 验证客户端凭据（可选但推荐）
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	// 如果没有通过表单传递，尝试Basic Auth
	if clientID == "" {
		clientID, clientSecret, _ = c.Request.BasicAuth()
	}

	// 获取token类型提示
	tokenTypeHint := c.PostForm("token_type_hint") // access_token 或 refresh_token

	// 调用服务验证token
	tokenInfo, err := h.oauthService.IntrospectToken(token, clientID, clientSecret, tokenTypeHint)

	/* RFC 7662: Introspect 响应禁止缓存 */
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	if err != nil {
		audit.Log(audit.ActionTokenRevoke, audit.ResultFailure, clientID, "introspect", c.ClientIP(), "hint", tokenTypeHint, "active", "false")
		// 根据RFC 7662，无效token返回 active: false，不是错误
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	audit.Log(audit.ActionTokenIssue, audit.ResultSuccess, clientID, "introspect", c.ClientIP(), "hint", tokenTypeHint, "active", "true")
	c.JSON(http.StatusOK, tokenInfo)
}
