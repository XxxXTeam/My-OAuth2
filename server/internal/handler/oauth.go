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
	serverBase     string // 本服务对外根 URL（用于判断是否嵌入 SPA）
}

/*
 * NewOAuthHandler 创建 OAuth2 处理器实例
 * @param oauthService   - OAuth2 服务
 * @param webhookService - Webhook 服务
 * @param frontendURL    - 前端 URL（用于授权重定向）
 */
func NewOAuthHandler(oauthService *service.OAuthService, webhookService *service.WebhookService, frontendURL, serverBase string) *OAuthHandler {
	return &OAuthHandler{
		oauthService:   oauthService,
		webhookService: webhookService,
		frontendURL:    strings.TrimRight(strings.TrimSpace(frontendURL), "/"),
		serverBase:     BrowserReachableBaseURL(serverBase),
	}
}

/* AuthorizeRequest OAuth2 授权请求参数，支持 PKCE */
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" binding:"required"`
	ClientID            string `form:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" binding:"required"`
	Scope               string `form:"scope"`
	State               string `form:"state"`
	Nonce               string `form:"nonce"`
	MaxAge              string `form:"max_age"`
	Prompt              string `form:"prompt"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
}

/*
 * Authorize OAuth2 授权端点
 * @route GET /oauth/authorize
 * 功能：重定向到前端授权页面，携带所有授权参数
 */
func (h *OAuthHandler) Authorize(c *gin.Context) {
	if !h.shouldRedirectAuthorizeToExternalUI(c) {
		c.Set("serve_spa", true)
		c.Next()
		return
	}
	frontendAuthURL := h.frontendURL + "/oauth/authorize?" + c.Request.URL.RawQuery
	c.Redirect(http.StatusFound, frontendAuthURL)
}

// IsEmbeddedFrontend 授权页由本进程嵌入 SPA 提供（无需 302 到外部前端）
func (h *OAuthHandler) IsEmbeddedFrontend() bool {
	return !h.shouldRedirectAuthorizeToExternalUI(nil)
}

func (h *OAuthHandler) shouldRedirectAuthorizeToExternalUI(c *gin.Context) bool {
	if h.frontendURL == "" {
		return false
	}
	if SamePublicOrigin(h.frontendURL, h.serverBase) {
		return false
	}
	if c != nil && c.Request != nil {
		reqBase := BrowserReachableBaseURL(requestScheme(c.Request) + "://" + requestHost(c.Request))
		if SamePublicOrigin(h.frontendURL, reqBase) {
			return false
		}
	}
	return true
}

func oidcPromptHasNone(prompt string) bool {
	for _, value := range strings.Fields(prompt) {
		if value == "none" {
			return true
		}
	}
	return false
}

func oidcIssuerFromRequest(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}
	host := requestHost(c.Request)
	if host == "" {
		return ""
	}
	return requestScheme(c.Request) + "://" + host
}

func (h *OAuthHandler) oidcPromptErrorResponse(c *gin.Context, redirectURI, state, prompt, errorCode, errorDescription string) bool {
	if !oidcPromptHasNone(prompt) {
		return false
	}
	redirectURL := h.buildRedirectURL(redirectURI, map[string]string{
		"error":             errorCode,
		"error_description": errorDescription,
		"state":             state,
	})
	Success(c, gin.H{"redirect_url": redirectURL})
	return true
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
	if redirectURI != "" && !app.ValidateRedirectURI(redirectURI) {
		BadRequest(c, "Invalid redirect_uri")
		return
	}

	requestedScope := c.Query("scope")
	responseType := c.Query("response_type")
	scopeBreakdown := app.ParseAuthorizeScopeRequest(requestedScope)
	issuedTypes := app.GetIssuedTokenTypesForRequest(scopeBreakdown.EffectiveScope, responseType)
	Success(c, gin.H{
		"app": gin.H{
			"id":                         app.ID.String(),
			"client_id":                  app.ClientID,
			"name":                       app.Name,
			"description":                app.Description,
			"scopes":                     app.GetUserAuthorizationScopes(),
			"allowed_scopes":             app.GetAllowedScopes(),
			"grant_types":                app.GetGrantTypes(),
			"post_logout_redirect_uris":  app.GetPostLogoutRedirectURIs(),
			"response_types_supported":   app.GetResponseTypesSupported(),
			"app_type":                   app.AppType,
			"token_endpoint_auth_method": app.TokenEndpointAuthMethod,
			"issued_token_types":         issuedTypes,
		},
		"requested_scopes":   scopeBreakdown.DisplayScopes,
		"invalid_scopes":     scopeBreakdown.InvalidScopes,
		"effective_scope":    scopeBreakdown.EffectiveScope,
		"has_openid":         scopeBreakdown.HasOpenID,
		"issued_token_types": issuedTypes,
	})
}

// GetAuthorizePending 若存在未兑换的授权码则返回 redirect_url（避免重复授权）
// GET /api/oauth/authorize/pending
func (h *OAuthHandler) GetAuthorizePending(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	if clientID == "" || redirectURI == "" {
		BadRequest(c, "client_id and redirect_uri are required")
		return
	}
	userID, ok := gctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}
	authTime, _ := gctx.GetAuthTime(c)
	authMethods, _ := gctx.GetAuthMethods(c)
	result, err := h.oauthService.FindPendingAuthorization(&service.AuthorizeInput{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		Scope:         c.Query("scope"),
		State:         c.Query("state"),
		Nonce:         c.Query("nonce"),
		MaxAge:        c.Query("max_age"),
		Prompt:        c.Query("prompt"),
		AuthTime:      authTime,
		AMR:           authMethods,
		CodeChallenge: c.Query("code_challenge"),
		UserID:        userID,
	})
	if err != nil {
		if errors.Is(err, service.ErrLoginRequired) {
			if h.oidcPromptErrorResponse(c, redirectURI, c.Query("state"), c.Query("prompt"), "login_required", "End-user authentication is required") {
				return
			}
			Success(c, gin.H{"pending": false, "login_required": true})
			return
		}
		if errors.Is(err, service.ErrConsentRequired) {
			if h.oidcPromptErrorResponse(c, redirectURI, c.Query("state"), c.Query("prompt"), "consent_required", "End-user consent is required") {
				return
			}
			Success(c, gin.H{"pending": false})
			return
		}
		Success(c, gin.H{"pending": false})
		return
	}
	redirectURL := h.buildRedirectURL(result.RedirectURI, map[string]string{
		"code":  result.Code,
		"state": result.State,
	})
	Success(c, gin.H{
		"pending":      true,
		"redirect_url": redirectURL,
		"reused":       true,
	})
}

// AuthorizeSubmitRequest represents the authorization submission request
type AuthorizeSubmitRequest struct {
	ClientID            string `json:"client_id" binding:"required"`
	RedirectURI         string `json:"redirect_uri" binding:"required"`
	ResponseType        string `json:"response_type" binding:"required"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	MaxAge              string `json:"max_age"`
	Prompt              string `json:"prompt"`
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
	authTime, _ := gctx.GetAuthTime(c)
	authMethods, _ := gctx.GetAuthMethods(c)

	// Get application info
	app, err := h.oauthService.GetApplication(req.ClientID)
	if err != nil {
		NotFound(c, "Application not found")
		return
	}

	if !app.ValidateRedirectURI(req.RedirectURI) {
		BadRequest(c, service.ErrInvalidRedirectURI.Error())
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
		Nonce:               req.Nonce,
		MaxAge:              req.MaxAge,
		Prompt:              req.Prompt,
		AuthTime:            authTime,
		AMR:                 authMethods,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		UserID:              userID,
	})
	if err != nil {
		if errors.Is(err, service.ErrLoginRequired) {
			if h.oidcPromptErrorResponse(c, req.RedirectURI, req.State, req.Prompt, "login_required", "End-user authentication is required") {
				return
			}
			Success(c, gin.H{"login_required": true})
			return
		}
		if errors.Is(err, service.ErrConsentRequired) {
			if h.oidcPromptErrorResponse(c, req.RedirectURI, req.State, req.Prompt, "consent_required", "End-user consent is required") {
				return
			}
			BadRequest(c, err.Error())
			return
		}
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

	username, _ := gctx.GetUserUsername(c)
	email, _ := gctx.GetUserEmail(c)

	if !result.Reused {
		emitOAuthAuthorizedSSE(app, userID.String(), username, email, req.Scope)
		if h.webhookService != nil {
			go h.webhookService.TriggerEvent(context.Background(), app.ID, model.WebhookEventOAuthAuthorized, map[string]any{
				"user_id":   userID.String(),
				"username":  username,
				"client_id": app.ClientID,
				"app_name":  app.Name,
				"scope":     req.Scope,
			})
		}
		audit.Log(audit.ActionTokenIssue, audit.ResultSuccess, userID.String(), req.ClientID, c.ClientIP(), "event", "authorize_approved", "scope", req.Scope)
	}

	redirectURL := h.buildRedirectURL(result.RedirectURI, map[string]string{
		"code":  result.Code,
		"state": result.State,
	})

	scopes := strings.Fields(req.Scope)
	Success(c, gin.H{
		"redirect_url": redirectURL,
		"code":         result.Code,
		"state":        result.State,
		"reused":       result.Reused,
		"authorization": gin.H{
			"scope":              req.Scope,
			"scopes":             scopes,
			"issued_token_types": app.GetIssuedTokenTypesForRequest(req.Scope, req.ResponseType),
			"user": gin.H{
				"id":       userID.String(),
				"username": username,
				"email":    email,
			},
			"app": gin.H{
				"id":        app.ID.String(),
				"client_id": app.ClientID,
				"name":      app.Name,
			},
		},
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
	setNoStoreHeaders := func() {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
	}

	var req TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		setNoStoreHeaders()
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Try to get client credentials from Authorization header
	clientID, clientSecret, hasBasicAuth := c.Request.BasicAuth()
	if hasBasicAuth && (req.ClientID != "" || req.ClientSecret != "") {
		setNoStoreHeaders()
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "multiple client authentication methods are not allowed",
		})
		return
	}
	if hasBasicAuth {
		req.ClientID = clientID
		req.ClientSecret = clientSecret
	}

	result, err := h.oauthService.Token(&service.TokenInput{
		GrantType:          req.GrantType,
		Code:               req.Code,
		RedirectURI:        req.RedirectURI,
		ClientID:           req.ClientID,
		ClientSecret:       req.ClientSecret,
		RefreshToken:       req.RefreshToken,
		Issuer:             oidcIssuerFromRequest(c),
		IPAddress:          c.ClientIP(),
		UserAgent:          c.Request.UserAgent(),
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
		setNoStoreHeaders()
		if errors.Is(err, service.ErrInvalidClient) && c.GetHeader("Authorization") != "" {
			c.Header("WWW-Authenticate", `Basic realm="oauth"`)
		}
		h.handleTokenError(c, err)
		return
	}

	// Trigger webhook + SSE for token issued event
	if req.ClientID != "" {
		app, _ := h.oauthService.GetApplication(req.ClientID)
		if app != nil {
			emitOAuthTokenSSE(h.oauthService, app, req.GrantType, result.AccessToken, result.Scope)

			if h.webhookService != nil {
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
	}

	/* 审计日志：记录 token 签发 */
	actorID := req.ClientID
	if uid, ok := gctx.GetUserID(c); ok {
		actorID = uid.String()
	}
	audit.Log(audit.ActionTokenIssue, audit.ResultSuccess, actorID, req.ClientID, c.ClientIP(), "grant_type", req.GrantType)

	/* RFC 6749 Section 5.1: Token 响应必须包含 Cache-Control 和 Pragma 头 */
	setNoStoreHeaders()
	c.JSON(http.StatusOK, result)
}

// RevokeRequest represents the revoke request
type RevokeRequest struct {
	Token         string `form:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint"`
	ClientID      string `form:"client_id"`
	ClientSecret  string `form:"client_secret"`
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

	formCredentials := req.ClientID != "" || req.ClientSecret != ""
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	hasBasicAuth := strings.HasPrefix(strings.ToLower(authHeader), "basic ")
	if formCredentials && hasBasicAuth {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	usedBasicAuth := false
	if hasBasicAuth {
		clientID, clientSecret, ok := c.Request.BasicAuth()
		if !ok || clientID == "" {
			c.Header("WWW-Authenticate", "Basic")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
		req.ClientID = clientID
		req.ClientSecret = clientSecret
		usedBasicAuth = true
	}

	if err := h.oauthService.RevokeTokenForClient(req.Token, req.TokenTypeHint, req.ClientID, req.ClientSecret); err != nil {
		audit.Log(audit.ActionTokenRevoke, audit.ResultFailure, "client", req.ClientID, c.ClientIP(), "hint", req.TokenTypeHint)
		if errors.Is(err, service.ErrInvalidClient) {
			if usedBasicAuth {
				c.Header("WWW-Authenticate", "Basic")
			}
			h.handleTokenError(c, err)
			return
		}
		// Per RFC 7009, return 200 for invalid or unknown token values.
		c.JSON(http.StatusOK, gin.H{})
		return
	}

	audit.Log(audit.ActionTokenRevoke, audit.ResultSuccess, "client", req.ClientID, c.ClientIP(), "hint", req.TokenTypeHint)
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
 *   - groups: groups（用户所属组/角色）
 * GET /oauth/userinfo
 */
func (h *OAuthHandler) UserInfo(c *gin.Context) {
	writeBearerError := func(status int, errCode, description string) {
		challenge := fmt.Sprintf(`Bearer error="%s", error_description="%s"`, errCode, description)
		if errCode == "insufficient_scope" {
			challenge += `, scope="openid"`
		}
		c.Header("WWW-Authenticate", challenge)
		c.JSON(status, gin.H{
			"error":             errCode,
			"error_description": description,
		})
	}

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		writeBearerError(http.StatusUnauthorized, "invalid_token", "Missing access token")
		return
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeBearerError(http.StatusUnauthorized, "invalid_token", "Authorization header must use Bearer scheme")
		return
	}

	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if token == "" {
		writeBearerError(http.StatusUnauthorized, "invalid_token", "Missing access token")
		return
	}

	user, scope, err := h.oauthService.GetUserInfoWithScope(token)
	if err != nil {
		if errors.Is(err, service.ErrNoUserInToken) || errors.Is(err, service.ErrInvalidScope) {
			writeBearerError(http.StatusForbidden, "insufficient_scope", "This access token is not authorized for the UserInfo endpoint")
			return
		}
		writeBearerError(http.StatusUnauthorized, "invalid_token", "Invalid or expired token")
		return
	}
	if user == nil {
		writeBearerError(http.StatusForbidden, "insufficient_scope", "This access token does not represent an end-user")
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
	hasProfile := scopeSet["profile"]
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
	if scopeSet["email"] {
		response["email"] = user.Email
		response["email_verified"] = user.EmailVerified
	}

	/* phone scope */
	if scopeSet["phone"] {
		response["phone_number"] = user.PhoneNumber
		response["phone_number_verified"] = user.PhoneVerified
	}

	/* address scope */
	if scopeSet["address"] {
		response["address"] = user.GetAddress()
	}

	/* groups scope: 返回用户所属组/角色，来源于 User.Role（admin/user） */
	if scopeSet["groups"] {
		response["groups"] = []string{string(user.Role)}
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
	case errors.Is(err, service.ErrInvalidRedirectURI):
		errorCode = "invalid_grant"
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrUnsupportedGrantType):
		errorCode = "unsupported_grant_type"
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrInvalidRequest):
		errorCode = "invalid_request"
		status = http.StatusBadRequest
	case errors.Is(err, service.ErrInvalidTarget):
		errorCode = "invalid_target"
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
	case errors.Is(err, service.ErrInvalidScope):
		errorCode = "invalid_scope"
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
	/* RFC 7662: Introspect 响应禁止缓存 */
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	// 获取token
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	// 验证客户端凭据
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	formCredentials := clientID != "" || clientSecret != ""
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	hasBasicAuth := strings.HasPrefix(strings.ToLower(authHeader), "basic ")

	if formCredentials && hasBasicAuth {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	usedBasicAuth := false
	if hasBasicAuth {
		basicClientID, basicClientSecret, ok := c.Request.BasicAuth()
		if !ok || basicClientID == "" {
			c.Header("WWW-Authenticate", "Basic")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
		clientID = basicClientID
		clientSecret = basicClientSecret
		usedBasicAuth = true
	}

	// 获取token类型提示
	tokenTypeHint := c.PostForm("token_type_hint") // access_token 或 refresh_token

	// 调用服务验证token
	tokenInfo, err := h.oauthService.IntrospectToken(token, clientID, clientSecret, tokenTypeHint)

	if err != nil {
		audit.Log(audit.ActionTokenRevoke, audit.ResultFailure, clientID, "introspect", c.ClientIP(), "hint", tokenTypeHint, "active", "false")
		if errors.Is(err, service.ErrInvalidClient) {
			if usedBasicAuth {
				c.Header("WWW-Authenticate", "Basic")
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
		// 根据RFC 7662，无效token返回 active: false，不是错误
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	active := "false"
	if isActive, ok := tokenInfo["active"].(bool); ok && isActive {
		active = "true"
	}
	audit.Log(audit.ActionTokenIssue, audit.ResultSuccess, clientID, "introspect", c.ClientIP(), "hint", tokenTypeHint, "active", active)
	c.JSON(http.StatusOK, tokenInfo)
}
