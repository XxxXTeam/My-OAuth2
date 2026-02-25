package service

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"

	"github.com/google/uuid"
)

/* OAuth2 服务层错误定义 */
var (
	ErrInvalidClient       = errors.New("invalid client")
	ErrInvalidRedirectURI  = errors.New("invalid redirect uri")
	ErrInvalidGrant        = errors.New("invalid grant")
	ErrInvalidScope        = errors.New("invalid scope")
	ErrAuthCodeExpired     = errors.New("authorization code expired")
	ErrAuthCodeUsed        = errors.New("authorization code already used")
	ErrInvalidCodeVerifier = errors.New("invalid code verifier")
	ErrTokenExpired        = errors.New("token expired")
	ErrTokenRevoked        = errors.New("token revoked")
)

/*
 * OAuthService OAuth2 核心服务
 * 功能：实现 OAuth2 授权码流程、Token 签发/刷新/撤销、PKCE 校验、
 *       Client Credentials 授权、Device Flow、Token Introspection 等
 */
type OAuthService struct {
	appRepo      *repository.ApplicationRepository
	oauthRepo    *repository.OAuthRepository
	userRepo     *repository.UserRepository
	userAuthRepo *repository.UserAuthorizationRepository
	deviceRepo   *repository.DeviceCodeRepository
	config       *config.Config
}

/*
 * NewOAuthService 创建 OAuth2 服务实例
 * @param appRepo      - 应用仓储
 * @param oauthRepo    - OAuth 令牌仓储
 * @param userRepo     - 用户仓储
 * @param userAuthRepo - 用户授权仓储
 * @param cfg          - 系统配置
 */
func NewOAuthService(
	appRepo *repository.ApplicationRepository,
	oauthRepo *repository.OAuthRepository,
	userRepo *repository.UserRepository,
	userAuthRepo *repository.UserAuthorizationRepository,
	cfg *config.Config,
) *OAuthService {
	return &OAuthService{
		appRepo:      appRepo,
		oauthRepo:    oauthRepo,
		userRepo:     userRepo,
		userAuthRepo: userAuthRepo,
		config:       cfg,
	}
}

/* SetDeviceCodeRepository 注入设备码仓储（可选依赖，启用 Device Flow） */
func (s *OAuthService) SetDeviceCodeRepository(repo *repository.DeviceCodeRepository) {
	s.deviceRepo = repo
}

/* AuthorizeInput OAuth2 授权请求参数，支持 PKCE */
type AuthorizeInput struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              uuid.UUID
}

/* AuthorizeResult OAuth2 授权结果，包含授权码和重定向信息 */
type AuthorizeResult struct {
	Code        string
	RedirectURI string
	State       string
}

/*
 * Authorize 创建授权码
 * 功能：校验客户端、回调地址、scope，生成授权码，记录用户授权
 *       支持 PKCE (code_challenge / code_challenge_method)
 * @param input - 授权请求参数
 * @return *AuthorizeResult - 授权码和重定向信息
 */
func (s *OAuthService) Authorize(input *AuthorizeInput) (*AuthorizeResult, error) {
	// Validate client
	app, err := s.appRepo.FindByClientID(input.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	// Validate redirect URI
	if !app.ValidateRedirectURI(input.RedirectURI) {
		return nil, ErrInvalidRedirectURI
	}

	/*
	 * PKCE 强制策略 (RFC 7636)：
	 *   - 公开客户端（SPA/移动端）必须使用 PKCE
	 *   - 机密客户端推荐但不强制
	 *   - code_challenge_method 仅接受 S256（禁用 plain）
	 */
	if app.AppType == model.AppTypePublic {
		if input.CodeChallenge == "" {
			return nil, errors.New("PKCE code_challenge is required for public clients")
		}
	}
	if input.CodeChallenge != "" {
		if input.CodeChallengeMethod == "" {
			input.CodeChallengeMethod = "S256"
		}
		if input.CodeChallengeMethod != "S256" {
			return nil, errors.New("only S256 code_challenge_method is supported")
		}
	}

	// Create authorization code
	authCode := &model.AuthorizationCode{
		ClientID:            input.ClientID,
		UserID:              input.UserID,
		RedirectURI:         input.RedirectURI,
		Scope:               input.Scope,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(s.config.OAuth.AuthCodeTTL),
	}

	if err := s.oauthRepo.CreateAuthorizationCode(authCode); err != nil {
		return nil, err
	}

	// Record user authorization for the app
	if s.userAuthRepo != nil {
		s.userAuthRepo.CreateOrUpdate(input.UserID, app.ID, input.Scope, "authorization_code")
	}

	return &AuthorizeResult{
		Code:        authCode.Code,
		RedirectURI: input.RedirectURI,
		State:       input.State,
	}, nil
}

/*
 * TokenInput OAuth2 Token 请求参数
 * 功能：统一封装所有 grant_type 的请求参数
 *       支持 authorization_code、refresh_token、client_credentials、device_code、token-exchange
 */
type TokenInput struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
	CodeVerifier string
	Scope        string // For client_credentials grant
	DeviceCode   string // For device_code grant
	// Token Exchange (RFC 8693)
	SubjectToken       string // The token to exchange
	SubjectTokenType   string // urn:ietf:params:oauth:token-type:access_token, etc.
	ActorToken         string // Optional actor token for delegation
	ActorTokenType     string // Type of actor token
	RequestedTokenType string // Requested token type
	Audience           string // Target audience for the new token
	Resource           string // Target resource
}

/* TokenResult OAuth2 Token 响应结构 */
type TokenResult struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

/*
 * Token 根据 grant_type 签发或刷新令牌
 * 功能：路由到对应的 grant 处理函数
 *       支持: authorization_code, refresh_token, client_credentials, device_code, token-exchange
 * @param input - Token 请求参数
 * @return *TokenResult - 令牌响应
 */
func (s *OAuthService) Token(input *TokenInput) (*TokenResult, error) {
	switch input.GrantType {
	case "authorization_code":
		return s.exchangeAuthorizationCode(input)
	case "refresh_token":
		return s.refreshAccessToken(input)
	case "client_credentials":
		return s.clientCredentials(input)
	case "urn:ietf:params:oauth:grant-type:device_code", "device_code":
		return s.deviceCodeGrant(input)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		return s.tokenExchange(input)
	default:
		return nil, ErrInvalidGrant
	}
}

/*
 * exchangeAuthorizationCode 授权码换取令牌
 * 功能：校验授权码、客户端、回调地址、PKCE，签发 access_token + refresh_token
 * @param input - Token 请求参数
 */
func (s *OAuthService) exchangeAuthorizationCode(input *TokenInput) (*TokenResult, error) {
	// Find authorization code
	authCode, err := s.oauthRepo.FindAuthorizationCode(input.Code)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	// Check if code is expired
	if authCode.IsExpired() {
		return nil, ErrAuthCodeExpired
	}

	// Check if code is already used
	if authCode.Used {
		return nil, ErrAuthCodeUsed
	}

	// Validate client
	app, err := s.appRepo.FindByClientID(input.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	/*
	 * 客户端认证策略：
	 *   - 机密客户端（confidential/machine）必须提供有效的 client_secret
	 *   - 公开客户端（public）不需要 client_secret，但必须使用 PKCE
	 */
	if app.AppType == model.AppTypeConfidential || app.AppType == model.AppTypeMachine {
		if input.ClientSecret == "" || subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(input.ClientSecret)) != 1 {
			return nil, ErrInvalidClient
		}
	} else if input.ClientSecret != "" {
		/* 公开客户端也提供了 secret，仍然校验 */
		if subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(input.ClientSecret)) != 1 {
			return nil, ErrInvalidClient
		}
	}

	// Validate redirect URI
	if authCode.RedirectURI != input.RedirectURI {
		return nil, ErrInvalidRedirectURI
	}

	// Validate PKCE code verifier
	if authCode.CodeChallenge != "" {
		if !s.validateCodeVerifier(input.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, ErrInvalidCodeVerifier
		}
	}

	// Mark authorization code as used
	if err := s.oauthRepo.MarkAuthorizationCodeUsed(input.Code); err != nil {
		return nil, err
	}

	// Create access token
	accessToken := &model.AccessToken{
		ClientID:  input.ClientID,
		UserID:    &authCode.UserID,
		Scope:     authCode.Scope,
		ExpiresAt: time.Now().Add(s.config.OAuth.AccessTokenTTL),
	}

	if err := s.oauthRepo.CreateAccessToken(accessToken); err != nil {
		return nil, err
	}

	// Create refresh token
	refreshToken := &model.RefreshToken{
		AccessTokenID: &accessToken.ID,
		ExpiresAt:     time.Now().Add(s.config.OAuth.RefreshTokenTTL),
	}

	if err := s.oauthRepo.CreateRefreshToken(refreshToken); err != nil {
		return nil, err
	}

	return &TokenResult{
		AccessToken:  accessToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.OAuth.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken.Token,
		Scope:        authCode.Scope,
	}, nil
}

/*
 * refreshAccessToken 使用 refresh_token 刷新令牌
 * 功能：撤销旧令牌对，签发新的 access_token + refresh_token
 * @param input - Token 请求参数
 */
func (s *OAuthService) refreshAccessToken(input *TokenInput) (*TokenResult, error) {
	// Find refresh token
	refreshToken, err := s.oauthRepo.FindRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	/*
	 * Refresh Token 重放检测 (Token Rotation Security)
	 * 如果一个已被撤销的 refresh_token 再次被使用，说明可能发生了令牌泄露：
	 *   - 攻击者和合法用户都持有同一个 refresh_token
	 *   - 合法用户先刷新（旧 token 被撤销），攻击者再使用旧 token
	 * 安全措施：撤销该 refresh_token 关联的所有令牌（整个 token family）
	 */
	if refreshToken.Revoked {
		if refreshToken.AccessTokenID != nil {
			if at, atErr := s.oauthRepo.FindAccessTokenByID(*refreshToken.AccessTokenID); atErr == nil {
				/* 撤销 family：同一 client + user 的所有未过期令牌 */
				s.oauthRepo.RevokeAccessToken(at.Token)
				s.oauthRepo.RevokeRefreshTokenByAccessTokenID(at.ID)
			}
		}
		return nil, ErrTokenRevoked
	}

	// Check if token is valid (expired check)
	if !refreshToken.IsValid() {
		return nil, ErrTokenRevoked
	}

	// Get the old access token to get user info
	if refreshToken.AccessTokenID == nil {
		return nil, ErrInvalidGrant
	}
	oldAccessToken, err := s.oauthRepo.FindAccessTokenByID(*refreshToken.AccessTokenID)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	/* 检查用户对该应用的授权是否已被撤销 */
	if oldAccessToken.UserID != nil && s.userAuthRepo != nil {
		app, appErr := s.appRepo.FindByClientID(oldAccessToken.ClientID)
		if appErr == nil {
			auth, authErr := s.userAuthRepo.FindByUserAndApp(*oldAccessToken.UserID, app.ID)
			if authErr != nil || !auth.IsValid() {
				/* 授权已撤销或不存在，拒绝刷新 */
				s.oauthRepo.RevokeRefreshToken(input.RefreshToken)
				return nil, ErrAccessDenied
			}
		}
	}

	// Revoke old tokens
	s.oauthRepo.RevokeAccessToken(oldAccessToken.Token)
	s.oauthRepo.RevokeRefreshToken(input.RefreshToken)

	// Create new access token
	accessToken := &model.AccessToken{
		ClientID:  oldAccessToken.ClientID,
		UserID:    oldAccessToken.UserID,
		Scope:     oldAccessToken.Scope,
		ExpiresAt: time.Now().Add(s.config.OAuth.AccessTokenTTL),
	}

	if err := s.oauthRepo.CreateAccessToken(accessToken); err != nil {
		return nil, err
	}

	// Create new refresh token
	newRefreshToken := &model.RefreshToken{
		AccessTokenID: &accessToken.ID,
		ExpiresAt:     time.Now().Add(s.config.OAuth.RefreshTokenTTL),
	}

	if err := s.oauthRepo.CreateRefreshToken(newRefreshToken); err != nil {
		return nil, err
	}

	return &TokenResult{
		AccessToken:  accessToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.OAuth.AccessTokenTTL.Seconds()),
		RefreshToken: newRefreshToken.Token,
		Scope:        oldAccessToken.Scope,
	}, nil
}

/*
 * clientCredentials 客户端凭证授权 (RFC 6749 Section 4.4)
 * 功能：机器对机器认证，无用户上下文，验证 client_id/secret 后直接签发 access_token
 *       不签发 refresh_token（客户端可随时重新认证）
 * @param input - Token 请求参数
 */
func (s *OAuthService) clientCredentials(input *TokenInput) (*TokenResult, error) {
	// Validate client credentials
	app, err := s.appRepo.FindByClientID(input.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	/* 常量时间比较 client_secret，防止时序攻击 */
	if subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(input.ClientSecret)) != 1 {
		return nil, ErrInvalidClient
	}

	/* 仅 machine / confidential 类型应用允许 client_credentials 授权 */
	if app.AppType != model.AppTypeMachine && app.AppType != model.AppTypeConfidential {
		return nil, ErrInvalidGrant
	}

	// Check if client_credentials grant is allowed for this application
	if !app.SupportsGrantType("client_credentials") {
		return nil, ErrInvalidGrant
	}

	// Validate requested scope
	if !app.ValidateScope(input.Scope) {
		return nil, ErrInvalidScope
	}

	// Determine the scope to use
	scope := input.Scope
	if scope == "" {
		// Use default allowed scopes if no scope requested
		allowedScopes := app.GetAllowedScopes()
		if len(allowedScopes) > 0 {
			scope = strings.Join(allowedScopes, " ")
		}
	}

	// Create access token (no user associated - UserID will be zero UUID)
	accessToken := &model.AccessToken{
		ClientID:  input.ClientID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(s.config.OAuth.AccessTokenTTL),
	}

	if err := s.oauthRepo.CreateAccessToken(accessToken); err != nil {
		return nil, err
	}

	// Client credentials grant typically does not issue refresh tokens
	// as the client can always re-authenticate with its credentials
	return &TokenResult{
		AccessToken: accessToken.Token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.config.OAuth.AccessTokenTTL.Seconds()),
		Scope:       scope,
	}, nil
}

/* Device Flow 错误定义 (RFC 8628) */
var (
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrSlowDown             = errors.New("slow_down")
	ErrAccessDenied         = errors.New("access_denied")
	ErrExpiredToken         = errors.New("expired_token")
)

/*
 * deviceCodeGrant 设备码授权 (RFC 8628)
 * 功能：设备轮询此端点直到用户在浏览器完成授权
 *       返回 authorization_pending / slow_down / access_denied / expired_token
 *       授权成功后签发 access_token + refresh_token 并删除设备码
 * @param input - Token 请求参数（需包含 DeviceCode）
 */
func (s *OAuthService) deviceCodeGrant(input *TokenInput) (*TokenResult, error) {
	if s.deviceRepo == nil {
		return nil, ErrInvalidGrant
	}

	if input.DeviceCode == "" {
		return nil, ErrInvalidGrant
	}

	// Find device code
	dc, err := s.deviceRepo.FindByDeviceCode(input.DeviceCode)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	// Validate client
	if dc.ClientID != input.ClientID {
		return nil, ErrInvalidClient
	}

	/* RFC 8628 Section 3.5: 强制执行轮询间隔，客户端过快轮询返回 slow_down */
	now := time.Now()
	if dc.LastPolledAt != nil {
		interval := time.Duration(dc.Interval) * time.Second
		if now.Sub(*dc.LastPolledAt) < interval {
			/* 记录本次轮询时间并增加 interval（slow_down 语义） */
			_ = s.deviceRepo.UpdateLastPolledAt(input.DeviceCode, now)
			return nil, ErrSlowDown
		}
	}
	_ = s.deviceRepo.UpdateLastPolledAt(input.DeviceCode, now)

	// Check if expired
	if dc.IsExpired() {
		return nil, ErrExpiredToken
	}

	// Check status
	switch dc.Status {
	case "pending":
		return nil, ErrAuthorizationPending
	case "denied":
		return nil, ErrAccessDenied
	case "authorized":
		// Continue to issue token
	default:
		return nil, ErrInvalidGrant
	}

	// Get user
	if dc.UserID == nil {
		return nil, ErrInvalidGrant
	}
	user, err := s.userRepo.FindByID(*dc.UserID)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	// Create access token
	accessToken := &model.AccessToken{
		ClientID:  input.ClientID,
		UserID:    &user.ID,
		Scope:     dc.Scope,
		ExpiresAt: time.Now().Add(s.config.OAuth.AccessTokenTTL),
	}

	if err := s.oauthRepo.CreateAccessToken(accessToken); err != nil {
		return nil, err
	}

	// Create refresh token
	refreshToken := &model.RefreshToken{
		AccessTokenID: &accessToken.ID,
		ExpiresAt:     time.Now().Add(s.config.OAuth.RefreshTokenTTL),
	}

	if err := s.oauthRepo.CreateRefreshToken(refreshToken); err != nil {
		return nil, err
	}

	// Delete the device code after successful token exchange
	s.deviceRepo.Delete(dc.ID)

	// Record user authorization
	if s.userAuthRepo != nil {
		app, _ := s.appRepo.FindByClientID(input.ClientID)
		if app != nil {
			s.userAuthRepo.CreateOrUpdate(user.ID, app.ID, dc.Scope, "device_code")
		}
	}

	return &TokenResult{
		AccessToken:  accessToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.OAuth.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken.Token,
		Scope:        dc.Scope,
	}, nil
}

/* Token 类型 URI 常量 (RFC 8693 Token Exchange) */
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
)

/* TokenExchangeResult Token Exchange 扩展响应结构 (RFC 8693) */
type TokenExchangeResult struct {
	TokenResult
	IssuedTokenType string `json:"issued_token_type"`
}

/*
 * tokenExchange Token 交换授权 (RFC 8693)
 * 功能：使用已有令牌换取新令牌，支持 access_token 和 refresh_token 类型交换
 *       可用于跨服务委托、令牌降权等场景
 * @param input - Token 请求参数（需包含 SubjectToken 和 SubjectTokenType）
 */
func (s *OAuthService) tokenExchange(input *TokenInput) (*TokenResult, error) {
	// Validate required parameters
	if input.SubjectToken == "" {
		return nil, errors.New("subject_token is required")
	}
	if input.SubjectTokenType == "" {
		input.SubjectTokenType = TokenTypeAccessToken // Default to access_token
	}

	/* 强制要求客户端认证（RFC 8693 安全要求） */
	if input.ClientID == "" {
		return nil, ErrInvalidClient
	}
	app, err := s.appRepo.FindByClientID(input.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	/* 机密客户端 / 机器客户端必须提供有效 secret */
	if app.AppType == model.AppTypeConfidential || app.AppType == model.AppTypeMachine {
		if input.ClientSecret == "" || subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(input.ClientSecret)) != 1 {
			return nil, ErrInvalidClient
		}
	} else if input.ClientSecret != "" {
		/* 公开客户端提供了 secret，也需要校验 */
		if subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(input.ClientSecret)) != 1 {
			return nil, ErrInvalidClient
		}
	}

	/* 检查 token-exchange 授权类型是否允许 */
	if !app.SupportsGrantType("urn:ietf:params:oauth:grant-type:token-exchange") && !app.SupportsGrantType("token-exchange") && !app.SupportsGrantType("token_exchange") {
		return nil, ErrInvalidGrant
	}

	// Validate subject token based on type
	var user *model.User
	var originalScope string

	switch input.SubjectTokenType {
	case TokenTypeAccessToken, "access_token":
		// Validate as access token
		u, accessToken, err := s.ValidateAccessToken(input.SubjectToken)
		if err != nil {
			return nil, ErrInvalidGrant
		}
		user = u
		originalScope = accessToken.Scope

	case TokenTypeRefreshToken, "refresh_token":
		// Validate as refresh token
		refreshToken, err := s.oauthRepo.FindRefreshToken(input.SubjectToken)
		if err != nil || !refreshToken.IsValid() {
			return nil, ErrInvalidGrant
		}
		if refreshToken.AccessTokenID == nil {
			return nil, ErrInvalidGrant
		}
		accessToken, err := s.oauthRepo.FindAccessTokenByID(*refreshToken.AccessTokenID)
		if err != nil {
			return nil, ErrInvalidGrant
		}
		if accessToken.UserID == nil {
			return nil, ErrInvalidGrant
		}
		user, err = s.userRepo.FindByID(*accessToken.UserID)
		if err != nil {
			return nil, ErrInvalidGrant
		}
		originalScope = accessToken.Scope

	default:
		return nil, errors.New("unsupported subject_token_type")
	}

	// Validate actor token if provided (delegation scenario)
	if input.ActorToken != "" {
		// For now, we just validate the actor token exists and is valid
		// More complex delegation logic can be added here
		switch input.ActorTokenType {
		case TokenTypeAccessToken, "access_token", "":
			_, _, err := s.ValidateAccessToken(input.ActorToken)
			if err != nil {
				return nil, errors.New("invalid actor_token")
			}
		default:
			return nil, errors.New("unsupported actor_token_type")
		}
	}

	// Determine scope for new token
	scope := input.Scope
	if scope == "" {
		scope = originalScope
	} else {
		// Validate requested scope is subset of original scope
		// For now, we allow any scope that was in the original token
		// More strict validation can be added here
	}

	// Determine the issued token type
	requestedType := input.RequestedTokenType
	if requestedType == "" {
		requestedType = TokenTypeAccessToken
	}

	// Create new access token
	newAccessToken := &model.AccessToken{
		ClientID:  input.ClientID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(s.config.OAuth.AccessTokenTTL),
	}
	if user != nil {
		newAccessToken.UserID = &user.ID
	}

	if err := s.oauthRepo.CreateAccessToken(newAccessToken); err != nil {
		return nil, err
	}

	// Create refresh token if requested
	var newRefreshToken *model.RefreshToken
	if requestedType == TokenTypeRefreshToken {
		newRefreshToken = &model.RefreshToken{
			AccessTokenID: &newAccessToken.ID,
			ExpiresAt:     time.Now().Add(s.config.OAuth.RefreshTokenTTL),
		}
		if err := s.oauthRepo.CreateRefreshToken(newRefreshToken); err != nil {
			return nil, err
		}
	}

	result := &TokenResult{
		AccessToken: newAccessToken.Token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.config.OAuth.AccessTokenTTL.Seconds()),
		Scope:       scope,
	}

	if newRefreshToken != nil {
		result.RefreshToken = newRefreshToken.Token
	}

	return result, nil
}

/*
 * ValidateAccessToken 校验访问令牌并返回关联的用户
 * @param token - 访问令牌字符串
 * @return *model.User        - 关联用户（client_credentials 模式时为 nil）
 * @return *model.AccessToken  - 令牌实体
 */
func (s *OAuthService) ValidateAccessToken(token string) (*model.User, *model.AccessToken, error) {
	accessToken, err := s.oauthRepo.FindAccessToken(token)
	if err != nil {
		return nil, nil, ErrTokenExpired
	}

	if !accessToken.IsValid() {
		return nil, nil, ErrTokenRevoked
	}

	if accessToken.UserID == nil {
		// Client credentials token — no user associated
		return nil, accessToken, nil
	}

	user, err := s.userRepo.FindByID(*accessToken.UserID)
	if err != nil {
		return nil, nil, err
	}

	return user, accessToken, nil
}

/*
 * RevokeToken 撤销令牌
 * 功能：根据 tokenTypeHint 撤销指定类型的令牌，未指定时两者都尝试
 * @param token         - 令牌字符串
 * @param tokenTypeHint - 令牌类型提示 (access_token / refresh_token)
 */
func (s *OAuthService) RevokeToken(token, tokenTypeHint string) error {
	switch tokenTypeHint {
	case "access_token":
		/* 撤销 access_token 并同时撤销其关联的 refresh_token */
		at, err := s.oauthRepo.FindAccessToken(token)
		if err != nil {
			return err
		}
		_ = s.oauthRepo.RevokeAccessToken(token)
		_ = s.oauthRepo.RevokeRefreshTokenByAccessTokenID(at.ID)
		return nil
	case "refresh_token":
		/* 撤销 refresh_token 并同时撤销其关联的 access_token */
		rt, err := s.oauthRepo.FindRefreshToken(token)
		if err != nil {
			return err
		}
		_ = s.oauthRepo.RevokeRefreshToken(token)
		if rt.AccessTokenID != nil {
			if at, atErr := s.oauthRepo.FindAccessTokenByID(*rt.AccessTokenID); atErr == nil {
				_ = s.oauthRepo.RevokeAccessToken(at.Token)
			}
		}
		return nil
	default:
		/* 未指定类型，先尝试 access_token 再尝试 refresh_token */
		if at, err := s.oauthRepo.FindAccessToken(token); err == nil {
			_ = s.oauthRepo.RevokeAccessToken(token)
			_ = s.oauthRepo.RevokeRefreshTokenByAccessTokenID(at.ID)
			return nil
		}
		if rt, err := s.oauthRepo.FindRefreshToken(token); err == nil {
			_ = s.oauthRepo.RevokeRefreshToken(token)
			if rt.AccessTokenID != nil {
				if at, atErr := s.oauthRepo.FindAccessTokenByID(*rt.AccessTokenID); atErr == nil {
					_ = s.oauthRepo.RevokeAccessToken(at.Token)
				}
			}
			return nil
		}
		return ErrTokenExpired
	}
}

/*
 * GetUserInfoWithScope 获取访问令牌关联的用户信息及授权 scope (OIDC UserInfo 端点)
 * @param token - 访问令牌字符串
 * @return *model.User  - 用户实体
 * @return string       - 令牌授权的 scope
 */
func (s *OAuthService) GetUserInfoWithScope(token string) (*model.User, string, error) {
	user, accessToken, err := s.ValidateAccessToken(token)
	if err != nil {
		return nil, "", err
	}
	scope := ""
	if accessToken != nil {
		scope = accessToken.Scope
	}
	return user, scope, nil
}

/*
 * GetUserInfo 获取访问令牌关联的用户信息 (OIDC UserInfo 端点，向后兼容)
 * @param token - 访问令牌字符串
 * @return *model.User - 用户实体
 */
func (s *OAuthService) GetUserInfo(token string) (*model.User, error) {
	user, _, err := s.ValidateAccessToken(token)
	return user, err
}

/*
 * validateCodeVerifier PKCE code_verifier 校验 (RFC 7636)
 * @param verifier  - 客户端提供的 code_verifier
 * @param challenge - 授权请求时的 code_challenge
 * @param method    - 校验方法 (S256 / plain)
 * @return bool     - 校验通过返回 true
 */
func (s *OAuthService) validateCodeVerifier(verifier, challenge, method string) bool {
	if verifier == "" {
		return false
	}

	/*
	 * RFC 7636 §4.1: code_verifier 长度必须在 43-128 字符之间
	 * 过短的 verifier 安全熵不足，过长的超出规范
	 */
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}

	switch method {
	case "S256":
		hash := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		/* 使用常量时间比较防止时序攻击 */
		return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
	default:
		/* 仅支持 S256，拒绝 plain 和其他方法（符合 OAuth 2.1 草案要求） */
		return false
	}
}

/*
 * GetApplication 根据 client_id 获取应用
 * @param clientID - OAuth2 客户端 ID
 */
func (s *OAuthService) GetApplication(clientID string) (*model.Application, error) {
	return s.appRepo.FindByClientID(clientID)
}

/*
 * ParseScope 解析空格分隔的 scope 字符串
 * @param scope  - 空格分隔的 scope 字符串
 * @return []string - scope 切片
 */
func ParseScope(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Split(scope, " ")
}

/*
 * IntrospectToken Token 内省 (RFC 7662)
 * 功能：校验令牌有效性并返回其元数据，支持 access_token 和 refresh_token
 * @param token         - 待内省的令牌
 * @param clientID      - 请求客户端 ID（可选，用于身份验证）
 * @param clientSecret  - 请求客户端密钥（可选）
 * @param tokenTypeHint - 令牌类型提示
 * @return map[string]interface{} - 令牌元数据（active, scope, sub 等）
 */
func (s *OAuthService) IntrospectToken(token, clientID, clientSecret, tokenTypeHint string) (map[string]interface{}, error) {
	/*
	 * RFC 7662 安全增强：强制要求客户端认证
	 * introspection 端点返回敏感信息（用户 ID、scope 等），必须验证调用者身份
	 * 拒绝无认证的请求，防止未授权方探测 token 状态
	 */
	if clientID == "" {
		return nil, ErrInvalidClient
	}
	app, err := s.appRepo.FindByClientID(clientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	/* 机密客户端必须提供有效 secret */
	if app.AppType == model.AppTypeConfidential || app.AppType == model.AppTypeMachine {
		if clientSecret == "" || app.ClientSecret != clientSecret {
			return nil, ErrInvalidClient
		}
	} else if clientSecret != "" && app.ClientSecret != clientSecret {
		return nil, ErrInvalidClient
	}

	// 尝试验证为access_token
	if tokenTypeHint == "" || tokenTypeHint == "access_token" {
		user, accessToken, err := s.ValidateAccessToken(token)
		if err == nil && accessToken != nil {
			result := map[string]interface{}{
				"active":     true,
				"scope":      accessToken.Scope,
				"client_id":  accessToken.ClientID,
				"token_type": "Bearer",
				"exp":        accessToken.ExpiresAt.Unix(),
				"iat":        accessToken.CreatedAt.Unix(),
				"aud":        accessToken.ClientID,
				"iss":        s.config.JWT.Issuer,
			}
			/* 有用户关联时补充用户字段（client_credentials 模式无用户） */
			if user != nil {
				result["sub"] = user.ID.String()
				result["username"] = user.Username
				result["email"] = user.Email
				result["email_verified"] = user.EmailVerified
			}
			return result, nil
		}
	}

	// 尝试验证为refresh_token
	if tokenTypeHint == "" || tokenTypeHint == "refresh_token" {
		refreshToken, err := s.oauthRepo.FindRefreshToken(token)
		if err == nil && refreshToken != nil && refreshToken.ExpiresAt.After(time.Now()) && !refreshToken.Revoked {
			// 获取关联的access token信息
			var accessToken *model.AccessToken
			if refreshToken.AccessTokenID != nil {
				accessToken, _ = s.oauthRepo.FindAccessTokenByID(*refreshToken.AccessTokenID)
			}
			if accessToken != nil && accessToken.UserID != nil {
				user, _ := s.userRepo.FindByID(*accessToken.UserID)
				return map[string]interface{}{
					"active":     true,
					"scope":      accessToken.Scope,
					"client_id":  accessToken.ClientID,
					"username":   user.Username,
					"token_type": "refresh_token",
					"exp":        refreshToken.ExpiresAt.Unix(),
					"iat":        refreshToken.CreatedAt.Unix(),
					"sub":        user.ID.String(),
				}, nil
			}
		}
	}

	return nil, errors.New("token not found or invalid")
}
