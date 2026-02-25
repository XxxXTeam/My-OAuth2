package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"
	"server/pkg/password"

	"github.com/google/uuid"
)

/* 社交登录服务层错误定义 */
var (
	ErrProviderNotFound      = errors.New("provider not found")
	ErrProviderDisabled      = errors.New("provider is disabled")
	ErrOAuthStateMismatch    = errors.New("oauth state mismatch")
	ErrOAuthCodeExchange     = errors.New("failed to exchange code for token")
	ErrOAuthUserInfo         = errors.New("failed to get user info from provider")
	ErrNoEmailFromProvider   = errors.New("no email returned from provider")
	ErrIdentityAlreadyLinked = errors.New("this social account is already linked to another user")
	ErrIdentityNotFound      = errors.New("social identity not found")
	ErrCannotUnlinkOnly      = errors.New("cannot unlink the only login method")
)

/*
 * SocialAuthService 社交/联邦登录服务
 * 功能：实现通过外部 OAuth2 提供者（GitHub、Google、自定义 SSO 等）的用户登录和账号关联
 *       支持自动创建用户、资料同步、身份绑定/解绑
 */
type SocialAuthService struct {
	userRepo       *repository.UserRepository
	federationRepo *repository.FederationRepository
	loginLogRepo   *repository.LoginLogRepository
	oauthRepo      *repository.OAuthRepository
	jwtManager     *jwt.Manager
	config         *config.Config
	httpClient     *http.Client
}

/* SetOAuthRepo 注入 OAuthRepository（启用 Refresh Token Rotation） */
func (s *SocialAuthService) SetOAuthRepo(repo *repository.OAuthRepository) {
	s.oauthRepo = repo
}

/*
 * NewSocialAuthService 创建社交登录服务实例
 * @param userRepo       - 用户仓储
 * @param federationRepo - 联邦仓储
 * @param loginLogRepo   - 登录日志仓储
 * @param jwtManager     - JWT 管理器
 * @param cfg            - 系统配置
 */
func NewSocialAuthService(
	userRepo *repository.UserRepository,
	federationRepo *repository.FederationRepository,
	loginLogRepo *repository.LoginLogRepository,
	jwtManager *jwt.Manager,
	cfg *config.Config,
) *SocialAuthService {
	return &SocialAuthService{
		userRepo:       userRepo,
		federationRepo: federationRepo,
		loginLogRepo:   loginLogRepo,
		jwtManager:     jwtManager,
		config:         cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

/* ProviderConfig 内置社交提供者配置模板 */
type ProviderConfig struct {
	Name        string
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	Scopes      []string
}

/* builtinProviders 内置社交提供者配置模板（GitHub、Google、GitLab） */
var builtinProviders = map[string]ProviderConfig{
	"github": {
		Name:        "GitHub",
		AuthURL:     "https://github.com/login/oauth/authorize",
		TokenURL:    "https://github.com/login/oauth/access_token",
		UserInfoURL: "https://api.github.com/user",
		Scopes:      []string{"user:email", "read:user"},
	},
	"google": {
		Name:        "Google",
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:    "https://oauth2.googleapis.com/token",
		UserInfoURL: "https://www.googleapis.com/oauth2/v2/userinfo",
		Scopes:      []string{"openid", "email", "profile"},
	},
}

// GetAuthURL 获取第三方登录授权URL
func (s *SocialAuthService) GetAuthURL(providerSlug, state, redirectURI string) (string, error) {
	provider, err := s.federationRepo.FindBySlug(providerSlug)
	if err != nil {
		return "", ErrProviderNotFound
	}
	if !provider.Enabled {
		return "", ErrProviderDisabled
	}

	params := url.Values{}
	params.Set("client_id", provider.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("state", state)
	if provider.Scopes != "" {
		params.Set("scope", provider.Scopes)
	}

	// Google需要额外参数
	if providerSlug == "google" {
		params.Set("access_type", "offline")
		params.Set("prompt", "consent")
	}

	return fmt.Sprintf("%s?%s", provider.AuthURL, params.Encode()), nil
}
func (s *SocialAuthService) ExchangeCodeForToken(ctx context.Context, providerSlug, code, redirectURI string) (*OAuthTokenResponse, error) {
	provider, err := s.federationRepo.FindBySlug(providerSlug)
	if err != nil {
		return nil, ErrProviderNotFound
	}

	data := url.Values{}
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", provider.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, ErrOAuthCodeExchange
	}
	defer resp.Body.Close()

	/* 限制响应体大小（1MB），防止恶意提供者返回超大响应 */
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, ErrOAuthCodeExchange
	}

	var tokenResp OAuthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		values, _ := url.ParseQuery(string(body))
		tokenResp.AccessToken = values.Get("access_token")
		tokenResp.TokenType = values.Get("token_type")
	}

	if tokenResp.AccessToken == "" {
		return nil, ErrOAuthCodeExchange
	}

	return &tokenResp, nil
}

type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type SocialUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Username      string `json:"username"`
	AvatarURL     string `json:"avatar_url"`
	EmailVerified bool   `json:"email_verified"`
}

func (s *SocialAuthService) GetUserInfo(ctx context.Context, providerSlug, accessToken string) (*SocialUserInfo, error) {
	provider, err := s.federationRepo.FindBySlug(providerSlug)
	if err != nil {
		return nil, ErrProviderNotFound
	}

	req, err := http.NewRequestWithContext(ctx, "GET", provider.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	if providerSlug == "github" {
		req.Header.Set("Accept", "application/vnd.github.v3+json")
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, ErrOAuthUserInfo
	}
	defer resp.Body.Close()

	/* 限制响应体大小（1MB），防止恶意提供者返回超大响应 */
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, ErrOAuthUserInfo
	}

	var rawData map[string]interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, ErrOAuthUserInfo
	}

	// 根据提供商解析用户信息
	userInfo := &SocialUserInfo{}
	switch providerSlug {
	case "github":
		userInfo = s.parseGitHubUser(rawData, accessToken)
	case "google":
		userInfo = s.parseGoogleUser(rawData)
	default:
		userInfo = s.parseGenericUser(rawData)
	}

	if userInfo.Email == "" {
		return nil, ErrNoEmailFromProvider
	}

	return userInfo, nil
}
func (s *SocialAuthService) parseGitHubUser(data map[string]interface{}, accessToken string) *SocialUserInfo {
	user := &SocialUserInfo{
		EmailVerified: true,
	}

	if id, ok := data["id"].(float64); ok {
		user.ID = fmt.Sprintf("%.0f", id)
	}
	if email, ok := data["email"].(string); ok {
		user.Email = email
	}
	if name, ok := data["name"].(string); ok {
		user.Name = name
	}
	if login, ok := data["login"].(string); ok {
		user.Username = login
	}
	if avatar, ok := data["avatar_url"].(string); ok {
		user.AvatarURL = avatar
	}
	if user.Email == "" {
		user.Email = s.fetchGitHubEmail(accessToken)
	}

	return user
}

func (s *SocialAuthService) fetchGitHubEmail(accessToken string) string {
	req, _ := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	/* 限制响应体大小（1MB） */
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	json.Unmarshal(body, &emails)

	// 优先返回主邮箱
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email
		}
	}
	// 返回任意已验证邮箱
	for _, e := range emails {
		if e.Verified {
			return e.Email
		}
	}
	return ""
}

// parseGoogleUser 解析Google用户信息
func (s *SocialAuthService) parseGoogleUser(data map[string]interface{}) *SocialUserInfo {
	user := &SocialUserInfo{}

	if id, ok := data["id"].(string); ok {
		user.ID = id
	}
	if email, ok := data["email"].(string); ok {
		user.Email = email
	}
	if verified, ok := data["verified_email"].(bool); ok {
		user.EmailVerified = verified
	}
	if name, ok := data["name"].(string); ok {
		user.Name = name
	}
	if picture, ok := data["picture"].(string); ok {
		user.AvatarURL = picture
	}

	return user
}

// parseGenericUser 解析通用用户信息
func (s *SocialAuthService) parseGenericUser(data map[string]interface{}) *SocialUserInfo {
	user := &SocialUserInfo{}

	// 尝试多种常见字段名
	for _, key := range []string{"id", "sub", "user_id"} {
		if v, ok := data[key]; ok {
			user.ID = fmt.Sprintf("%v", v)
			break
		}
	}
	for _, key := range []string{"email", "mail"} {
		if v, ok := data[key].(string); ok {
			user.Email = v
			break
		}
	}
	for _, key := range []string{"name", "display_name", "displayName"} {
		if v, ok := data[key].(string); ok {
			user.Name = v
			break
		}
	}
	for _, key := range []string{"username", "login", "preferred_username"} {
		if v, ok := data[key].(string); ok {
			user.Username = v
			break
		}
	}
	for _, key := range []string{"avatar_url", "picture", "avatar", "photo"} {
		if v, ok := data[key].(string); ok {
			user.AvatarURL = v
			break
		}
	}
	if v, ok := data["email_verified"].(bool); ok {
		user.EmailVerified = v
	}

	return user
}

// LoginOrCreateUser 使用社交账号登录或创建用户
func (s *SocialAuthService) LoginOrCreateUser(
	ctx context.Context,
	providerSlug string,
	userInfo *SocialUserInfo,
	tokenResp *OAuthTokenResponse,
	ipAddress, userAgent string,
) (*model.User, *AuthTokens, error) {
	provider, err := s.federationRepo.FindBySlug(providerSlug)
	if err != nil {
		return nil, nil, ErrProviderNotFound
	}

	// 查找是否已有关联身份
	identity, err := s.federationRepo.FindIdentityByExternalID(provider.ID, userInfo.ID)
	if err == nil && identity != nil {
		// 已存在关联，直接登录
		user, err := s.userRepo.FindByID(identity.UserID)
		if err != nil {
			return nil, nil, err
		}

		// 更新令牌
		identity.AccessToken = tokenResp.AccessToken
		identity.RefreshToken = tokenResp.RefreshToken
		if tokenResp.ExpiresIn > 0 {
			identity.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		}
		s.federationRepo.UpdateIdentity(identity)

		// 同步资料
		if provider.SyncProfile {
			s.syncUserProfile(user, userInfo)
			s.userRepo.Update(user)
		}

		// 记录登录日志
		if s.loginLogRepo != nil {
			s.loginLogRepo.CreateLoginLog(&user.ID, nil, model.LoginTypeOAuth, ipAddress, userAgent, user.Email, true, "")
		}

		tokens, err := s.generateTokens(user)
		return user, tokens, err
	}

	// 尝试通过邮箱查找用户
	existingUser, err := s.userRepo.FindByEmail(userInfo.Email)
	if err == nil && existingUser != nil {
		// 用户存在，创建关联
		identity := &model.FederatedIdentity{
			UserID:        existingUser.ID,
			ProviderID:    provider.ID,
			ExternalID:    userInfo.ID,
			ExternalEmail: userInfo.Email,
			AccessToken:   tokenResp.AccessToken,
			RefreshToken:  tokenResp.RefreshToken,
		}
		if tokenResp.ExpiresIn > 0 {
			identity.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		}
		s.federationRepo.CreateIdentity(identity)

		// 记录登录日志
		if s.loginLogRepo != nil {
			s.loginLogRepo.CreateLoginLog(&existingUser.ID, nil, model.LoginTypeOAuth, ipAddress, userAgent, existingUser.Email, true, "")
		}

		tokens, err := s.generateTokens(existingUser)
		return existingUser, tokens, err
	}

	// 如果不允许自动创建用户
	if !provider.AutoCreateUser {
		return nil, nil, errors.New("user not found and auto-creation is disabled")
	}

	// 创建新用户
	username := userInfo.Username
	if username == "" {
		username = strings.Split(userInfo.Email, "@")[0]
	}
	// 确保用户名唯一
	username = s.ensureUniqueUsername(username)

	// 生成随机密码
	randomPwd, _ := password.GenerateRandom(16)
	hashedPwd, _ := password.Hash(randomPwd)

	newUser := &model.User{
		Email:         userInfo.Email,
		Username:      username,
		PasswordHash:  hashedPwd,
		Avatar:        userInfo.AvatarURL,
		EmailVerified: provider.TrustEmailVerified && userInfo.EmailVerified,
		Status:        "active",
	}

	if userInfo.Name != "" {
		parts := strings.SplitN(userInfo.Name, " ", 2)
		if len(parts) == 2 {
			newUser.GivenName = parts[0]
			newUser.FamilyName = parts[1]
		} else {
			newUser.Nickname = userInfo.Name
		}
	}

	if err := s.userRepo.Create(newUser); err != nil {
		return nil, nil, err
	}

	// 创建关联
	identity = &model.FederatedIdentity{
		UserID:        newUser.ID,
		ProviderID:    provider.ID,
		ExternalID:    userInfo.ID,
		ExternalEmail: userInfo.Email,
		AccessToken:   tokenResp.AccessToken,
		RefreshToken:  tokenResp.RefreshToken,
	}
	if tokenResp.ExpiresIn > 0 {
		identity.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}
	s.federationRepo.CreateIdentity(identity)

	// 记录登录日志
	if s.loginLogRepo != nil {
		s.loginLogRepo.CreateLoginLog(&newUser.ID, nil, model.LoginTypeOAuth, ipAddress, userAgent, newUser.Email, true, "")
	}

	tokens, err := s.generateTokens(newUser)
	return newUser, tokens, err
}

// syncUserProfile 同步用户资料
func (s *SocialAuthService) syncUserProfile(user *model.User, info *SocialUserInfo) {
	if user.Avatar == "" && info.AvatarURL != "" {
		user.Avatar = info.AvatarURL
	}
	if user.Nickname == "" && info.Name != "" {
		user.Nickname = info.Name
	}
}

// ensureUniqueUsername 确保用户名唯一
func (s *SocialAuthService) ensureUniqueUsername(base string) string {
	username := base
	suffix := 1
	for {
		exists, _ := s.userRepo.ExistsByUsername(username)
		if !exists {
			return username
		}
		username = fmt.Sprintf("%s%d", base, suffix)
		suffix++
		if suffix > 1000 {
			// 避免无限循环
			return fmt.Sprintf("%s_%s", base, uuid.New().String()[:8])
		}
	}
}

func (s *SocialAuthService) generateTokens(user *model.User) (*AuthTokens, error) {
	accessToken, err := s.jwtManager.GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeAccess,
		s.config.JWT.AccessTokenTTL,
	)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.jwtManager.GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeRefresh,
		s.config.JWT.RefreshTokenTTL,
	)
	if err != nil {
		return nil, err
	}

	/* 将 refresh token 的 JTI 存入 DB，用于 Token Rotation 追踪 */
	if s.oauthRepo != nil {
		if refreshClaims, parseErr := s.jwtManager.ValidateRefreshToken(refreshToken); parseErr == nil {
			_ = s.oauthRepo.StoreAuthRefreshToken(
				refreshClaims.ID,
				user.ID,
				refreshClaims.ExpiresAt.Time,
			)
		}
	}

	return &AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
	}, nil
}

// GetEnabledProviders 获取已启用的提供商列表
func (s *SocialAuthService) GetEnabledProviders() ([]model.FederatedProvider, error) {
	return s.federationRepo.FindAllEnabled()
}

// LinkAccount 将社交账号关联到已登录用户
func (s *SocialAuthService) LinkAccount(
	ctx context.Context,
	userID uuid.UUID,
	providerSlug string,
	code string,
	redirectURI string,
) error {
	provider, err := s.federationRepo.FindBySlug(providerSlug)
	if err != nil {
		return ErrProviderNotFound
	}
	if !provider.Enabled {
		return ErrProviderDisabled
	}

	// 交换token
	tokenResp, err := s.ExchangeCodeForToken(ctx, providerSlug, code, redirectURI)
	if err != nil {
		return err
	}

	// 获取用户信息
	userInfo, err := s.GetUserInfo(ctx, providerSlug, tokenResp.AccessToken)
	if err != nil {
		return err
	}

	// 检查该社交账号是否已被其他用户关联
	existingIdentity, err := s.federationRepo.FindIdentityByExternalID(provider.ID, userInfo.ID)
	if err == nil && existingIdentity != nil {
		if existingIdentity.UserID != userID {
			return ErrIdentityAlreadyLinked
		}
		// 已经关联到当前用户，更新token
		existingIdentity.AccessToken = tokenResp.AccessToken
		existingIdentity.RefreshToken = tokenResp.RefreshToken
		if tokenResp.ExpiresIn > 0 {
			existingIdentity.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		}
		return s.federationRepo.UpdateIdentity(existingIdentity)
	}

	// 创建新关联
	identity := &model.FederatedIdentity{
		UserID:        userID,
		ProviderID:    provider.ID,
		ExternalID:    userInfo.ID,
		ExternalEmail: userInfo.Email,
		AccessToken:   tokenResp.AccessToken,
		RefreshToken:  tokenResp.RefreshToken,
	}
	if tokenResp.ExpiresIn > 0 {
		identity.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return s.federationRepo.CreateIdentity(identity)
}

// UnlinkAccount 解除社交账号关联
func (s *SocialAuthService) UnlinkAccount(userID uuid.UUID, providerSlug string) error {
	provider, err := s.federationRepo.FindBySlug(providerSlug)
	if err != nil {
		return ErrProviderNotFound
	}

	// 查找用户的该提供商关联
	identities, err := s.federationRepo.FindIdentitiesByUserID(userID)
	if err != nil {
		return err
	}

	var targetIdentity *model.FederatedIdentity
	for i := range identities {
		if identities[i].ProviderID == provider.ID {
			targetIdentity = &identities[i]
			break
		}
	}

	if targetIdentity == nil {
		return ErrIdentityNotFound
	}

	// 检查用户是否有密码或其他登录方式
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	// 如果用户没有密码且只有一个社交登录方式，不允许解除关联
	if user.PasswordHash == "" && len(identities) <= 1 {
		return ErrCannotUnlinkOnly
	}

	return s.federationRepo.DeleteIdentity(targetIdentity.ID)
}

// GetUserLinkedProviders 获取用户已关联的提供商
func (s *SocialAuthService) GetUserLinkedProviders(userID uuid.UUID) ([]model.FederatedIdentity, error) {
	return s.federationRepo.FindIdentitiesByUserID(userID)
}
