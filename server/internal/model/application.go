package model

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * ApplicationType OAuth2 客户端类型枚举
 * @value AppTypeConfidential - 机密客户端（服务端应用，可安全存储密钥）
 * @value AppTypePublic       - 公开客户端（移动端/SPA，无法安全存储密钥）
 * @value AppTypeMachine      - 机器对机器（服务账号，用于 client_credentials 授权）
 */
type ApplicationType string

const (
	AppTypeConfidential ApplicationType = "confidential" // Server-side apps with secure storage
	AppTypePublic       ApplicationType = "public"       // Mobile/SPA apps without secure storage
	AppTypeMachine      ApplicationType = "machine"      // Machine-to-machine (service accounts)
)

/*
 * TokenEndpointAuthMethod Token 端点认证方式枚举
 * @value AuthMethodClientSecretBasic - HTTP Basic 认证（Authorization 头）
 * @value AuthMethodClientSecretPost  - POST 请求体中携带 client_secret
 * @value AuthMethodClientSecretJWT   - 使用共享密钥签名的 JWT 认证
 * @value AuthMethodPrivateKeyJWT     - 使用私钥签名的 JWT 认证
 * @value AuthMethodNone              - 无认证（公开客户端）
 */
type TokenEndpointAuthMethod string

const (
	AuthMethodClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	AuthMethodClientSecretPost  TokenEndpointAuthMethod = "client_secret_post"
	AuthMethodClientSecretJWT   TokenEndpointAuthMethod = "client_secret_jwt"
	AuthMethodPrivateKeyJWT     TokenEndpointAuthMethod = "private_key_jwt"
	AuthMethodNone              TokenEndpointAuthMethod = "none"
)

/*
 * Application OAuth2 应用/客户端模型
 * 功能：定义 OAuth2 客户端注册信息，包括密钥、回调地址、授权范围和授权类型
 * 表名：applications
 * 索引：client_id(唯一), user_id
 */
type Application struct {
	ID                     uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ClientID               string    `gorm:"uniqueIndex;size:100;not null" json:"client_id"`
	ClientSecret           string    `gorm:"size:255;not null" json:"-"`
	Name                   string    `gorm:"size:200;not null" json:"name"`
	Description            string    `gorm:"type:text" json:"description,omitempty"`
	RedirectURIs           string    `gorm:"type:text;not null" json:"-"` // JSON array stored as string
	PostLogoutRedirectURIs string    `gorm:"type:text" json:"-"`
	Scopes                 string    `gorm:"type:text" json:"-"` // JSON array stored as string
	UserID                 uuid.UUID `gorm:"type:uuid;index" json:"user_id"`
	CreatedAt              time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt              time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	// OAuth2 Client Configuration
	AppType                 ApplicationType         `gorm:"size:20;default:confidential" json:"app_type"`
	TokenEndpointAuthMethod TokenEndpointAuthMethod `gorm:"size:30;default:client_secret_basic" json:"token_endpoint_auth_method"`
	GrantTypes              string                  `gorm:"type:text" json:"-"` // JSON array: authorization_code, refresh_token, client_credentials, device_code
	AllowedScopes           string                  `gorm:"type:text" json:"-"` // JSON array: scopes allowed for client_credentials
	JWKSURI                 string                  `gorm:"size:500" json:"jwks_uri,omitempty"`
	JWKS                    string                  `gorm:"type:text" json:"-"` // JSON Web Key Set for private_key_jwt

	// Relations
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * 功能：自动生成 UUID 主键
 * @param tx - 当前数据库事务
 */
func (a *Application) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}

/*
 * GetRedirectURIs 解析 JSON 数组格式的回调地址列表
 * @return []string - 允许的回调 URI 列表
 */
func (a *Application) GetRedirectURIs() []string {
	var uris []string
	if a.RedirectURIs != "" {
		json.Unmarshal([]byte(a.RedirectURIs), &uris)
	}
	return uris
}

/*
 * SetRedirectURIs 将回调地址列表序列化为 JSON 存储
 * @param uris - 回调 URI 列表
 */
func (a *Application) SetRedirectURIs(uris []string) {
	data, _ := json.Marshal(uris)
	a.RedirectURIs = string(data)
}

/* GetPostLogoutRedirectURIs 解析 OIDC RP-Initiated Logout 回跳地址列表 */
func (a *Application) GetPostLogoutRedirectURIs() []string {
	var uris []string
	if a.PostLogoutRedirectURIs != "" {
		json.Unmarshal([]byte(a.PostLogoutRedirectURIs), &uris)
	}
	return uris
}

/* SetPostLogoutRedirectURIs 将 OIDC 登出回跳地址列表序列化为 JSON 存储 */
func (a *Application) SetPostLogoutRedirectURIs(uris []string) {
	data, _ := json.Marshal(uris)
	a.PostLogoutRedirectURIs = string(data)
}

/* ValidatePostLogoutRedirectURI 校验 OIDC 登出回跳地址是否精确登记 */
func (a *Application) ValidatePostLogoutRedirectURI(uri string) bool {
	if !isSafeRegisteredURI(uri) {
		return false
	}
	for _, allowed := range a.GetPostLogoutRedirectURIs() {
		if allowed == uri {
			return true
		}
	}
	return false
}

/*
 * GetScopes 解析 JSON 数组格式的权限范围列表
 * @return []string - 应用支持的 scope 列表
 */
func (a *Application) GetScopes() []string {
	var scopes []string
	if a.Scopes != "" {
		json.Unmarshal([]byte(a.Scopes), &scopes)
	}
	return scopes
}

/*
 * SetScopes 将权限范围列表序列化为 JSON 存储
 * @param scopes - scope 列表
 */
func (a *Application) SetScopes(scopes []string) {
	data, _ := json.Marshal(scopes)
	a.Scopes = string(data)
}

/* isSafeRegisteredURI 执行 OAuth/OIDC 回跳地址基础安全校验 */
func isSafeRegisteredURI(uri string) bool {
	lower := strings.ToLower(uri)
	return uri != "" &&
		!strings.HasPrefix(lower, "javascript:") &&
		!strings.HasPrefix(lower, "data:") &&
		!strings.HasPrefix(lower, "vbscript:") &&
		!strings.Contains(uri, "/../") &&
		!strings.Contains(uri, "/..\\") &&
		!strings.Contains(uri, "@")
}

/* ValidateRedirectURI 校验 OAuth redirect_uri 是否精确登记 */
func (a *Application) ValidateRedirectURI(uri string) bool {
	if !isSafeRegisteredURI(uri) {
		return false
	}
	for _, allowed := range a.GetRedirectURIs() {
		if allowed == uri {
			return true
		}
	}
	return false
}

/*
 * GetGrantTypes 解析 JSON 数组格式的授权类型列表
 * 功能：返回应用支持的 grant_type，默认为 [authorization_code, refresh_token]
 * @return []string - 授权类型列表
 */
func (a *Application) GetGrantTypes() []string {
	var types []string
	if a.GrantTypes != "" {
		json.Unmarshal([]byte(a.GrantTypes), &types)
	}
	// Default grant types if not set
	if len(types) == 0 {
		types = []string{"authorization_code", "refresh_token"}
	}
	return types
}

/*
 * SetGrantTypes 将授权类型列表序列化为 JSON 存储
 * @param types - grant_type 列表
 */
func (a *Application) SetGrantTypes(types []string) {
	data, _ := json.Marshal(types)
	a.GrantTypes = string(data)
}

/*
 * normalizeGrantType 将 grant_type 别名归一化（前端/URN 与存储值互通）
 */
func normalizeGrantType(grantType string) string {
	switch grantType {
	case "token-exchange", "urn:ietf:params:oauth:grant-type:token-exchange":
		return "token_exchange"
	case "device_code", "urn:ietf:params:oauth:grant-type:device_code":
		return "device_code"
	default:
		return grantType
	}
}

/*
 * SupportsGrantType 检查应用是否支持指定的授权类型
 * @param grantType - 待检查的 grant_type（支持 URN 别名）
 * @return bool     - 支持返回 true
 */
func (a *Application) SupportsGrantType(grantType string) bool {
	want := normalizeGrantType(grantType)
	for _, gt := range a.GetGrantTypes() {
		if normalizeGrantType(gt) == want {
			return true
		}
	}
	return false
}

/* userCentricScopes 仅适用于终端用户授权（授权码/设备流等），禁止 client_credentials */
var userCentricScopes = map[string]struct{}{
	"openid": {}, "profile": {}, "email": {}, "phone": {}, "address": {}, "groups": {}, "offline_access": {},
}

func DefaultUserAuthorizationScopes() []string {
	/* groups：返回用户所属组/角色（UserInfo groups claim），属于用户 scope */
	return []string{"openid", "profile", "email", "phone", "address", "groups", "offline_access"}
}

/* DefaultMachineScopes client_credentials 默认可申请的机器 scope */
func DefaultMachineScopes() []string {
	return []string{"api.read", "api.write"}
}

/*
 * AllServerSupportedScopes OIDC Discovery 与文档用：用户 scope + 机器 scope 并集
 */
func AllServerSupportedScopes() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range append(DefaultUserAuthorizationScopes(), DefaultMachineScopes()...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

/*
 * GetUserAuthorizationScopes 终端用户授权（授权码/设备流）允许的 scope
 * 仅含 userCentricScopes，排除应用上配置的 api.read 等机器 scope
 */
func (a *Application) GetUserAuthorizationScopes() []string {
	if scopes := a.GetScopes(); len(scopes) > 0 {
		var out []string
		for _, s := range scopes {
			if _, ok := userCentricScopes[s]; ok {
				out = appendUniqueString(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return DefaultUserAuthorizationScopes()
}

/*
 * GetOIDCScopes 同 GetUserAuthorizationScopes（OIDC 授权页 / 校验）
 */
func (a *Application) GetOIDCScopes() []string {
	return a.GetUserAuthorizationScopes()
}

/* userScopeDisplayOrder 授权页展示顺序（不含 openid） */
var userScopeDisplayOrder = []string{"profile", "email", "phone", "address", "groups", "offline_access"}

/* AuthorizeScopeBreakdown 解析授权请求中的 scope */
type AuthorizeScopeBreakdown struct {
	DisplayScopes  []string // 授权页列表（不含 openid）
	InvalidScopes  []string // 请求了但应用不允许或非用户 scope
	EffectiveScope string   // 将写入授权码的 scope
	HasOpenID      bool
}

/*
 * ParseAuthorizeScopeRequest 解析 scope 查询参数：交集、去重、无效项分离
 */
func (a *Application) ParseAuthorizeScopeRequest(requestedScope string) AuthorizeScopeBreakdown {
	var out AuthorizeScopeBreakdown
	requestedScope = strings.TrimSpace(requestedScope)
	if requestedScope == "" {
		return out
	}
	allowed := make(map[string]struct{}, len(a.GetUserAuthorizationScopes()))
	for _, s := range a.GetUserAuthorizationScopes() {
		allowed[s] = struct{}{}
	}
	seen := make(map[string]struct{})
	var effective []string
	for _, rs := range strings.Fields(requestedScope) {
		if rs == "" {
			continue
		}
		if _, dup := seen[rs]; dup {
			continue
		}
		seen[rs] = struct{}{}
		if _, user := userCentricScopes[rs]; !user {
			out.InvalidScopes = appendUniqueString(out.InvalidScopes, rs)
			continue
		}
		if _, ok := allowed[rs]; !ok {
			out.InvalidScopes = appendUniqueString(out.InvalidScopes, rs)
			continue
		}
		effective = append(effective, rs)
		if rs == "openid" {
			out.HasOpenID = true
		}
	}
	out.EffectiveScope = strings.Join(effective, " ")
	out.DisplayScopes = orderUserScopesForDisplay(effective)
	return out
}

func orderUserScopesForDisplay(effective []string) []string {
	inEffective := make(map[string]struct{})
	for _, s := range effective {
		if s != "openid" {
			inEffective[s] = struct{}{}
		}
	}
	var ordered []string
	for _, s := range userScopeDisplayOrder {
		if _, ok := inEffective[s]; ok {
			ordered = append(ordered, s)
		}
	}
	for _, s := range effective {
		if s == "openid" {
			continue
		}
		if _, ok := inEffective[s]; !ok {
			continue
		}
		already := false
		for _, o := range ordered {
			if o == s {
				already = true
				break
			}
		}
		if !already {
			ordered = append(ordered, s)
		}
	}
	return ordered
}

/*
 * GetResponseTypesSupported 根据 grant_types 推导 OAuth response_types（RFC 6749）
 */
func (a *Application) GetResponseTypesSupported() []string {
	for _, gt := range a.GetGrantTypes() {
		if normalizeGrantType(gt) == "authorization_code" {
			return []string{"code"}
		}
	}
	return []string{"code"}
}

/* HasOIDCScope 应用是否配置 openid（可签发 id_token） */
func (a *Application) HasOIDCScope() bool {
	return ScopeContainsOpenID(strings.Join(a.GetOIDCScopes(), " "))
}

func appendUniqueString(out []string, v string) []string {
	for _, existing := range out {
		if existing == v {
			return out
		}
	}
	return append(out, v)
}

/*
 * FilterRequestedUserScopes 授权页展示的 scope（不含 openid，已排序）
 */
func (a *Application) FilterRequestedUserScopes(requestedScope string) []string {
	return a.ParseAuthorizeScopeRequest(requestedScope).DisplayScopes
}

/*
 * GetIssuedTokenTypes 按应用 grant 推导默认可签发的令牌类型（管理端展示等）
 */
func (a *Application) GetIssuedTokenTypes() []string {
	return a.GetIssuedTokenTypesForRequest("", "")
}

/*
 * GetIssuedTokenTypesForRequest 按当前授权请求（scope、response_type）推导将签发的令牌类型
 */
func (a *Application) GetIssuedTokenTypesForRequest(requestedScope, responseType string) []string {
	var out []string
	hasUserGrant := false
	for _, gt := range a.GetGrantTypes() {
		switch normalizeGrantType(gt) {
		case "authorization_code", "device_code", "refresh_token", "token_exchange":
			hasUserGrant = true
		}
	}
	if !hasUserGrant {
		for _, gt := range a.GetGrantTypes() {
			if normalizeGrantType(gt) == "client_credentials" {
				return []string{"access_token"}
			}
		}
		return out
	}
	out = appendUniqueString(out, "access_token")

	for _, gt := range a.GetGrantTypes() {
		switch normalizeGrantType(gt) {
		case "authorization_code", "device_code", "refresh_token":
			out = appendUniqueString(out, "refresh_token")
		}
	}
	if ScopeContainsOpenID(requestedScope) || strings.Contains(responseType, "id_token") {
		out = appendUniqueString(out, "id_token")
	}
	return out
}

/* ScopeContainsOpenID 是否包含 openid scope（需签发 id_token） */
func ScopeContainsOpenID(scope string) bool {
	for _, s := range strings.Fields(scope) {
		if s == "openid" {
			return true
		}
	}
	return false
}

func ScopeContainsWildcard(scope string) bool {
	for _, s := range strings.Fields(scope) {
		if isWildcardScope(s) {
			return true
		}
	}
	return false
}

/*
 * isWildcardScope 通配 scope（如 all）在用户授权里可能表示“全部权限”，
 * client_credentials 禁止签发，避免绕过 openid/profile 校验。
 */
func isWildcardScope(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "all", "*":
		return true
	default:
		return false
	}
}

/*
 * ContainsUserCentricScope 是否包含 OIDC 用户类 scope
 */
func ContainsUserCentricScope(scope string) bool {
	for _, s := range strings.Fields(scope) {
		if _, ok := userCentricScopes[s]; ok {
			return true
		}
		if isWildcardScope(s) {
			return true
		}
	}
	return false
}

/*
 * ResolveClientCredentialsScope 解析 client_credentials 可签发的 scope
 * 规则：禁止 openid/profile 等用户 scope；必须在 AllowedScopes（或过滤后的 Scopes）白名单内
 * @return (scope, ok) — ok=false 表示请求非法
 */
func (a *Application) ResolveClientCredentialsScope(requested string) (string, bool) {
	if ContainsUserCentricScope(requested) {
		return "", false
	}
	allowed := a.GetAllowedScopes()
	if len(allowed) == 0 {
		for _, s := range a.GetScopes() {
			if !ContainsUserCentricScope(s) && !isWildcardScope(s) {
				allowed = append(allowed, s)
			}
		}
	}
	if len(allowed) == 0 {
		/* 未配置任何机器 scope 时仅允许空 scope（纯客户端身份令牌） */
		return "", requested == ""
	}
	if requested == "" {
		return strings.Join(allowed, " "), true
	}
	for _, rs := range strings.Fields(requested) {
		found := false
		for _, as := range allowed {
			if rs == as {
				found = true
				break
			}
		}
		if !found {
			return "", false
		}
	}
	return requested, true
}

/*
 * GetAllowedScopes 解析 client_credentials 模式允许的 scope 列表
 * @return []string - 允许的 scope 列表
 */
func (a *Application) GetAllowedScopes() []string {
	var scopes []string
	if a.AllowedScopes != "" {
		json.Unmarshal([]byte(a.AllowedScopes), &scopes)
	}
	return scopes
}

/*
 * SetAllowedScopes 将允许的 scope 列表序列化为 JSON 存储
 * @param scopes - 允许的 scope 列表
 */
func (a *Application) SetAllowedScopes(scopes []string) {
	data, _ := json.Marshal(scopes)
	a.AllowedScopes = string(data)
}

/*
 * ValidateUserAuthorizationScope 校验终端用户授权（授权码/设备流）请求的 scope
 * @param requestedScope - 空格分隔的 scope 字符串
 */
func (a *Application) ValidateUserAuthorizationScope(requestedScope string) bool {
	if strings.TrimSpace(requestedScope) == "" {
		return true
	}
	br := a.ParseAuthorizeScopeRequest(requestedScope)
	return len(br.InvalidScopes) == 0
}

/*
 * ValidateScope 校验请求的 scope 是否在 AllowedScopes 白名单内（通用）
 * @param requestedScope - 空格分隔的 scope 字符串
 * @return bool          - 全部允许返回 true
 */
func (a *Application) ValidateScope(requestedScope string) bool {
	if requestedScope == "" {
		return true
	}
	allowedScopes := a.GetAllowedScopes()
	if len(allowedScopes) == 0 {
		// If no allowed scopes configured, allow all scopes defined for the app
		allowedScopes = a.GetScopes()
	}
	if len(allowedScopes) == 0 {
		/* 未配置白名单时不默认放行，避免任意 scope 越权 */
		return requestedScope == ""
	}

	// Check each requested scope
	requestedScopes := splitScopes(requestedScope)
	for _, rs := range requestedScopes {
		found := false
		for _, as := range allowedScopes {
			if rs == as {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

/*
 * splitScopes 按空格分割 scope 字符串（内部工具函数）
 * @param scope - 空格分隔的 scope 字符串
 * @return []string - scope 切片
 */
func splitScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

/* TableName 指定 GORM 表名为 applications */
func (Application) TableName() string {
	return "applications"
}
