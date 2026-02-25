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
	ID           uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ClientID     string    `gorm:"uniqueIndex;size:100;not null" json:"client_id"`
	ClientSecret string    `gorm:"size:255;not null" json:"-"`
	Name         string    `gorm:"size:200;not null" json:"name"`
	Description  string    `gorm:"type:text" json:"description,omitempty"`
	RedirectURIs string    `gorm:"type:text;not null" json:"-"` // JSON array stored as string
	Scopes       string    `gorm:"type:text" json:"-"`          // JSON array stored as string
	UserID       uuid.UUID `gorm:"type:uuid;index" json:"user_id"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime" json:"updated_at"`

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

/*
 * ValidateRedirectURI 校验回调地址是否在允许列表中
 * 功能：精确匹配 + 安全校验，阻止开放重定向攻击
 *       - 禁止 javascript:/data: 等危险协议
 *       - 禁止路径穿越（/../）
 *       - 禁止带用户信息的 URI（user@host）
 * @param uri  - 待校验的回调 URI
 * @return bool - 在允许列表中返回 true
 */
func (a *Application) ValidateRedirectURI(uri string) bool {
	/* 基础安全检查：阻止危险协议和路径穿越 */
	lower := strings.ToLower(uri)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "vbscript:") ||
		strings.Contains(uri, "/../") ||
		strings.Contains(uri, "/..\\") ||
		strings.Contains(uri, "@") {
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
 * SupportsGrantType 检查应用是否支持指定的授权类型
 * @param grantType - 待检查的 grant_type
 * @return bool     - 支持返回 true
 */
func (a *Application) SupportsGrantType(grantType string) bool {
	for _, gt := range a.GetGrantTypes() {
		if gt == grantType {
			return true
		}
	}
	return false
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
 * ValidateScope 校验请求的 scope 是否在允许范围内
 * 功能：用于 client_credentials 模式的 scope 校验
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
		return true // No restrictions
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
