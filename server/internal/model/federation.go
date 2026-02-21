package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * FederatedProvider 联邦认证提供者模型
 * 功能：配置外部 OAuth2 提供者（如主站 SSO、GitHub 等），实现用户通过外部身份登录本系统
 *       支持自动创建用户、信任邮箱验证、同步资料等特性开关
 * 表名：federated_providers
 * 索引：name(唯一), slug(唯一)
 */
type FederatedProvider struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Name        string    `gorm:"size:100;not null;uniqueIndex" json:"name"` // 显示名称
	Slug        string    `gorm:"size:50;not null;uniqueIndex" json:"slug"`  // 唯一标识 e.g., "main-sso"
	Description string    `gorm:"size:500" json:"description,omitempty"`

	// OAuth2 Configuration
	AuthURL      string `gorm:"size:500;not null" json:"auth_url"`     // 授权端点
	TokenURL     string `gorm:"size:500;not null" json:"token_url"`    // Token端点
	UserInfoURL  string `gorm:"size:500;not null" json:"userinfo_url"` // 用户信息端点
	ClientID     string `gorm:"size:200;not null" json:"client_id"`
	ClientSecret string `gorm:"size:500;not null" json:"-"` // 不返回给前端
	Scopes       string `gorm:"size:500" json:"scopes"`     // 空格分隔的scopes

	// Feature flags
	Enabled            bool `gorm:"default:true" json:"enabled"`
	AutoCreateUser     bool `gorm:"default:true" json:"auto_create_user"`     // 自动创建不存在的用户
	TrustEmailVerified bool `gorm:"default:true" json:"trust_email_verified"` // 信任外部系统的邮箱验证
	SyncProfile        bool `gorm:"default:true" json:"sync_profile"`         // 同步用户资料

	// Display
	IconURL    string `gorm:"size:500" json:"icon_url,omitempty"`
	ButtonText string `gorm:"size:100" json:"button_text,omitempty"`

	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (f *FederatedProvider) BeforeCreate(tx *gorm.DB) error {
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	return nil
}

/* TableName 指定 GORM 表名为 federated_providers */
func (FederatedProvider) TableName() string {
	return "federated_providers"
}

/*
 * FederatedIdentity 联邦身份关联模型
 * 功能：将本系统用户与外部提供者的身份信息进行关联
 *       存储外部用户 ID (sub)、外部邮箱、缓存数据和 Token
 * 表名：federated_identities
 * 索引：user_id, provider_id
 */
type FederatedIdentity struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	UserID        uuid.UUID `gorm:"type:uuid;index;not null" json:"user_id"`
	ProviderID    uuid.UUID `gorm:"type:uuid;index;not null" json:"provider_id"`
	ExternalID    string    `gorm:"size:255;not null" json:"external_id"` // 外部系统的用户ID (sub)
	ExternalEmail string    `gorm:"size:255" json:"external_email,omitempty"`

	// Cached external data
	ExternalData string `gorm:"type:text" json:"-"` // JSON格式的外部用户数据

	// Tokens (encrypted)
	AccessToken  string    `gorm:"size:2000" json:"-"`
	RefreshToken string    `gorm:"size:2000" json:"-"`
	TokenExpiry  time.Time `json:"-"`

	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	// Relations
	User     *User              `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Provider *FederatedProvider `gorm:"foreignKey:ProviderID" json:"provider,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (f *FederatedIdentity) BeforeCreate(tx *gorm.DB) error {
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	return nil
}

/* TableName 指定 GORM 表名为 federated_identities */
func (FederatedIdentity) TableName() string {
	return "federated_identities"
}

/*
 * TrustedApp 受信任应用模型
 * 功能：代表来自联邦系统的应用，可通过 API Key 验证 Token 和查询用户
 * 表名：trusted_apps
 * 索引：api_key(唯一), provider_id
 */
type TrustedApp struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Name       string    `gorm:"size:100;not null" json:"name"`
	ProviderID uuid.UUID `gorm:"type:uuid;index" json:"provider_id,omitempty"` // 关联的联邦提供者

	// API Key for verification requests
	APIKey    string `gorm:"size:100;uniqueIndex;not null" json:"-"`
	APISecret string `gorm:"size:200;not null" json:"-"`

	// Permissions
	CanVerifyTokens bool `gorm:"default:true" json:"can_verify_tokens"`
	CanReadUsers    bool `gorm:"default:false" json:"can_read_users"`

	Enabled   bool      `gorm:"default:true" json:"enabled"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	// Relations
	Provider *FederatedProvider `gorm:"foreignKey:ProviderID" json:"provider,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (t *TrustedApp) BeforeCreate(tx *gorm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	return nil
}

/* TableName 指定 GORM 表名为 trusted_apps */
func (TrustedApp) TableName() string {
	return "trusted_apps"
}
