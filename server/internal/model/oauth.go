package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * AuthorizationCode OAuth2 授权码模型
 * 功能：存储 Authorization Code Grant 流程中生成的临时授权码
 *       支持 PKCE (RFC 7636) 通过 CodeChallenge / CodeChallengeMethod 字段
 * 表名：authorization_codes
 * 索引：code(唯一), client_id, user_id
 */
type AuthorizationCode struct {
	ID                  uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Code                string    `gorm:"uniqueIndex;size:100;not null" json:"code"`
	ClientID            string    `gorm:"size:100;not null;index" json:"client_id"`
	UserID              uuid.UUID `gorm:"type:uuid;index" json:"user_id"`
	RedirectURI         string    `gorm:"size:500;not null" json:"redirect_uri"`
	Scope               string    `gorm:"size:500" json:"scope"`
	CodeChallenge       string    `gorm:"size:128" json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `gorm:"size:10" json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time `gorm:"not null" json:"expires_at"`
	Used                bool      `gorm:"default:false" json:"used"`
	CreatedAt           time.Time `gorm:"autoCreateTime" json:"created_at"`

	// Relations
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (a *AuthorizationCode) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}

/* IsExpired 检查授权码是否已过期 */
func (a *AuthorizationCode) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

/* IsValid 检查授权码是否有效（未过期且未使用） */
func (a *AuthorizationCode) IsValid() bool {
	return !a.IsExpired() && !a.Used
}

/* TableName 指定 GORM 表名为 authorization_codes */
func (AuthorizationCode) TableName() string {
	return "authorization_codes"
}

/*
 * AccessToken OAuth2 访问令牌模型
 * 功能：存储发放的 access_token 及其元数据
 *       UserID 可为空（client_credentials 模式无用户上下文）
 * 表名：access_tokens
 * 索引：token(唯一), client_id, user_id
 */
type AccessToken struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	Token     string     `gorm:"uniqueIndex;size:500;not null" json:"token"`
	ClientID  string     `gorm:"size:100;not null;index:idx_at_client_user,priority:1" json:"client_id"`
	UserID    *uuid.UUID `gorm:"type:uuid;index:idx_at_client_user,priority:2" json:"user_id"`
	Scope     string     `gorm:"size:500" json:"scope"`
	ExpiresAt time.Time  `gorm:"not null;index:idx_at_expires" json:"expires_at"`
	Revoked   bool       `gorm:"default:false;index:idx_at_revoked_expires" json:"revoked"`
	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`

	// Relations
	User         *User         `gorm:"foreignKey:UserID" json:"user,omitempty"`
	RefreshToken *RefreshToken `gorm:"foreignKey:AccessTokenID" json:"refresh_token,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (a *AccessToken) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}

/* IsExpired 检查访问令牌是否已过期 */
func (a *AccessToken) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

/* IsValid 检查访问令牌是否有效（未过期且未撤销） */
func (a *AccessToken) IsValid() bool {
	return !a.IsExpired() && !a.Revoked
}

/* TableName 指定 GORM 表名为 access_tokens */
func (AccessToken) TableName() string {
	return "access_tokens"
}

/*
 * RefreshToken OAuth2 刷新令牌模型
 * 功能：存储 refresh_token 及其关联关系
 *       AccessTokenID 可为空：
 *         - OAuth2 流程的 refresh_token 关联对应的 access_token
 *         - Auth 认证系统的 refresh_token（Token Rotation）不关联 access_token
 * 表名：refresh_tokens
 * 索引：token(唯一), access_token_id, user_id
 */
type RefreshToken struct {
	ID            uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	Token         string     `gorm:"uniqueIndex;size:500;not null" json:"token"`
	AccessTokenID *uuid.UUID `gorm:"type:uuid;index" json:"access_token_id"`
	UserID        *uuid.UUID `gorm:"type:uuid;index:idx_rt_user_revoked,priority:1" json:"user_id"`
	ExpiresAt     time.Time  `gorm:"not null;index:idx_rt_expires" json:"expires_at"`
	Revoked       bool       `gorm:"default:false;index:idx_rt_user_revoked,priority:2" json:"revoked"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	CreatedAt     time.Time  `gorm:"autoCreateTime" json:"created_at"`

	// Relations
	AccessToken *AccessToken `gorm:"foreignKey:AccessTokenID" json:"access_token,omitempty"`
	User        *User        `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (r *RefreshToken) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

/* IsExpired 检查刷新令牌是否已过期 */
func (r *RefreshToken) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

/* IsValid 检查刷新令牌是否有效（未过期且未撤销） */
func (r *RefreshToken) IsValid() bool {
	return !r.IsExpired() && !r.Revoked
}

/* TableName 指定 GORM 表名为 refresh_tokens */
func (RefreshToken) TableName() string {
	return "refresh_tokens"
}
