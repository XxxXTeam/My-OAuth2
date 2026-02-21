package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * UserAuthorization 用户授权记录模型
 * 功能：记录用户对应用的 OAuth2 授权状态，包括授权范围、时间和撤销信息
 *       用户可在个人中心查看和撤销已授权的应用
 * 表名：user_authorizations
 * 索引：user_id, app_id
 */
type UserAuthorization struct {
	ID           uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID       uuid.UUID  `gorm:"type:uuid;index;not null" json:"user_id"`
	AppID        uuid.UUID  `gorm:"type:uuid;index;not null" json:"app_id"`
	Scope        string     `gorm:"size:500" json:"scope"`
	GrantType    string     `gorm:"size:50;default:'authorization_code'" json:"grant_type"`
	AuthorizedAt time.Time  `gorm:"not null" json:"authorized_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Revoked      bool       `gorm:"default:false" json:"revoked"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	CreatedAt    time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time  `gorm:"autoUpdateTime" json:"updated_at"`

	// Relations
	User *User        `gorm:"foreignKey:UserID" json:"user,omitempty"`
	App  *Application `gorm:"foreignKey:AppID" json:"app,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * 功能：自动生成 UUID 和授权时间
 * @param tx - 当前数据库事务
 */
func (u *UserAuthorization) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.AuthorizedAt.IsZero() {
		u.AuthorizedAt = time.Now()
	}
	return nil
}

/* IsValid 检查授权是否有效（未撤销且未过期） */
func (u *UserAuthorization) IsValid() bool {
	if u.Revoked {
		return false
	}
	if u.ExpiresAt != nil && time.Now().After(*u.ExpiresAt) {
		return false
	}
	return true
}

/* Revoke 撤销授权，设置撤销标志和撤销时间 */
func (u *UserAuthorization) Revoke() {
	now := time.Now()
	u.Revoked = true
	u.RevokedAt = &now
}

/* TableName 指定 GORM 表名为 user_authorizations */
func (UserAuthorization) TableName() string {
	return "user_authorizations"
}

/* UserAuthorizationStats 授权统计数据结构，用于管理后台仪表盘展示 */
type UserAuthorizationStats struct {
	TotalAuthorizations   int64 `json:"total_authorizations"`
	UniqueUsers           int64 `json:"unique_users"`
	ActiveAuthorizations  int64 `json:"active_authorizations"`
	RevokedAuthorizations int64 `json:"revoked_authorizations"`
	Last24hAuthorizations int64 `json:"last_24h_authorizations"`
	Last7dAuthorizations  int64 `json:"last_7d_authorizations"`
}
