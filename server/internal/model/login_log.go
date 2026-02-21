package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * LoginType 登录类型枚举
 * @value LoginTypeDirect - 直接登录（通过 Web UI 输入账号密码）
 * @value LoginTypeOAuth  - OAuth2 授权登录
 * @value LoginTypeSDK    - SDK 接入登录
 */
type LoginType string

const (
	LoginTypeDirect LoginType = "direct" // Direct login via web UI
	LoginTypeOAuth  LoginType = "oauth"  // OAuth authorization login
	LoginTypeSDK    LoginType = "sdk"    // SDK login
)

/*
 * LoginLog 登录日志模型
 * 功能：记录每次登录尝试的详细信息，包括成功/失败、IP、用户代理等
 *       UserID 可为空（登录失败且用户不存在的情况）
 *       AppID  可为空（直接登录而非 OAuth 授权登录）
 * 表名：login_logs
 * 索引：user_id, app_id, created_at
 */
type LoginLog struct {
	ID            uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID        *uuid.UUID `gorm:"type:uuid;index" json:"user_id,omitempty"` // NULL for failed login with non-existent user
	AppID         *uuid.UUID `gorm:"type:uuid;index" json:"app_id,omitempty"`  // NULL for direct login
	LoginType     LoginType  `gorm:"size:20;not null" json:"login_type"`
	IPAddress     string     `gorm:"size:45" json:"ip_address"` // IPv6 compatible
	UserAgent     string     `gorm:"type:text" json:"user_agent"`
	Success       bool       `gorm:"not null" json:"success"`
	FailureReason string     `gorm:"size:200" json:"failure_reason,omitempty"`
	Email         string     `gorm:"size:255" json:"email,omitempty"` // Store attempted email for failed logins
	CreatedAt     time.Time  `gorm:"autoCreateTime;index" json:"created_at"`

	// Relations
	User *User        `gorm:"foreignKey:UserID" json:"user,omitempty"`
	App  *Application `gorm:"foreignKey:AppID" json:"app,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (l *LoginLog) BeforeCreate(tx *gorm.DB) error {
	if l.ID == uuid.Nil {
		l.ID = uuid.New()
	}
	return nil
}

/* TableName 指定 GORM 表名为 login_logs */
func (LoginLog) TableName() string {
	return "login_logs"
}

/* LoginStats 登录统计数据结构，用于管理后台仪表盘展示 */
type LoginStats struct {
	TotalLogins      int64 `json:"total_logins"`
	SuccessfulLogins int64 `json:"successful_logins"`
	FailedLogins     int64 `json:"failed_logins"`
	UniqueUsers      int64 `json:"unique_users"`
	Last24hLogins    int64 `json:"last_24h_logins"`
	Last7dLogins     int64 `json:"last_7d_logins"`
	DirectLogins     int64 `json:"direct_logins"`
	OAuthLogins      int64 `json:"oauth_logins"`
	SDKLogins        int64 `json:"sdk_logins"`
}

/* LoginTrend 登录趋势数据点，用于管理后台图表展示 */
type LoginTrend struct {
	Date       string `json:"date"`
	TotalCount int64  `json:"total_count"`
	Success    int64  `json:"success"`
	Failed     int64  `json:"failed"`
}
