package model

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * PasswordReset 密码重置记录模型
 * 功能：存储密码重置令牌及其元数据，支持过期、使用状态跟踪和 IP 审计
 * 表名：password_resets
 * 索引：token(唯一), user_id
 */
type PasswordReset struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;index;not null" json:"user_id"`
	Token     string     `gorm:"uniqueIndex;size:100;not null" json:"-"`
	ExpiresAt time.Time  `gorm:"not null" json:"expires_at"`
	Used      bool       `gorm:"default:false" json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	IPAddress string     `gorm:"size:50" json:"ip_address,omitempty"`
	UserAgent string     `gorm:"size:500" json:"user_agent,omitempty"`
	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (p *PasswordReset) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

/* TableName 指定 GORM 表名为 password_resets */
func (PasswordReset) TableName() string {
	return "password_resets"
}

/* IsExpired 检查重置令牌是否已过期 */
func (p *PasswordReset) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

/* IsValid 检查重置令牌是否有效（未过期且未使用） */
func (p *PasswordReset) IsValid() bool {
	return !p.Used && !p.IsExpired()
}

/*
 * GenerateResetToken 生成安全随机重置令牌
 * 功能：使用 crypto/rand 生成 32 字节随机数，Hex 编码为 64 字符令牌
 * @return string - 64 字符的十六进制令牌
 * @return error  - 随机数生成失败时返回错误
 */
func GenerateResetToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
