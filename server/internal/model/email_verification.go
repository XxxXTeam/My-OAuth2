package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * EmailVerification 邮箱验证记录模型
 * 功能：存储邮箱验证/更换令牌，支持当前邮箱验证和更换新邮箱两种场景
 *       Email 字段可能是当前邮箱（验证）或新邮箱（更换）
 * 表名：email_verifications
 * 索引：token(唯一), user_id
 */
type EmailVerification struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;index;not null" json:"user_id"`
	Email     string     `gorm:"size:255;not null" json:"email"`         // 要验证的邮箱（可能是新邮箱）
	Token     string     `gorm:"uniqueIndex;size:100;not null" json:"-"` // 验证令牌
	ExpiresAt time.Time  `gorm:"not null" json:"expires_at"`
	Used      bool       `gorm:"default:false" json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (e *EmailVerification) BeforeCreate(tx *gorm.DB) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	return nil
}

/* TableName 指定 GORM 表名为 email_verifications */
func (EmailVerification) TableName() string {
	return "email_verifications"
}

/* IsExpired 检查验证令牌是否已过期 */
func (e *EmailVerification) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

/* IsValid 检查验证令牌是否有效（未过期且未使用） */
func (e *EmailVerification) IsValid() bool {
	return !e.Used && !e.IsExpired()
}
