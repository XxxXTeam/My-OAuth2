package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * EmailTaskStatus 邮件任务状态枚举
 * 功能：跟踪邮件任务在队列中的生命周期
 */
type EmailTaskStatus string

const (
	EmailTaskPending    EmailTaskStatus = "pending"
	EmailTaskProcessing EmailTaskStatus = "processing"
	EmailTaskSent       EmailTaskStatus = "sent"
	EmailTaskFailed     EmailTaskStatus = "failed"
)

/*
 * EmailTaskType 邮件任务类型枚举
 * 功能：区分不同类型的邮件模板
 */
type EmailTaskType string

const (
	EmailTaskVerification  EmailTaskType = "verification"
	EmailTaskEmailChange   EmailTaskType = "email_change"
	EmailTaskPasswordReset EmailTaskType = "password_reset"
	EmailTaskResetSuccess  EmailTaskType = "reset_success"
	EmailTaskTest          EmailTaskType = "test"
)

/*
 * EmailTask 邮件任务模型
 * 功能：持久化邮件发送任务到数据库队列，由后台 worker 异步处理
 *       支持失败重试、状态跟踪和错误记录
 */
type EmailTask struct {
	ID          uuid.UUID       `gorm:"type:uuid;primaryKey" json:"id"`
	Type        EmailTaskType   `gorm:"size:30;not null;index" json:"type"`
	Recipient   string          `gorm:"size:255;not null" json:"recipient"`
	Subject     string          `gorm:"size:500" json:"subject"`
	TemplateData string         `gorm:"type:text" json:"template_data"`
	Status      EmailTaskStatus `gorm:"size:20;not null;default:pending;index" json:"status"`
	Attempts    int             `gorm:"default:0" json:"attempts"`
	MaxAttempts int             `gorm:"default:3" json:"max_attempts"`
	Error       string          `gorm:"type:text" json:"error,omitempty"`
	NextRetryAt *time.Time      `gorm:"index" json:"next_retry_at,omitempty"`
	ProcessedAt *time.Time      `json:"processed_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

func (t *EmailTask) BeforeCreate(tx *gorm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.MaxAttempts == 0 {
		t.MaxAttempts = 3
	}
	return nil
}
