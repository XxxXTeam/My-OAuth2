package model

import (
	"time"

	"github.com/google/uuid"
)

/*
 * SystemConfig 系统配置模型
 * 功能：存储系统级别的键值对配置，如站点名称、前端 URL、邮件模板等
 * 表名：system_configs
 * 索引：key(唯一)
 */
type SystemConfig struct {
	ID        uuid.UUID `gorm:"type:char(36);primaryKey" json:"id"`
	Key       string    `gorm:"type:varchar(100);uniqueIndex;not null" json:"key"`
	Value     string    `gorm:"type:text;not null" json:"value"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

/* 常用配置键名常量 */
const (
	ConfigKeyFrontendURL = "frontend_url"
	ConfigKeyServerURL   = "server_url"
	ConfigKeySiteName    = "site_name"
)

/* EmailTemplateKeyPrefix 邮件模板配置键前缀，完整键名为 "email_template:{name}" */
const EmailTemplateKeyPrefix = "email_template:"

/* 已知邮件模板名称常量 */
const (
	EmailTplPasswordReset        = "password_reset"
	EmailTplPasswordResetSuccess = "password_reset_success"
	EmailTplWelcome              = "welcome"
	EmailTplLoginAlert           = "login_alert"
	EmailTplEmailVerification    = "email_verification"
)

/*
 * EmailTemplate 邮件模板结构
 * 功能：序列化为 JSON 后存储在 SystemConfig.Value 中
 */
type EmailTemplate struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

/*
 * EmailTemplateConfigKey 拼接邮件模板的配置键名
 * @param name - 模板名称，如 "password_reset"
 * @return string - 完整键名，如 "email_template:password_reset"
 */
func EmailTemplateConfigKey(name string) string {
	return EmailTemplateKeyPrefix + name
}

/* AllEmailTemplateNames 返回所有已知邮件模板名称列表 */
func AllEmailTemplateNames() []string {
	return []string{
		EmailTplPasswordReset,
		EmailTplPasswordResetSuccess,
		EmailTplWelcome,
		EmailTplLoginAlert,
		EmailTplEmailVerification,
	}
}
