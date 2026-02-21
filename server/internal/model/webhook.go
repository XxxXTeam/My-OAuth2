package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * WebhookEvent Webhook 事件类型枚举
 * 功能：定义可触发 Webhook 回调的事件类型
 * @value WebhookEventUserRegistered  - 用户注册
 * @value WebhookEventUserLogin       - 用户登录
 * @value WebhookEventUserUpdated     - 用户信息更新
 * @value WebhookEventOAuthAuthorized - OAuth2 授权同意
 * @value WebhookEventOAuthRevoked    - OAuth2 授权撤销
 * @value WebhookEventTokenIssued     - 令牌签发
 * @value WebhookEventTokenRefreshed  - 令牌刷新
 */
type WebhookEvent string

const (
	WebhookEventUserRegistered  WebhookEvent = "user.registered"
	WebhookEventUserLogin       WebhookEvent = "user.login"
	WebhookEventUserUpdated     WebhookEvent = "user.updated"
	WebhookEventOAuthAuthorized WebhookEvent = "oauth.authorized"
	WebhookEventOAuthRevoked    WebhookEvent = "oauth.revoked"
	WebhookEventTokenIssued     WebhookEvent = "token.issued"
	WebhookEventTokenRefreshed  WebhookEvent = "token.refreshed"
)

/*
 * Webhook Webhook 配置模型
 * 功能：定义应用的 Webhook 回调地址、签名密钥和订阅事件
 * 表名：webhooks
 * 索引：app_id
 */
type Webhook struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	AppID     uuid.UUID `gorm:"type:uuid;index;not null" json:"app_id"`
	URL       string    `gorm:"size:500;not null" json:"url"`
	Secret    string    `gorm:"size:100" json:"secret,omitempty"` // For signing payloads
	Events    string    `gorm:"size:500" json:"events"`           // Comma-separated events
	Active    bool      `gorm:"default:true" json:"active"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	// Relations
	App *Application `gorm:"foreignKey:AppID" json:"app,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (w *Webhook) BeforeCreate(tx *gorm.DB) error {
	if w.ID == uuid.Nil {
		w.ID = uuid.New()
	}
	return nil
}

/* TableName 指定 GORM 表名为 webhooks */
func (Webhook) TableName() string {
	return "webhooks"
}

/*
 * WebhookDelivery Webhook 投递记录模型
 * 功能：记录每次 Webhook 回调的投递状态、响应代码和重试信息
 * 表名：webhook_deliveries
 * 索引：webhook_id
 */
type WebhookDelivery struct {
	ID          uuid.UUID    `gorm:"type:uuid;primaryKey" json:"id"`
	WebhookID   uuid.UUID    `gorm:"type:uuid;index;not null" json:"webhook_id"`
	Event       WebhookEvent `gorm:"size:50;not null" json:"event"`
	Payload     string       `gorm:"type:text" json:"payload"`
	StatusCode  int          `json:"status_code"`
	Response    string       `gorm:"type:text" json:"response,omitempty"`
	Error       string       `gorm:"size:500" json:"error,omitempty"`
	Delivered   bool         `gorm:"default:false" json:"delivered"`
	Attempts    int          `gorm:"default:0" json:"attempts"`
	NextRetryAt *time.Time   `json:"next_retry_at,omitempty"`
	DeliveredAt *time.Time   `json:"delivered_at,omitempty"`
	CreatedAt   time.Time    `gorm:"autoCreateTime" json:"created_at"`

	// Relations
	Webhook *Webhook `gorm:"foreignKey:WebhookID" json:"webhook,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (d *WebhookDelivery) BeforeCreate(tx *gorm.DB) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	return nil
}

/* TableName 指定 GORM 表名为 webhook_deliveries */
func (WebhookDelivery) TableName() string {
	return "webhook_deliveries"
}

/*
 * WebhookPayload Webhook 回调负载结构
 * 功能：定义发送给 Webhook 端点的 JSON 负载格式
 */
type WebhookPayload struct {
	Event     WebhookEvent   `json:"event"`
	Timestamp time.Time      `json:"timestamp"`
	AppID     string         `json:"app_id"`
	Data      map[string]any `json:"data"`
}
