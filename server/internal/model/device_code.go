package model

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * DeviceCodeStatus 设备授权请求状态枚举 (RFC 8628)
 * @value DeviceCodeStatusPending    - 等待用户授权
 * @value DeviceCodeStatusAuthorized - 用户已授权
 * @value DeviceCodeStatusDenied     - 用户已拒绝
 * @value DeviceCodeStatusExpired    - 已过期
 */
type DeviceCodeStatus string

const (
	DeviceCodeStatusPending    DeviceCodeStatus = "pending"
	DeviceCodeStatusAuthorized DeviceCodeStatus = "authorized"
	DeviceCodeStatusDenied     DeviceCodeStatus = "denied"
	DeviceCodeStatusExpired    DeviceCodeStatus = "expired"
)

/*
 * DeviceCode OAuth2 设备授权请求模型 (RFC 8628)
 * 功能：支持无浏览器设备（智能电视、CLI 工具等）的 OAuth2 授权流程
 *       设备显示 user_code → 用户在浏览器输入 → 设备轮询获取 token
 * 表名：device_codes
 * 索引：device_code(唯一), user_code(唯一), client_id, user_id
 */
type DeviceCode struct {
	ID                      uuid.UUID        `gorm:"type:uuid;primaryKey" json:"id"`
	DeviceCode              string           `gorm:"uniqueIndex;size:100;not null" json:"device_code"`
	UserCode                string           `gorm:"uniqueIndex;size:20;not null" json:"user_code"`
	ClientID                string           `gorm:"size:100;not null;index" json:"client_id"`
	Scope                   string           `gorm:"size:500" json:"scope"`
	VerificationURI         string           `gorm:"size:500;not null" json:"verification_uri"`
	VerificationURIComplete string           `gorm:"size:500" json:"verification_uri_complete"`
	ExpiresAt               time.Time        `gorm:"not null" json:"expires_at"`
	Interval                int              `gorm:"default:5" json:"interval"`
	UserID                  *uuid.UUID       `gorm:"type:uuid;index" json:"user_id"`
	Status                  DeviceCodeStatus `gorm:"size:20;default:pending" json:"status"`
	CreatedAt               time.Time        `gorm:"autoCreateTime" json:"created_at"`

	// Relations
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * 功能：自动生成 UUID、device_code、user_code 和默认状态
 * @param tx - 当前数据库事务
 */
func (d *DeviceCode) BeforeCreate(tx *gorm.DB) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	if d.DeviceCode == "" {
		d.DeviceCode = generateDeviceCode()
	}
	if d.UserCode == "" {
		d.UserCode = generateUserCode()
	}
	if d.Status == "" {
		d.Status = DeviceCodeStatusPending
	}
	if d.Interval == 0 {
		d.Interval = 5
	}
	return nil
}

/* IsExpired 检查设备码是否已过期 */
func (d *DeviceCode) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

/* IsPending 检查设备码是否仍在等待用户授权 */
func (d *DeviceCode) IsPending() bool {
	return d.Status == DeviceCodeStatusPending && !d.IsExpired()
}

/* IsAuthorized 检查设备码是否已被用户授权 */
func (d *DeviceCode) IsAuthorized() bool {
	return d.Status == DeviceCodeStatusAuthorized && !d.IsExpired()
}

/* IsDenied 检查设备码是否已被用户拒绝 */
func (d *DeviceCode) IsDenied() bool {
	return d.Status == DeviceCodeStatusDenied
}

/*
 * Authorize 标记设备码为已授权
 * @param userID - 授权用户的 UUID
 */
func (d *DeviceCode) Authorize(userID uuid.UUID) {
	d.UserID = &userID
	d.Status = DeviceCodeStatusAuthorized
}

/* Deny 标记设备码为已拒绝 */
func (d *DeviceCode) Deny() {
	d.Status = DeviceCodeStatusDenied
}

/* TableName 指定 GORM 表名为 device_codes */
func (DeviceCode) TableName() string {
	return "device_codes"
}

/*
 * generateDeviceCode 生成安全随机设备码
 * 功能：使用 crypto/rand 生成 32 字节随机数，Base64 URL 编码
 * @return string - 43 字符的随机设备码
 */
func generateDeviceCode() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

/*
 * generateUserCode 生成用户友好的验证码
 * 功能：生成 XXXX-XXXX 格式的 8 位码，使用不易混淆字符集（排除 0/O, 1/I/L）
 * @return string - 如 "WDJB-MJHT"
 */
func generateUserCode() string {
	// Use only unambiguous characters (no 0/O, 1/I/L)
	const chars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}

	code := make([]byte, 8)
	for i := 0; i < 8; i++ {
		code[i] = chars[int(b[i])%len(chars)]
	}

	// Format as XXXX-XXXX
	return string(code[:4]) + "-" + string(code[4:])
}

/*
 * NormalizeUserCode 标准化用户输入的验证码
 * 功能：转大写、移除连字符和空格，重新添加标准格式的连字符
 * @param code   - 用户输入的验证码
 * @return string - 标准化后的验证码，如 "WDJB-MJHT"
 */
func NormalizeUserCode(code string) string {
	code = strings.ToUpper(code)
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")

	// Re-add hyphen in the middle if length is 8
	if len(code) == 8 {
		return code[:4] + "-" + code[4:]
	}
	return code
}
