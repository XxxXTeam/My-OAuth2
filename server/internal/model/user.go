/*
 * Package model 数据模型层
 * 功能：定义所有数据库实体模型、枚举类型及其关联方法
 */
package model

import (
	"encoding/json"
	"server/pkg/password"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * UserRole 用户角色枚举
 * @value RoleAdmin - 管理员，拥有系统全部管理权限
 * @value RoleUser  - 普通用户，仅能管理个人信息
 */
type UserRole string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"
)

/*
 * User 用户模型
 * 功能：OAuth2 认证系统的核心用户实体，兼容 OIDC 标准声明（Standard Claims）
 * 表名：users
 * 索引：email(唯一), username(唯一), external_id
 */
type User struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Email         string    `gorm:"uniqueIndex;size:255;not null" json:"email"`
	Username      string    `gorm:"uniqueIndex;size:100;not null" json:"username"`
	PasswordHash  string    `gorm:"size:255;not null" json:"-"`
	Role          UserRole  `gorm:"size:20;default:user" json:"role"`
	Avatar        string    `gorm:"size:500" json:"avatar,omitempty"`
	EmailVerified bool      `gorm:"default:false" json:"email_verified"`

	// OIDC Standard Claims
	GivenName     string     `gorm:"size:100" json:"given_name,omitempty"`  // 名
	FamilyName    string     `gorm:"size:100" json:"family_name,omitempty"` // 姓
	Nickname      string     `gorm:"size:100" json:"nickname,omitempty"`    // 昵称
	Gender        string     `gorm:"size:20" json:"gender,omitempty"`       // male/female/other
	Birthdate     *time.Time `json:"birthdate,omitempty"`                   // 生日
	PhoneNumber   string     `gorm:"size:50" json:"phone_number,omitempty"` // 电话
	PhoneVerified bool       `gorm:"default:false" json:"phone_number_verified"`
	Address       string     `gorm:"type:text" json:"address,omitempty"` // JSON格式地址
	Locale        string     `gorm:"size:10" json:"locale,omitempty"`    // 语言偏好 zh-CN, en-US
	Zoneinfo      string     `gorm:"size:50" json:"zoneinfo,omitempty"`  // 时区 Asia/Shanghai
	Website       string     `gorm:"size:255" json:"website,omitempty"`  // 个人网站
	Bio           string     `gorm:"type:text" json:"bio,omitempty"`     // 个人简介

	// Social Accounts (JSON格式存储)
	SocialAccounts string `gorm:"type:text" json:"-"` // {"github":"xxx","twitter":"xxx"}

	// Profile Completion
	ProfileCompleted bool `gorm:"default:false" json:"profile_completed"` // 是否完成资料设置

	// Extended/Custom Fields (预留扩展字段)
	Metadata   string `gorm:"type:text" json:"-"`                   // JSON格式自定义元数据
	Tags       string `gorm:"size:500" json:"-"`                    // 用户标签，逗号分隔
	Department string `gorm:"size:100" json:"department,omitempty"` // 部门
	JobTitle   string `gorm:"size:100" json:"job_title,omitempty"`  // 职位
	Company    string `gorm:"size:200" json:"company,omitempty"`    // 公司
	EmployeeID string `gorm:"size:50" json:"employee_id,omitempty"` // 工号

	// Status & Security
	Status       string     `gorm:"size:20;default:active" json:"status"` // active, suspended, pending
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP  string     `gorm:"size:50" json:"last_login_ip,omitempty"`
	FailedLogins int        `gorm:"default:0" json:"-"`
	LockedUntil  *time.Time `json:"-"`

	// External Identity
	ExternalID     string `gorm:"size:255;index" json:"external_id,omitempty"` // 外部系统ID
	ExternalSource string `gorm:"size:50" json:"external_source,omitempty"`    // 来源系统

	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	// Relations
	Applications []Application `gorm:"foreignKey:UserID" json:"applications,omitempty"`
}

/* IsAdmin 判断用户是否为管理员角色 */
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

/*
 * BeforeCreate GORM 创建前钩子
 * 功能：自动生成 UUID 主键
 * @param tx - 当前数据库事务
 */
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

/* TableName 指定 GORM 表名为 users */
func (User) TableName() string {
	return "users"
}

/* SocialAccountsMap 社交账号映射类型，key 为平台名，value 为账号标识 */
type SocialAccountsMap map[string]string

/*
 * GetSocialAccounts 解析 JSON 格式的社交账号数据
 * @return SocialAccountsMap - 社交账号映射，如 {"github":"user","twitter":"@user"}
 */
func (u *User) GetSocialAccounts() SocialAccountsMap {
	var accounts SocialAccountsMap
	if u.SocialAccounts != "" {
		json.Unmarshal([]byte(u.SocialAccounts), &accounts)
	}
	if accounts == nil {
		accounts = make(SocialAccountsMap)
	}
	return accounts
}

/*
 * SetSocialAccounts 将社交账号映射序列化为 JSON 存储
 * @param accounts - 社交账号映射
 */
func (u *User) SetSocialAccounts(accounts SocialAccountsMap) {
	data, _ := json.Marshal(accounts)
	u.SocialAccounts = string(data)
}

/*
 * AddressInfo OIDC 地址声明结构
 * 功能：符合 OpenID Connect Core 5.1.1 地址声明规范
 */
type AddressInfo struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"` // 城市
	Region        string `json:"region,omitempty"`   // 省/州
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

/*
 * GetAddress 解析 JSON 格式的地址数据
 * @return *AddressInfo - OIDC 地址声明结构体指针
 */
func (u *User) GetAddress() *AddressInfo {
	var addr AddressInfo
	if u.Address != "" {
		json.Unmarshal([]byte(u.Address), &addr)
	}
	return &addr
}

/*
 * SetAddress 将地址结构体序列化为 JSON 存储
 * @param addr - OIDC 地址声明结构体
 */
func (u *User) SetAddress(addr *AddressInfo) {
	data, _ := json.Marshal(addr)
	u.Address = string(data)
}

/*
 * GetFullName 获取用户全名
 * 功能：优先返回「姓+名」，其次昵称，最后用户名
 * @return string - 用户显示名称
 */
func (u *User) GetFullName() string {
	if u.FamilyName != "" && u.GivenName != "" {
		return u.FamilyName + u.GivenName
	}
	if u.Nickname != "" {
		return u.Nickname
	}
	return u.Username
}

/*
 * ParseUUID 将字符串解析为 UUID
 * @param s - UUID 字符串
 * @return uuid.UUID - 解析后的 UUID
 * @return error     - 格式无效时返回错误
 */
func ParseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

/* MetadataMap 自定义元数据映射类型，支持任意 JSON 结构 */
type MetadataMap map[string]interface{}

/*
 * GetMetadata 解析 JSON 格式的自定义元数据
 * @return MetadataMap - 元数据键值对
 */
func (u *User) GetMetadata() MetadataMap {
	var meta MetadataMap
	if u.Metadata != "" {
		json.Unmarshal([]byte(u.Metadata), &meta)
	}
	if meta == nil {
		meta = make(MetadataMap)
	}
	return meta
}

/*
 * SetMetadata 将元数据映射序列化为 JSON 存储
 * @param meta - 自定义元数据映射
 */
func (u *User) SetMetadata(meta MetadataMap) {
	data, _ := json.Marshal(meta)
	u.Metadata = string(data)
}

/*
 * GetTags 获取用户标签列表
 * @return []string - 标签切片，从逗号分隔字符串解析
 */
func (u *User) GetTags() []string {
	if u.Tags == "" {
		return []string{}
	}
	tags := []string{}
	for _, t := range splitTags(u.Tags) {
		if t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

/*
 * SetTags 设置用户标签
 * @param tags - 标签切片，将被合并为逗号分隔字符串存储
 */
func (u *User) SetTags(tags []string) {
	u.Tags = joinTags(tags)
}

/*
 * HasTag 检查用户是否拥有指定标签
 * @param tag - 要检查的标签名
 * @return bool - 存在返回 true
 */
func (u *User) HasTag(tag string) bool {
	for _, t := range u.GetTags() {
		if t == tag {
			return true
		}
	}
	return false
}

/* splitTags 按逗号分割标签字符串（内部工具函数） */
func splitTags(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

/* joinTags 将标签切片合并为逗号分隔字符串（内部工具函数） */
func joinTags(tags []string) string {
	return strings.Join(tags, ",")
}

/* IsActive 检查用户是否处于活跃状态（status 为空或 "active"） */
func (u *User) IsActive() bool {
	return u.Status == "" || u.Status == "active"
}

/* IsSuspended 检查用户是否被停用 */
func (u *User) IsSuspended() bool {
	return u.Status == "suspended"
}

/* IsLocked 检查用户账户是否被锁定（连续登录失败后的临时锁定） */
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

/*
 * SetPassword 对密码进行 bcrypt 哈希后存储
 * 功能：统一使用 password 包的 Hash 函数，确保 bcrypt cost 一致且受 72 字节限制保护
 * @param pwd - 明文密码
 * @return error - 哈希失败或密码过长时返回错误
 */
func (u *User) SetPassword(pwd string) error {
	hash, err := password.Hash(pwd)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	return nil
}

/*
 * CheckPassword 校验密码是否与存储的哈希匹配
 * 功能：统一使用 password 包的 Verify 函数，确保与 SetPassword 使用相同的哈希策略
 * @param pwd - 明文密码
 * @return bool - 匹配返回 true
 */
func (u *User) CheckPassword(pwd string) bool {
	return password.Verify(pwd, u.PasswordHash)
}
