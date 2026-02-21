package repository

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* 应用仓储层错误定义 */
var (
	ErrAppNotFound      = errors.New("application not found")
	ErrAppAlreadyExists = errors.New("application already exists")
)

/*
 * ApplicationRepository 应用数据仓储
 * 功能：封装 OAuth2 应用/客户端表的全部 CRUD 操作
 */
type ApplicationRepository struct {
	db *gorm.DB
}

/*
 * NewApplicationRepository 创建应用仓储实例
 * @param db - GORM 数据库连接
 */
func NewApplicationRepository(db *gorm.DB) *ApplicationRepository {
	return &ApplicationRepository{db: db}
}

/*
 * Create 创建新应用
 * 功能：自动生成 client_id 和 client_secret（如未设置）
 * @param app - 应用实体
 * @return error - client_id 重复时返回 ErrAppAlreadyExists
 */
func (r *ApplicationRepository) Create(app *model.Application) error {
	// Generate client_id and client_secret if not set
	if app.ClientID == "" {
		app.ClientID = generateClientID()
	}
	if app.ClientSecret == "" {
		app.ClientSecret = generateClientSecret()
	}

	result := r.db.Create(app)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return ErrAppAlreadyExists
		}
		return result.Error
	}
	return nil
}

/*
 * FindByID 根据 UUID 查找应用
 * @param id - 应用 UUID
 * @return *model.Application - 应用实体，未找到时返回 ErrAppNotFound
 */
func (r *ApplicationRepository) FindByID(id uuid.UUID) (*model.Application, error) {
	var app model.Application
	result := r.db.First(&app, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrAppNotFound
		}
		return nil, result.Error
	}
	return &app, nil
}

/*
 * FindByClientID 根据 client_id 查找应用
 * @param clientID - OAuth2 客户端 ID
 * @return *model.Application - 应用实体，未找到时返回 ErrAppNotFound
 */
func (r *ApplicationRepository) FindByClientID(clientID string) (*model.Application, error) {
	var app model.Application
	result := r.db.First(&app, "client_id = ?", clientID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrAppNotFound
		}
		return nil, result.Error
	}
	return &app, nil
}

/*
 * FindByUserID 查找用户拥有的所有应用
 * @param userID - 用户 UUID
 * @return []model.Application - 应用列表
 */
func (r *ApplicationRepository) FindByUserID(userID uuid.UUID) ([]model.Application, error) {
	var apps []model.Application
	result := r.db.Where("user_id = ?", userID).Find(&apps)
	if result.Error != nil {
		return nil, result.Error
	}
	return apps, nil
}

/*
 * Update 更新应用信息
 * @param app - 包含更新字段的应用实体
 */
func (r *ApplicationRepository) Update(app *model.Application) error {
	return r.db.Save(app).Error
}

/*
 * Delete 删除应用
 * @param id - 应用 UUID
 */
func (r *ApplicationRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.Application{}, "id = ?", id).Error
}

/*
 * ValidateCredentials 校验客户端凭证
 * @param clientID     - OAuth2 客户端 ID
 * @param clientSecret - OAuth2 客户端密钥
 * @return *model.Application - 验证通过返回应用实体，失败返回 ErrAppNotFound
 */
func (r *ApplicationRepository) ValidateCredentials(clientID, clientSecret string) (*model.Application, error) {
	var app model.Application
	result := r.db.First(&app, "client_id = ? AND client_secret = ?", clientID, clientSecret)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrAppNotFound
		}
		return nil, result.Error
	}
	return &app, nil
}

/* Count 返回应用总数 */
func (r *ApplicationRepository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&model.Application{}).Count(&count).Error
	return count, err
}

/*
 * FindAll 分页查询所有应用（预加载关联用户）
 * @param offset - 偏移量
 * @param limit  - 每页数量
 * @return []model.Application - 应用列表
 * @return int64               - 总数
 */
func (r *ApplicationRepository) FindAll(offset, limit int) ([]model.Application, int64, error) {
	var apps []model.Application
	var total int64

	if err := r.db.Model(&model.Application{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	if err := r.db.Preload("User").Offset(offset).Limit(limit).Order("created_at DESC").Find(&apps).Error; err != nil {
		return nil, 0, err
	}

	return apps, total, nil
}

/*
 * ResetSecret 重置应用的客户端密钥
 * @param id - 应用 UUID
 * @return string - 新生成的客户端密钥
 */
func (r *ApplicationRepository) ResetSecret(id uuid.UUID) (string, error) {
	newSecret := generateClientSecret()
	err := r.db.Model(&model.Application{}).Where("id = ?", id).Update("client_secret", newSecret).Error
	if err != nil {
		return "", err
	}
	return newSecret, nil
}

/* AppStats 应用统计数据结构 */
type AppStats struct {
	TotalAuthorizations int64
	ActiveTokens        int64
	TotalUsers          int64
	Last24hTokens       int64
}

/*
 * GetStats 获取应用统计数据
 * 功能：统计授权码总数、活跃令牌数、独立用户数和近 24h 令牌签发数
 * @param appID - 应用 UUID
 * @return *AppStats - 统计数据
 */
func (r *ApplicationRepository) GetStats(appID uuid.UUID) (*AppStats, error) {
	stats := &AppStats{}

	// First get the client_id for this app
	var app model.Application
	if err := r.db.First(&app, "id = ?", appID).Error; err != nil {
		return stats, err
	}
	clientID := app.ClientID

	// Count total authorization codes ever issued
	r.db.Model(&model.AuthorizationCode{}).Where("client_id = ?", clientID).Count(&stats.TotalAuthorizations)

	// Count active access tokens (not expired and not revoked)
	r.db.Model(&model.AccessToken{}).Where("client_id = ? AND expires_at > ? AND revoked = ?", clientID, time.Now(), false).Count(&stats.ActiveTokens)

	// Count unique users who have authorized this app
	r.db.Model(&model.AccessToken{}).Where("client_id = ?", clientID).Distinct("user_id").Count(&stats.TotalUsers)

	// Count tokens issued in last 24 hours
	last24h := time.Now().Add(-24 * time.Hour)
	r.db.Model(&model.AccessToken{}).Where("client_id = ? AND created_at > ?", clientID, last24h).Count(&stats.Last24hTokens)

	return stats, nil
}

/* generateClientID 生成 32 字符的随机客户端 ID（内部工具函数） */
func generateClientID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(bytes)
}

/* generateClientSecret 生成 64 字符的随机客户端密钥（内部工具函数） */
func generateClientSecret() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(bytes)
}
