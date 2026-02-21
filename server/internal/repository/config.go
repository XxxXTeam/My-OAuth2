package repository

import (
	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * ConfigRepository 系统配置数据仓储
 * 功能：封装系统配置表的键值对 CRUD 操作
 */
type ConfigRepository struct {
	db *gorm.DB
}

/*
 * NewConfigRepository 创建配置仓储实例
 * @param db - GORM 数据库连接
 */
func NewConfigRepository(db *gorm.DB) *ConfigRepository {
	return &ConfigRepository{db: db}
}

/*
 * Get 根据键名获取配置值
 * @param key    - 配置键名
 * @return string - 配置值
 */
func (r *ConfigRepository) Get(key string) (string, error) {
	var config model.SystemConfig
	result := r.db.First(&config, "key = ?", key)
	if result.Error != nil {
		return "", result.Error
	}
	return config.Value, nil
}

/*
 * Set 创建或更新配置值（upsert 语义）
 * @param key   - 配置键名
 * @param value - 配置值
 */
func (r *ConfigRepository) Set(key, value string) error {
	var config model.SystemConfig
	result := r.db.First(&config, "key = ?", key)

	if result.Error == gorm.ErrRecordNotFound {
		// Create new config
		config = model.SystemConfig{
			ID:    uuid.New(),
			Key:   key,
			Value: value,
		}
		return r.db.Create(&config).Error
	}

	if result.Error != nil {
		return result.Error
	}

	// Update existing config
	return r.db.Model(&config).Update("value", value).Error
}

/*
 * GetAll 获取所有配置键值对
 * @return map[string]string - 键名 → 配置值映射
 */
func (r *ConfigRepository) GetAll() (map[string]string, error) {
	var configs []model.SystemConfig
	result := r.db.Find(&configs)
	if result.Error != nil {
		return nil, result.Error
	}

	configMap := make(map[string]string)
	for _, c := range configs {
		configMap[c.Key] = c.Value
	}
	return configMap, nil
}

/*
 * Delete 删除指定键名的配置
 * @param key - 配置键名
 */
func (r *ConfigRepository) Delete(key string) error {
	return r.db.Delete(&model.SystemConfig{}, "key = ?", key).Error
}
