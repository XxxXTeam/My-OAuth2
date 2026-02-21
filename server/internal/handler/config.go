package handler

import (
	"fmt"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"

	"github.com/gin-gonic/gin"
)

/*
 * ConfigHandler 系统配置请求处理器
 * 功能：处理系统配置的读取、更新、公开配置查询等 HTTP 请求
 */
type ConfigHandler struct {
	configRepo *repository.ConfigRepository
	cfg        *config.Config
}

/*
 * NewConfigHandler 创建配置处理器实例
 * @param configRepo - 配置仓储
 * @param cfg        - 系统配置（可选）
 */
func NewConfigHandler(configRepo *repository.ConfigRepository, cfg ...*config.Config) *ConfigHandler {
	h := &ConfigHandler{configRepo: configRepo}
	if len(cfg) > 0 {
		h.cfg = cfg[0]
	}
	return h
}

/*
 * GetConfig 获取单个配置值
 * @route GET /api/admin/config/:key
 */
func (h *ConfigHandler) GetConfig(c *gin.Context) {
	key := c.Param("key")
	value, err := h.configRepo.Get(key)
	if err != nil {
		NotFound(c, "Config not found")
		return
	}
	Success(c, gin.H{"key": key, "value": value})
}

/*
 * GetAllConfig 获取所有配置值
 * @route GET /api/admin/config
 */
func (h *ConfigHandler) GetAllConfig(c *gin.Context) {
	configs, err := h.configRepo.GetAll()
	if err != nil {
		InternalError(c, "Failed to get configs")
		return
	}
	Success(c, configs)
}

// SetConfig sets a config value
// PUT /api/admin/config/:key
func (h *ConfigHandler) SetConfig(c *gin.Context) {
	key := c.Param("key")

	var req struct {
		Value string `json:"value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	if err := h.configRepo.Set(key, req.Value); err != nil {
		InternalError(c, "Failed to set config")
		return
	}

	Success(c, gin.H{"key": key, "value": req.Value})
}

// SetConfigs sets multiple config values
// PUT /api/admin/config
func (h *ConfigHandler) SetConfigs(c *gin.Context) {
	var req map[string]string
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	for key, value := range req {
		if err := h.configRepo.Set(key, value); err != nil {
			InternalError(c, "Failed to set config: "+key)
			return
		}
	}

	Success(c, req)
}

// DeleteConfig deletes a config value
// DELETE /api/admin/config/:key
func (h *ConfigHandler) DeleteConfig(c *gin.Context) {
	key := c.Param("key")
	if err := h.configRepo.Delete(key); err != nil {
		InternalError(c, "Failed to delete config")
		return
	}
	Success(c, gin.H{"message": "Config deleted"})
}

// GetPublicConfig returns public config values (no auth required)
// GET /api/config
func (h *ConfigHandler) GetPublicConfig(c *gin.Context) {
	configs, err := h.configRepo.GetAll()
	if err != nil {
		InternalError(c, "Failed to get configs")
		return
	}

	// Only return public config keys
	publicKeys := []string{
		model.ConfigKeyFrontendURL,
		model.ConfigKeyServerURL,
		model.ConfigKeySiteName,
	}

	publicConfigs := make(map[string]string)
	for _, key := range publicKeys {
		if value, ok := configs[key]; ok {
			publicConfigs[key] = value
		}
	}

	/* 从运行时配置中追加注册开关 */
	if h.cfg != nil {
		publicConfigs["allow_registration"] = fmt.Sprintf("%v", h.cfg.Server.AllowRegistration)
	}

	Success(c, publicConfigs)
}
