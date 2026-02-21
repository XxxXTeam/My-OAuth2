package handler

import (
	"net/http"

	"server/internal/config"

	"github.com/gin-gonic/gin"
)

/*
 * SystemConfigHandler 系统配置查看处理器
 * 功能：处理系统运行配置查看、配置热更新等管理员 HTTP 请求（隐藏敏感信息）
 */
type SystemConfigHandler struct {
	cfg *config.Config
}

/*
 * NewSystemConfigHandler 创建系统配置处理器实例
 * @param cfg - 系统配置
 */
func NewSystemConfigHandler(cfg *config.Config) *SystemConfigHandler {
	return &SystemConfigHandler{cfg: cfg}
}

/* SystemConfigResponse 系统配置响应结构（隐藏密码、密钥等敏感信息） */
type SystemConfigResponse struct {
	Server   config.ServerConfig `json:"server"`
	Database DatabaseConfigSafe  `json:"database"`
	JWT      JWTConfigSafe       `json:"jwt"`
	OAuth    config.OAuthConfig  `json:"oauth"`
	Email    EmailConfigSafe     `json:"email"`
	Social   config.SocialConfig `json:"social"`
}

/* DatabaseConfigSafe 安全的数据库配置结构（隐藏 DSN 敏感细节） */
type DatabaseConfigSafe struct {
	Driver             string `json:"driver"`
	DSN                string `json:"dsn"`
	MaxOpenConns       int    `json:"max_open_conns"`
	MaxIdleConns       int    `json:"max_idle_conns"`
	ConnMaxLifetimeMin int    `json:"conn_max_lifetime_min"`
	ConnMaxIdleTimeMin int    `json:"conn_max_idle_time_min"`
}

// JWTConfigSafe 安全的JWT配置（隐藏密钥）
type JWTConfigSafe struct {
	SecretConfigured    bool   `json:"secret_configured"`
	AccessTokenTTLMin   int    `json:"access_token_ttl_minutes"`
	RefreshTokenTTLDays int    `json:"refresh_token_ttl_days"`
	Issuer              string `json:"issuer"`
}

// EmailConfigSafe 安全的邮件配置（隐藏密码）
type EmailConfigSafe struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	PasswordSet bool   `json:"password_set"`
	From        string `json:"from"`
	FromName    string `json:"from_name"`
	UseTLS      bool   `json:"use_tls"`
}

// GetConfig 获取系统配置
// GET /api/admin/system/config
func (h *SystemConfigHandler) GetConfig(c *gin.Context) {
	resp := SystemConfigResponse{
		Server: h.cfg.Server,
		Database: DatabaseConfigSafe{
			Driver:             h.cfg.Database.Driver,
			DSN:                h.cfg.Database.DSN,
			MaxOpenConns:       h.cfg.Database.MaxOpenConns,
			MaxIdleConns:       h.cfg.Database.MaxIdleConns,
			ConnMaxLifetimeMin: h.cfg.Database.ConnMaxLifetimeMin,
			ConnMaxIdleTimeMin: h.cfg.Database.ConnMaxIdleTimeMin,
		},
		JWT: JWTConfigSafe{
			SecretConfigured:    h.cfg.JWT.Secret != "" && h.cfg.JWT.Secret != "your-super-secret-key-change-in-production",
			AccessTokenTTLMin:   h.cfg.JWT.AccessTokenTTLMin,
			RefreshTokenTTLDays: h.cfg.JWT.RefreshTokenTTLDays,
			Issuer:              h.cfg.JWT.Issuer,
		},
		OAuth: h.cfg.OAuth,
		Email: EmailConfigSafe{
			Host:        h.cfg.Email.Host,
			Port:        h.cfg.Email.Port,
			Username:    h.cfg.Email.Username,
			PasswordSet: h.cfg.Email.Password != "",
			From:        h.cfg.Email.From,
			FromName:    h.cfg.Email.FromName,
			UseTLS:      h.cfg.Email.UseTLS,
		},
		Social: h.cfg.Social,
	}

	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    resp,
	})
}

// UpdateConfigRequest 更新配置请求
type UpdateConfigRequest struct {
	Server *ServerUpdateConfig `json:"server,omitempty"`
	JWT    *JWTUpdateConfig    `json:"jwt,omitempty"`
	OAuth  *OAuthUpdateConfig  `json:"oauth,omitempty"`
	Email  *EmailUpdateConfig  `json:"email,omitempty"`
	Social *SocialUpdateConfig `json:"social,omitempty"`
}

type ServerUpdateConfig struct {
	Host              *string `json:"host,omitempty"`
	Port              *int    `json:"port,omitempty"`
	Mode              *string `json:"mode,omitempty"`
	AllowRegistration *bool   `json:"allow_registration,omitempty"`
}

type JWTUpdateConfig struct {
	Secret              *string `json:"secret,omitempty"`
	AccessTokenTTLMin   *int    `json:"access_token_ttl_minutes,omitempty"`
	RefreshTokenTTLDays *int    `json:"refresh_token_ttl_days,omitempty"`
	Issuer              *string `json:"issuer,omitempty"`
}

type OAuthUpdateConfig struct {
	AuthCodeTTLMin      *int    `json:"auth_code_ttl_minutes,omitempty"`
	AccessTokenTTLHours *int    `json:"access_token_ttl_hours,omitempty"`
	RefreshTokenTTLDays *int    `json:"refresh_token_ttl_days,omitempty"`
	FrontendURL         *string `json:"frontend_url,omitempty"`
}

type EmailUpdateConfig struct {
	Host     *string `json:"host,omitempty"`
	Port     *int    `json:"port,omitempty"`
	Username *string `json:"username,omitempty"`
	Password *string `json:"password,omitempty"`
	From     *string `json:"from,omitempty"`
	FromName *string `json:"from_name,omitempty"`
	UseTLS   *bool   `json:"use_tls,omitempty"`
}

type SocialUpdateConfig struct {
	Enabled *bool                       `json:"enabled,omitempty"`
	GitHub  *SocialProviderUpdateConfig `json:"github,omitempty"`
	Google  *SocialProviderUpdateConfig `json:"google,omitempty"`
}

type SocialProviderUpdateConfig struct {
	Enabled      *bool   `json:"enabled,omitempty"`
	ClientID     *string `json:"client_id,omitempty"`
	ClientSecret *string `json:"client_secret,omitempty"`
}

// UpdateConfig 更新系统配置
// PUT /api/admin/system/config
func (h *SystemConfigHandler) UpdateConfig(c *gin.Context) {
	var req UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 更新服务器配置
	if req.Server != nil {
		if req.Server.Host != nil && *req.Server.Host != "" {
			h.cfg.Server.Host = *req.Server.Host
		}
		if req.Server.Port != nil && *req.Server.Port > 0 {
			h.cfg.Server.Port = *req.Server.Port
		}
		if req.Server.Mode != nil && *req.Server.Mode != "" {
			h.cfg.Server.Mode = *req.Server.Mode
		}
		if req.Server.AllowRegistration != nil {
			h.cfg.Server.AllowRegistration = *req.Server.AllowRegistration
		}
	}

	// 更新JWT配置
	if req.JWT != nil {
		if req.JWT.Secret != nil && *req.JWT.Secret != "" {
			h.cfg.JWT.Secret = *req.JWT.Secret
		}
		if req.JWT.AccessTokenTTLMin != nil {
			h.cfg.JWT.AccessTokenTTLMin = *req.JWT.AccessTokenTTLMin
		}
		if req.JWT.RefreshTokenTTLDays != nil {
			h.cfg.JWT.RefreshTokenTTLDays = *req.JWT.RefreshTokenTTLDays
		}
		if req.JWT.Issuer != nil {
			h.cfg.JWT.Issuer = *req.JWT.Issuer
		}
	}

	// 更新OAuth配置
	if req.OAuth != nil {
		if req.OAuth.AuthCodeTTLMin != nil {
			h.cfg.OAuth.AuthCodeTTLMin = *req.OAuth.AuthCodeTTLMin
		}
		if req.OAuth.AccessTokenTTLHours != nil {
			h.cfg.OAuth.AccessTokenTTLHours = *req.OAuth.AccessTokenTTLHours
		}
		if req.OAuth.RefreshTokenTTLDays != nil {
			h.cfg.OAuth.RefreshTokenTTLDays = *req.OAuth.RefreshTokenTTLDays
		}
		if req.OAuth.FrontendURL != nil {
			h.cfg.OAuth.FrontendURL = *req.OAuth.FrontendURL
		}
	}

	// 更新邮件配置
	if req.Email != nil {
		if req.Email.Host != nil {
			h.cfg.Email.Host = *req.Email.Host
		}
		if req.Email.Port != nil {
			h.cfg.Email.Port = *req.Email.Port
		}
		if req.Email.Username != nil {
			h.cfg.Email.Username = *req.Email.Username
		}
		if req.Email.Password != nil && *req.Email.Password != "" {
			h.cfg.Email.Password = *req.Email.Password
		}
		if req.Email.From != nil {
			h.cfg.Email.From = *req.Email.From
		}
		if req.Email.FromName != nil {
			h.cfg.Email.FromName = *req.Email.FromName
		}
		if req.Email.UseTLS != nil {
			h.cfg.Email.UseTLS = *req.Email.UseTLS
		}
	}

	// 更新社交登录配置
	if req.Social != nil {
		if req.Social.Enabled != nil {
			h.cfg.Social.Enabled = *req.Social.Enabled
		}
		if req.Social.GitHub != nil {
			if req.Social.GitHub.Enabled != nil {
				h.cfg.Social.GitHub.Enabled = *req.Social.GitHub.Enabled
			}
			if req.Social.GitHub.ClientID != nil {
				h.cfg.Social.GitHub.ClientID = *req.Social.GitHub.ClientID
			}
			if req.Social.GitHub.ClientSecret != nil && *req.Social.GitHub.ClientSecret != "" {
				h.cfg.Social.GitHub.ClientSecret = *req.Social.GitHub.ClientSecret
			}
		}
		if req.Social.Google != nil {
			if req.Social.Google.Enabled != nil {
				h.cfg.Social.Google.Enabled = *req.Social.Google.Enabled
			}
			if req.Social.Google.ClientID != nil {
				h.cfg.Social.Google.ClientID = *req.Social.Google.ClientID
			}
			if req.Social.Google.ClientSecret != nil && *req.Social.Google.ClientSecret != "" {
				h.cfg.Social.Google.ClientSecret = *req.Social.Google.ClientSecret
			}
		}
	}

	// 保存配置到文件
	if err := h.cfg.Save(); err != nil {
		InternalError(c, "Failed to save configuration")
		return
	}

	// 重新计算时间 duration，确保内存中的 TTL 立即生效
	h.cfg.ComputeDurations()

	Success(c, gin.H{
		"message": "Configuration updated successfully. Some changes may require server restart.",
	})
}

// RegenerateJWTSecret 重新生成JWT密钥
// POST /api/admin/system/regenerate-jwt-secret
func (h *SystemConfigHandler) RegenerateJWTSecret(c *gin.Context) {
	h.cfg.JWT.Secret = config.GenerateRandomSecret(32)

	if err := h.cfg.Save(); err != nil {
		InternalError(c, "Failed to save configuration")
		return
	}

	Success(c, gin.H{
		"message": "JWT secret regenerated. All existing tokens will be invalidated. Server restart recommended.",
	})
}
