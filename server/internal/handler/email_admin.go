package handler

import (
	"encoding/json"
	"net/http"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/pkg/email"

	"github.com/gin-gonic/gin"
)

/*
 * EmailAdminHandler 邮件管理请求处理器
 * 功能：处理 SMTP 连接测试、测试邮件发送、邮件模板管理、SMTP 配置热加载等管理员 HTTP 请求
 */
type EmailAdminHandler struct {
	emailService *email.Service
	configRepo   *repository.ConfigRepository
	cfg          *config.Config
}

/*
 * NewEmailAdminHandler 创建邮件管理处理器实例
 * @param emailService - 邮件服务
 * @param configRepo   - 配置仓储
 * @param cfg          - 系统配置
 */
func NewEmailAdminHandler(emailService *email.Service, configRepo *repository.ConfigRepository, cfg *config.Config) *EmailAdminHandler {
	return &EmailAdminHandler{
		emailService: emailService,
		configRepo:   configRepo,
		cfg:          cfg,
	}
}

/* SetEmailService 更新邮件服务实例（SMTP 配置热加载时调用） */
func (h *EmailAdminHandler) SetEmailService(svc *email.Service) {
	h.emailService = svc
}

/*
 * TestConnection 测试 SMTP 连接
 * @route POST /api/admin/email/test-connection
 */
func (h *EmailAdminHandler) TestConnection(c *gin.Context) {
	if h.emailService == nil {
		BadRequest(c, "Email service not configured. Please configure SMTP settings first.")
		return
	}

	if err := h.emailService.TestConnection(); err != nil {
		c.JSON(http.StatusOK, Response{
			Success: false,
			Error:   &ErrorInfo{Code: "SMTP_ERROR", Message: err.Error()},
		})
		return
	}

	Success(c, gin.H{"message": "SMTP connection successful"})
}

// SendTestEmailRequest 发送测试邮件请求
type SendTestEmailRequest struct {
	To string `json:"to" binding:"required,email"`
}

// SendTestEmail 发送测试邮件
// POST /api/admin/email/test
func (h *EmailAdminHandler) SendTestEmail(c *gin.Context) {
	if h.emailService == nil {
		BadRequest(c, "Email service not configured. Please configure SMTP settings first.")
		return
	}

	var req SendTestEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	if err := h.emailService.SendTestEmail(req.To); err != nil {
		c.JSON(http.StatusOK, Response{
			Success: false,
			Error:   &ErrorInfo{Code: "SEND_FAILED", Message: err.Error()},
		})
		return
	}

	Success(c, gin.H{"message": "Test email sent successfully to " + req.To})
}

// TemplateInfo 模板信息
type TemplateInfo struct {
	Name       string `json:"name"`
	Subject    string `json:"subject"`
	Body       string `json:"body"`
	IsCustom   bool   `json:"is_custom"`
	HasDefault bool   `json:"has_default"`
}

// ListTemplates 获取所有邮件模板
// GET /api/admin/email/templates
func (h *EmailAdminHandler) ListTemplates(c *gin.Context) {
	if h.emailService == nil {
		BadRequest(c, "Email service not configured")
		return
	}

	names := model.AllEmailTemplateNames()
	templates := make([]TemplateInfo, 0, len(names))

	for _, name := range names {
		tpl := h.emailService.GetTemplate(name)
		defaultTpl := h.emailService.GetDefaultTemplate(name)
		isCustom := h.emailService.HasCustomTemplate(name)

		templates = append(templates, TemplateInfo{
			Name:       name,
			Subject:    tpl.Subject,
			Body:       tpl.Body,
			IsCustom:   isCustom,
			HasDefault: defaultTpl.Body != "",
		})
	}

	Success(c, gin.H{"templates": templates})
}

// GetTemplate 获取单个模板详情
// GET /api/admin/email/templates/:name
func (h *EmailAdminHandler) GetTemplate(c *gin.Context) {
	if h.emailService == nil {
		BadRequest(c, "Email service not configured")
		return
	}

	name := c.Param("name")
	tpl := h.emailService.GetTemplate(name)
	if tpl == nil || tpl.Body == "" {
		NotFound(c, "Template not found")
		return
	}

	defaultTpl := h.emailService.GetDefaultTemplate(name)
	isCustom := h.emailService.HasCustomTemplate(name)

	Success(c, gin.H{
		"template": TemplateInfo{
			Name:       name,
			Subject:    tpl.Subject,
			Body:       tpl.Body,
			IsCustom:   isCustom,
			HasDefault: defaultTpl.Body != "",
		},
		"default_subject": defaultTpl.Subject,
		"default_body":    defaultTpl.Body,
	})
}

// UpdateTemplateRequest 更新模板请求
type UpdateTemplateRequest struct {
	Subject string `json:"subject" binding:"required"`
	Body    string `json:"body" binding:"required"`
}

// UpdateTemplate 更新指定模板
// POST /api/admin/email/templates/:name
func (h *EmailAdminHandler) UpdateTemplate(c *gin.Context) {
	if h.emailService == nil {
		BadRequest(c, "Email service not configured")
		return
	}

	name := c.Param("name")

	// 验证模板名称是否合法
	validNames := model.AllEmailTemplateNames()
	valid := false
	for _, n := range validNames {
		if n == name {
			valid = true
			break
		}
	}
	if !valid {
		BadRequest(c, "Invalid template name: "+name)
		return
	}

	var req UpdateTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 更新内存模板
	h.emailService.SetCustomTemplate(name, req.Subject, req.Body)

	// 持久化到 DB
	tplData := model.EmailTemplate{Subject: req.Subject, Body: req.Body}
	data, _ := json.Marshal(tplData)
	key := model.EmailTemplateConfigKey(name)
	if err := h.configRepo.Set(key, string(data)); err != nil {
		InternalError(c, "Template updated in memory but failed to persist: "+err.Error())
		return
	}

	Success(c, gin.H{"message": "Template updated successfully"})
}

// ResetTemplate 重置模板为默认值
// POST /api/admin/email/templates/:name/reset
func (h *EmailAdminHandler) ResetTemplate(c *gin.Context) {
	if h.emailService == nil {
		BadRequest(c, "Email service not configured")
		return
	}

	name := c.Param("name")

	// 删除自定义模板
	h.emailService.RemoveCustomTemplate(name)

	// 从 DB 删除
	key := model.EmailTemplateConfigKey(name)
	_ = h.configRepo.Delete(key)

	// 返回默认模板
	defaultTpl := h.emailService.GetDefaultTemplate(name)
	Success(c, gin.H{
		"message": "Template reset to default",
		"template": TemplateInfo{
			Name:       name,
			Subject:    defaultTpl.Subject,
			Body:       defaultTpl.Body,
			IsCustom:   false,
			HasDefault: true,
		},
	})
}

// UpdateEmailConfig 更新邮件 SMTP 配置并热加载
// POST /api/admin/email/config
func (h *EmailAdminHandler) UpdateEmailConfig(c *gin.Context) {
	var req EmailUpdateConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 更新 cfg
	if req.Host != nil {
		h.cfg.Email.Host = *req.Host
	}
	if req.Port != nil {
		h.cfg.Email.Port = *req.Port
	}
	if req.Username != nil {
		h.cfg.Email.Username = *req.Username
	}
	if req.Password != nil && *req.Password != "" {
		h.cfg.Email.Password = *req.Password
	}
	if req.From != nil {
		h.cfg.Email.From = *req.From
	}
	if req.FromName != nil {
		h.cfg.Email.FromName = *req.FromName
	}
	if req.UseTLS != nil {
		h.cfg.Email.UseTLS = *req.UseTLS
	}

	// 持久化
	if err := h.cfg.Save(); err != nil {
		InternalError(c, "Failed to save configuration")
		return
	}

	// 热加载邮件服务
	if h.emailService != nil && h.cfg.Email.Host != "" {
		h.emailService.UpdateConfig(&email.Config{
			Host:     h.cfg.Email.Host,
			Port:     h.cfg.Email.Port,
			Username: h.cfg.Email.Username,
			Password: h.cfg.Email.Password,
			From:     h.cfg.Email.From,
			FromName: h.cfg.Email.FromName,
			UseTLS:   h.cfg.Email.UseTLS,
		})
	}

	Success(c, gin.H{"message": "Email configuration updated successfully"})
}

// GetEmailConfig 获取当前邮件配置（隐藏密码）
// GET /api/admin/email/config
func (h *EmailAdminHandler) GetEmailConfig(c *gin.Context) {
	Success(c, gin.H{
		"host":         h.cfg.Email.Host,
		"port":         h.cfg.Email.Port,
		"username":     h.cfg.Email.Username,
		"password_set": h.cfg.Email.Password != "",
		"from":         h.cfg.Email.From,
		"from_name":    h.cfg.Email.FromName,
		"use_tls":      h.cfg.Email.UseTLS,
		"configured":   h.cfg.Email.Host != "",
	})
}
