package handler

import (
	"strconv"

	ctx "server/internal/context"
	"server/internal/service"
	"server/pkg/audit"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/*
 * WebhookHandler Webhook 管理请求处理器
 * 功能：处理 Webhook 的创建、更新、删除、测试和投递历史查询等 HTTP 请求
 */
type WebhookHandler struct {
	webhookService *service.WebhookService
}

/*
 * NewWebhookHandler 创建 Webhook 处理器实例
 * @param webhookService - Webhook 服务
 */
func NewWebhookHandler(webhookService *service.WebhookService) *WebhookHandler {
	return &WebhookHandler{
		webhookService: webhookService,
	}
}

/* CreateWebhookRequest 创建 Webhook 请求体 */
type CreateWebhookRequest struct {
	URL    string `json:"url" binding:"required,url"`
	Secret string `json:"secret"`
	Events string `json:"events" binding:"required"` // Comma-separated: "user.registered,user.login"
}

/* UpdateWebhookRequest 更新 Webhook 请求体 */
type UpdateWebhookRequest struct {
	URL    string `json:"url" binding:"required,url"`
	Secret string `json:"secret"`
	Events string `json:"events" binding:"required"`
	Active bool   `json:"active"`
}

/*
 * CreateWebhook 为应用创建新的 Webhook
 * @route POST /api/apps/:id/webhooks
 */
func (h *WebhookHandler) CreateWebhook(c *gin.Context) {
	appIDStr := c.Param("id")
	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		BadRequest(c, "Invalid app ID")
		return
	}

	var req CreateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	webhook, err := h.webhookService.CreateWebhook(appID, req.URL, req.Secret, req.Events)
	if err != nil {
		InternalError(c, "Failed to create webhook")
		return
	}

	actorID := "unknown"
	if uid, ok := ctx.GetUserID(c); ok {
		actorID = uid.String()
	}
	audit.Log(audit.ActionAppCreate, audit.ResultSuccess, actorID, webhook.ID.String(), c.ClientIP(), "type", "webhook", "app_id", appID.String())

	// Don't return the secret
	webhook.Secret = ""
	Created(c, webhook)
}

// ListWebhooks lists all webhooks for an application
// GET /api/apps/:id/webhooks
func (h *WebhookHandler) ListWebhooks(c *gin.Context) {
	appIDStr := c.Param("id")
	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		BadRequest(c, "Invalid app ID")
		return
	}

	webhooks, err := h.webhookService.GetWebhooks(appID)
	if err != nil {
		InternalError(c, "Failed to fetch webhooks")
		return
	}

	// Clear secrets from response
	for i := range webhooks {
		webhooks[i].Secret = ""
	}

	Success(c, webhooks)
}

// UpdateWebhook updates a webhook
// PUT /api/apps/:id/webhooks/:webhook_id
func (h *WebhookHandler) UpdateWebhook(c *gin.Context) {
	webhookIDStr := c.Param("webhook_id")
	webhookID, err := uuid.Parse(webhookIDStr)
	if err != nil {
		BadRequest(c, "Invalid webhook ID")
		return
	}

	var req UpdateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	err = h.webhookService.UpdateWebhook(webhookID, req.URL, req.Secret, req.Events, req.Active)
	if err != nil {
		InternalError(c, "Failed to update webhook")
		return
	}

	Success(c, gin.H{"message": "Webhook updated successfully"})
}

// DeleteWebhook deletes a webhook
// DELETE /api/apps/:id/webhooks/:webhook_id
func (h *WebhookHandler) DeleteWebhook(c *gin.Context) {
	webhookIDStr := c.Param("webhook_id")
	webhookID, err := uuid.Parse(webhookIDStr)
	if err != nil {
		BadRequest(c, "Invalid webhook ID")
		return
	}

	err = h.webhookService.DeleteWebhook(webhookID)
	if err != nil {
		InternalError(c, "Failed to delete webhook")
		return
	}

	actorIDDel := "unknown"
	if uid, ok := ctx.GetUserID(c); ok {
		actorIDDel = uid.String()
	}
	audit.Log(audit.ActionAppDelete, audit.ResultSuccess, actorIDDel, webhookID.String(), c.ClientIP(), "type", "webhook")

	Success(c, gin.H{"message": "Webhook deleted successfully"})
}

// ListDeliveries lists delivery history for a webhook
// GET /api/apps/:id/webhooks/:webhook_id/deliveries
func (h *WebhookHandler) ListDeliveries(c *gin.Context) {
	webhookIDStr := c.Param("webhook_id")
	webhookID, err := uuid.Parse(webhookIDStr)
	if err != nil {
		BadRequest(c, "Invalid webhook ID")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	deliveries, total, err := h.webhookService.GetDeliveries(webhookID, page, limit)
	if err != nil {
		InternalError(c, "Failed to fetch deliveries")
		return
	}

	Success(c, gin.H{
		"deliveries": deliveries,
		"total":      total,
		"page":       page,
		"limit":      limit,
	})
}

// TestWebhook sends a test event to a specific webhook
// POST /api/apps/:id/webhooks/:webhook_id/test
func (h *WebhookHandler) TestWebhook(c *gin.Context) {
	webhookIDStr := c.Param("webhook_id")
	webhookID, err := uuid.Parse(webhookIDStr)
	if err != nil {
		BadRequest(c, "Invalid webhook ID")
		return
	}

	// Get user ID from context
	userID, _ := c.Get("user_id")
	userIDStr := ""
	if uid, ok := userID.(uuid.UUID); ok {
		userIDStr = uid.String()
	}

	// 直接投递到指定webhook
	err = h.webhookService.TestWebhook(webhookID, userIDStr)
	if err != nil {
		InternalError(c, "Failed to trigger test webhook: "+err.Error())
		return
	}

	Success(c, gin.H{"message": "Test webhook triggered successfully"})
}
