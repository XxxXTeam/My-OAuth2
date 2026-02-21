package repository

import (
	"strings"
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * WebhookRepository Webhook 数据仓储
 * 功能：封装 Webhook 配置和投递记录的全部 CRUD 操作
 */
type WebhookRepository struct {
	db *gorm.DB
}

/*
 * NewWebhookRepository 创建 Webhook 仓储实例
 * @param db - GORM 数据库连接
 */
func NewWebhookRepository(db *gorm.DB) *WebhookRepository {
	return &WebhookRepository{db: db}
}

/* Create 创建新的 Webhook 配置 */
func (r *WebhookRepository) Create(webhook *model.Webhook) error {
	return r.db.Create(webhook).Error
}

/*
 * FindByID 根据 UUID 查找 Webhook
 * @param id - Webhook UUID
 */
func (r *WebhookRepository) FindByID(id uuid.UUID) (*model.Webhook, error) {
	var webhook model.Webhook
	result := r.db.First(&webhook, "id = ?", id)
	if result.Error != nil {
		return nil, result.Error
	}
	return &webhook, nil
}

/*
 * FindByAppID 查找应用的所有 Webhook 配置
 * @param appID - 应用 UUID
 */
func (r *WebhookRepository) FindByAppID(appID uuid.UUID) ([]model.Webhook, error) {
	var webhooks []model.Webhook
	result := r.db.Where("app_id = ?", appID).Find(&webhooks)
	if result.Error != nil {
		return nil, result.Error
	}
	return webhooks, nil
}

/*
 * FindActiveByAppAndEvent 查找应用中订阅了指定事件的活跃 Webhook
 * 功能：先查询应用的所有活跃 Webhook，再按事件类型过滤（支持通配符 "*"）
 * @param appID - 应用 UUID
 * @param event - 事件类型
 */
func (r *WebhookRepository) FindActiveByAppAndEvent(appID uuid.UUID, event model.WebhookEvent) ([]model.Webhook, error) {
	var webhooks []model.Webhook

	// Get all active webhooks for the app
	result := r.db.Where("app_id = ? AND active = true", appID).Find(&webhooks)
	if result.Error != nil {
		return nil, result.Error
	}

	// Filter by event
	var matching []model.Webhook
	for _, w := range webhooks {
		events := strings.Split(w.Events, ",")
		for _, e := range events {
			if strings.TrimSpace(e) == string(event) || strings.TrimSpace(e) == "*" {
				matching = append(matching, w)
				break
			}
		}
	}

	return matching, nil
}

/* Update 更新 Webhook 配置 */
func (r *WebhookRepository) Update(webhook *model.Webhook) error {
	return r.db.Save(webhook).Error
}

/* Delete 删除 Webhook */
func (r *WebhookRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.Webhook{}, "id = ?", id).Error
}

/* DeleteByAppID 删除应用的所有 Webhook */
func (r *WebhookRepository) DeleteByAppID(appID uuid.UUID) error {
	return r.db.Delete(&model.Webhook{}, "app_id = ?", appID).Error
}

/* CreateDelivery 创建 Webhook 投递记录 */
func (r *WebhookRepository) CreateDelivery(delivery *model.WebhookDelivery) error {
	return r.db.Create(delivery).Error
}

/* UpdateDelivery 更新 Webhook 投递记录 */
func (r *WebhookRepository) UpdateDelivery(delivery *model.WebhookDelivery) error {
	return r.db.Save(delivery).Error
}

/*
 * FindPendingDeliveries 查找待重试的投递记录
 * 功能：查询未投递成功且到达重试时间的记录（最多 5 次重试）
 * @param limit - 最大返回数量
 */
func (r *WebhookRepository) FindPendingDeliveries(limit int) ([]model.WebhookDelivery, error) {
	var deliveries []model.WebhookDelivery
	result := r.db.Preload("Webhook").
		Where("delivered = false AND (next_retry_at IS NULL OR next_retry_at <= ?)", time.Now()).
		Where("attempts < 5"). // Max 5 retry attempts
		Order("created_at ASC").
		Limit(limit).
		Find(&deliveries)
	if result.Error != nil {
		return nil, result.Error
	}
	return deliveries, nil
}

/*
 * FindDeliveriesByWebhook 分页查询指定 Webhook 的投递记录
 * @param webhookID - Webhook UUID
 * @param offset    - 偏移量
 * @param limit     - 每页数量
 */
func (r *WebhookRepository) FindDeliveriesByWebhook(webhookID uuid.UUID, offset, limit int) ([]model.WebhookDelivery, int64, error) {
	var deliveries []model.WebhookDelivery
	var total int64

	r.db.Model(&model.WebhookDelivery{}).Where("webhook_id = ?", webhookID).Count(&total)

	result := r.db.Where("webhook_id = ?", webhookID).
		Order("created_at DESC").
		Offset(offset).Limit(limit).
		Find(&deliveries)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return deliveries, total, nil
}

/*
 * CountFailedDeliveries 统计 Webhook 近 24h 内的失败投递数
 * @param webhookID - Webhook UUID
 */
func (r *WebhookRepository) CountFailedDeliveries(webhookID uuid.UUID) (int64, error) {
	var count int64
	result := r.db.Model(&model.WebhookDelivery{}).
		Where("webhook_id = ? AND delivered = false AND created_at > ?", webhookID, time.Now().Add(-24*time.Hour)).
		Count(&count)
	return count, result.Error
}
