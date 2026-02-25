package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/logger"

	"github.com/google/uuid"
)

/* Webhook URL 安全校验错误 */
var (
	ErrWebhookURLInvalid  = errors.New("webhook URL must be a valid HTTP or HTTPS URL")
	ErrWebhookURLInsecure = errors.New("webhook URL must use HTTPS in production")
)

/*
 * WebhookService Webhook 事件服务
 * 功能：管理 Webhook 配置、触发事件回调、异步投递、失败重试和 HMAC-SHA256 签名
 */
type WebhookService struct {
	webhookRepo *repository.WebhookRepository
	httpClient  *http.Client
	log         *logger.Logger
}

/*
 * NewWebhookService 创建 Webhook 服务实例
 * @param webhookRepo - Webhook 数据仓储
 */
func NewWebhookService(webhookRepo *repository.WebhookRepository) *WebhookService {
	return &WebhookService{
		webhookRepo: webhookRepo,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				DisableKeepAlives:   false,
			},
		},
		log: logger.Default(),
	}
}

/*
 * CreateWebhook 为应用创建新的 Webhook 配置
 * @param appID  - 应用 UUID
 * @param url    - 回调 URL
 * @param secret - 签名密钥
 * @param events - 订阅事件（逗号分隔）
 */
func (s *WebhookService) CreateWebhook(appID uuid.UUID, webhookURL, secret, events string) (*model.Webhook, error) {
	/* 校验 Webhook URL 安全性 */
	if err := validateWebhookURL(webhookURL); err != nil {
		return nil, err
	}

	webhook := &model.Webhook{
		AppID:  appID,
		URL:    webhookURL,
		Secret: secret,
		Events: events,
		Active: true,
	}

	if err := s.webhookRepo.Create(webhook); err != nil {
		return nil, err
	}

	return webhook, nil
}

/*
 * validateWebhookURL 校验 Webhook 回调 URL 安全性
 * 规则：仅允许 http/https 协议，阻止 javascript:/data: 等危险协议
 *       生产环境建议仅允许 HTTPS
 */
func validateWebhookURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ErrWebhookURLInvalid
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return ErrWebhookURLInvalid
	}
	/*
	 * SSRF 防护：使用 net.IP 解析检测内部网络地址
	 * 覆盖 RFC 1918 私有地址 + 链路本地 + 环回 + 未指定 + 元数据服务
	 */
	host := parsed.Hostname()
	if host == "" {
		return ErrWebhookURLInvalid
	}
	/* 先检查主机名（localhost 等无法 IP 解析） */
	if strings.EqualFold(host, "localhost") {
		return errors.New("webhook URL must not point to internal network addresses")
	}
	ip := net.ParseIP(host)
	if ip != nil && isPrivateIP(ip) {
		return errors.New("webhook URL must not point to internal network addresses")
	}
	return nil
}

/*
 * isPrivateIP 判断 IP 是否为内部/私有地址
 * 覆盖：环回、未指定、私有(RFC1918)、链路本地(169.254/fe80)、ULA(fc00::/7)
 */
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	/* Go 1.17+ net.IP.IsPrivate() 覆盖 10/8, 172.16/12, 192.168/16, fc00::/7 */
	if ip.IsPrivate() {
		return true
	}
	/* 云元数据服务地址 169.254.169.254 */
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	return false
}

/*
 * GetWebhooks 获取应用的所有 Webhook 配置
 * @param appID - 应用 UUID
 */
func (s *WebhookService) GetWebhooks(appID uuid.UUID) ([]model.Webhook, error) {
	return s.webhookRepo.FindByAppID(appID)
}

/*
 * UpdateWebhook 更新 Webhook 配置
 * @param id     - Webhook UUID
 * @param url    - 新的回调 URL
 * @param secret - 新的签名密钥（空字符串表示不更新）
 * @param events - 新的订阅事件
 * @param active - 是否启用
 */
func (s *WebhookService) UpdateWebhook(id uuid.UUID, webhookURL, secret, events string, active bool) error {
	/* 校验新 URL 安全性 */
	if err := validateWebhookURL(webhookURL); err != nil {
		return err
	}

	webhook, err := s.webhookRepo.FindByID(id)
	if err != nil {
		return err
	}

	webhook.URL = webhookURL
	if secret != "" {
		webhook.Secret = secret
	}
	webhook.Events = events
	webhook.Active = active

	return s.webhookRepo.Update(webhook)
}

/* DeleteWebhook 删除 Webhook */
func (s *WebhookService) DeleteWebhook(id uuid.UUID) error {
	return s.webhookRepo.Delete(id)
}

/*
 * TriggerEvent 触发指定事件的 Webhook 回调
 * 功能：查找订阅了该事件的所有活跃 Webhook，异步投递负载
 * @param ctx   - 上下文
 * @param appID - 应用 UUID
 * @param event - 事件类型
 * @param data  - 事件数据
 */
func (s *WebhookService) TriggerEvent(ctx context.Context, appID uuid.UUID, event model.WebhookEvent, data map[string]any) error {
	webhooks, err := s.webhookRepo.FindActiveByAppAndEvent(appID, event)
	if err != nil {
		return err
	}

	payload := model.WebhookPayload{
		Event:     event,
		Timestamp: time.Now(),
		AppID:     appID.String(),
		Data:      data,
	}

	// Send webhooks asynchronously
	for _, webhook := range webhooks {
		go s.deliverWebhook(webhook, payload)
	}

	return nil
}

/*
 * deliverWebhook 向配置的 URL 投递 Webhook 负载
 * 功能：发送 HTTP POST 请求，携带签名头、事件头等，记录投递结果
 * @param webhook - Webhook 配置
 * @param payload - 回调负载
 */
func (s *WebhookService) deliverWebhook(webhook model.Webhook, payload model.WebhookPayload) {
	// Create delivery record
	payloadBytes, _ := json.Marshal(payload)
	delivery := &model.WebhookDelivery{
		WebhookID: webhook.ID,
		Event:     payload.Event,
		Payload:   string(payloadBytes),
		Attempts:  1,
	}

	// Make HTTP request
	req, err := http.NewRequest("POST", webhook.URL, bytes.NewReader(payloadBytes))
	if err != nil {
		delivery.Error = err.Error()
		s.webhookRepo.CreateDelivery(delivery)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OAuth2-Webhook/1.0")
	req.Header.Set("X-Webhook-Event", string(payload.Event))
	req.Header.Set("X-Webhook-Delivery", delivery.ID.String())
	req.Header.Set("X-Webhook-Timestamp", fmt.Sprintf("%d", payload.Timestamp.Unix()))

	// Sign payload if secret is configured
	if webhook.Secret != "" {
		signature := s.signPayload(payloadBytes, webhook.Secret)
		req.Header.Set("X-Webhook-Signature", signature)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		delivery.Error = err.Error()
		delivery.NextRetryAt = s.calculateNextRetry(delivery.Attempts)
		s.webhookRepo.CreateDelivery(delivery)
		s.log.Warn("Webhook delivery failed",
			"webhook_id", webhook.ID,
			"url", webhook.URL,
			"error", err,
		)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	delivery.StatusCode = resp.StatusCode
	delivery.Response = string(body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		delivery.Delivered = true
		now := time.Now()
		delivery.DeliveredAt = &now
		s.log.Info("Webhook delivered successfully",
			"webhook_id", webhook.ID,
			"url", webhook.URL,
			"event", payload.Event,
		)
	} else {
		delivery.NextRetryAt = s.calculateNextRetry(delivery.Attempts)
		s.log.Warn("Webhook delivery received non-2xx response",
			"webhook_id", webhook.ID,
			"url", webhook.URL,
			"status", resp.StatusCode,
		)
	}

	s.webhookRepo.CreateDelivery(delivery)
}

/*
 * signPayload 使用 HMAC-SHA256 对负载进行签名
 * @param payload - 负载字节数据
 * @param secret  - 签名密钥
 * @return string - 格式为 "sha256=<hex>" 的签名字符串
 */
func (s *WebhookService) signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

/*
 * calculateNextRetry 使用指数退避计算下次重试时间
 * 策略：1min → 5min → 15min → 1hr → 4hr，超过 5 次后不再重试
 * @param attempts - 已尝试次数
 * @return *time.Time - 下次重试时间，nil 表示不再重试
 */
func (s *WebhookService) calculateNextRetry(attempts int) *time.Time {
	// Exponential backoff: 1min, 5min, 15min, 1hr, 4hr
	delays := []time.Duration{
		1 * time.Minute,
		5 * time.Minute,
		15 * time.Minute,
		1 * time.Hour,
		4 * time.Hour,
	}

	if attempts >= len(delays) {
		return nil // No more retries
	}

	nextRetry := time.Now().Add(delays[attempts])
	return &nextRetry
}

/*
 * ProcessPendingDeliveries 处理失败的 Webhook 投递（后台任务调用）
 * 功能：查找待重试的投递记录，逐条重新投递
 * @param ctx - 上下文（支持取消）
 */
func (s *WebhookService) ProcessPendingDeliveries(ctx context.Context) error {
	deliveries, err := s.webhookRepo.FindPendingDeliveries(100)
	if err != nil {
		return err
	}

	for _, delivery := range deliveries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if delivery.Webhook == nil {
				continue
			}

			var payload model.WebhookPayload
			if err := json.Unmarshal([]byte(delivery.Payload), &payload); err != nil {
				continue
			}

			// Retry delivery
			delivery.Attempts++
			s.retryDelivery(&delivery, payload)
		}
	}

	return nil
}

/*
 * retryDelivery 重试失败的 Webhook 投递
 * @param delivery - 投递记录
 * @param payload  - 原始负载
 */
func (s *WebhookService) retryDelivery(delivery *model.WebhookDelivery, payload model.WebhookPayload) {
	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", delivery.Webhook.URL, bytes.NewReader(payloadBytes))
	if err != nil {
		delivery.Error = err.Error()
		delivery.NextRetryAt = s.calculateNextRetry(delivery.Attempts)
		s.webhookRepo.UpdateDelivery(delivery)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OAuth2-Webhook/1.0")
	req.Header.Set("X-Webhook-Event", string(payload.Event))
	req.Header.Set("X-Webhook-Delivery", delivery.ID.String())
	req.Header.Set("X-Webhook-Retry", fmt.Sprintf("%d", delivery.Attempts))

	if delivery.Webhook.Secret != "" {
		signature := s.signPayload(payloadBytes, delivery.Webhook.Secret)
		req.Header.Set("X-Webhook-Signature", signature)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		delivery.Error = err.Error()
		delivery.NextRetryAt = s.calculateNextRetry(delivery.Attempts)
		s.webhookRepo.UpdateDelivery(delivery)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	delivery.StatusCode = resp.StatusCode
	delivery.Response = string(body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		delivery.Delivered = true
		now := time.Now()
		delivery.DeliveredAt = &now
		delivery.NextRetryAt = nil
	} else {
		delivery.NextRetryAt = s.calculateNextRetry(delivery.Attempts)
	}

	s.webhookRepo.UpdateDelivery(delivery)
}

/*
 * GetDeliveries 获取 Webhook 的投递历史记录
 * @param webhookID - Webhook UUID
 * @param page      - 页码（1-based）
 * @param limit     - 每页数量
 */
func (s *WebhookService) GetDeliveries(webhookID uuid.UUID, page, limit int) ([]model.WebhookDelivery, int64, error) {
	offset := (page - 1) * limit
	return s.webhookRepo.FindDeliveriesByWebhook(webhookID, offset, limit)
}

/*
 * TestWebhook 发送测试负载到指定的 Webhook
 * 功能：直接投递测试事件，不管 Webhook 订阅了什么事件
 * @param webhookID - Webhook UUID
 * @param userID    - 发起测试的用户 ID
 */
func (s *WebhookService) TestWebhook(webhookID uuid.UUID, userID string) error {
	webhook, err := s.webhookRepo.FindByID(webhookID)
	if err != nil {
		return err
	}

	payload := model.WebhookPayload{
		Event:     "test",
		Timestamp: time.Now(),
		AppID:     webhook.AppID.String(),
		Data: map[string]any{
			"test":       true,
			"user_id":    userID,
			"message":    "This is a test webhook delivery",
			"webhook_id": webhookID.String(),
		},
	}

	// 直接投递到这个webhook，不管它订阅了什么事件
	go s.deliverWebhook(*webhook, payload)
	return nil
}
