package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

/*
 * WebhookEvent Webhook 事件类型枚举
 * @value WebhookEventUserRegistered  - 用户注册
 * @value WebhookEventUserLogin       - 用户登录
 * @value WebhookEventUserUpdated     - 用户信息更新
 * @value WebhookEventOAuthAuthorized - OAuth2 授权同意
 * @value WebhookEventOAuthRevoked    - OAuth2 授权撤销
 * @value WebhookEventTokenRefreshed  - 令牌刷新
 * @value WebhookEventTest            - 测试事件
 */
type WebhookEvent string

const (
	WebhookEventUserRegistered  WebhookEvent = "user.registered"
	WebhookEventUserLogin       WebhookEvent = "user.login"
	WebhookEventUserUpdated     WebhookEvent = "user.updated"
	WebhookEventOAuthAuthorized WebhookEvent = "oauth.authorized"
	WebhookEventOAuthRevoked    WebhookEvent = "oauth.revoked"
	WebhookEventTokenRefreshed  WebhookEvent = "token.refreshed"
	WebhookEventTest            WebhookEvent = "test"
)

/* WebhookPayload Webhook 回调负载结构 */
type WebhookPayload struct {
	Event     WebhookEvent   `json:"event"`
	Timestamp time.Time      `json:"timestamp"`
	AppID     string         `json:"app_id"`
	Data      map[string]any `json:"data"`
}

/* WebhookHandler Webhook 事件处理函数类型 */
type WebhookHandler func(payload *WebhookPayload) error

/* WebhookHandlerOptions Webhook 处理器配置（签名验证、时间戳校验等） */
type WebhookHandlerOptions struct {
	Secret            string
	ValidateTimestamp bool
	MaxTimeDrift      time.Duration
}

/* DefaultWebhookHandlerOptions 返回默认的 Webhook 处理器配置 */
func DefaultWebhookHandlerOptions() *WebhookHandlerOptions {
	return &WebhookHandlerOptions{
		ValidateTimestamp: true,
		MaxTimeDrift:      5 * time.Minute,
	}
}

// WebhookServer handles incoming webhook requests
type WebhookServer struct {
	handlers map[WebhookEvent][]WebhookHandler
	options  *WebhookHandlerOptions
	logger   Logger
}

// NewWebhookServer creates a new webhook server
func NewWebhookServer(options *WebhookHandlerOptions) *WebhookServer {
	if options == nil {
		options = DefaultWebhookHandlerOptions()
	}
	return &WebhookServer{
		handlers: make(map[WebhookEvent][]WebhookHandler),
		options:  options,
		logger:   NewDefaultLogger(),
	}
}

// SetLogger sets a custom logger
func (s *WebhookServer) SetLogger(logger Logger) {
	s.logger = logger
}

// On registers a handler for a specific event
func (s *WebhookServer) On(event WebhookEvent, handler WebhookHandler) {
	s.handlers[event] = append(s.handlers[event], handler)
}

// OnAll registers a handler for all events
func (s *WebhookServer) OnAll(handler WebhookHandler) {
	s.On("*", handler)
}

// ServeHTTP implements http.Handler
func (s *WebhookServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024)) // 1MB limit
	if err != nil {
		s.logger.Error("Failed to read webhook body", err)
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Validate signature if secret is configured
	if s.options.Secret != "" {
		signature := r.Header.Get("X-Webhook-Signature")
		if !s.validateSignature(body, signature) {
			s.logger.Warn("Invalid webhook signature")
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	}

	// Parse payload
	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		s.logger.Error("Failed to parse webhook payload", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Validate timestamp if enabled
	if s.options.ValidateTimestamp {
		drift := time.Since(payload.Timestamp)
		if drift < 0 {
			drift = -drift
		}
		if drift > s.options.MaxTimeDrift {
			s.logger.Warn("Webhook timestamp drift too large", drift)
			http.Error(w, "Timestamp validation failed", http.StatusBadRequest)
			return
		}
	}

	// Log the event
	s.logger.Info(fmt.Sprintf("Received webhook event: %s", payload.Event))

	// Call handlers
	eventHandlers := s.handlers[payload.Event]
	allHandlers := s.handlers["*"]

	var lastErr error
	for _, handler := range append(eventHandlers, allHandlers...) {
		if err := handler(&payload); err != nil {
			s.logger.Error(fmt.Sprintf("Webhook handler error for event %s", payload.Event), err)
			lastErr = err
		}
	}

	if lastErr != nil {
		http.Error(w, "Handler error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// validateSignature validates the HMAC-SHA256 signature
func (s *WebhookServer) validateSignature(body []byte, signature string) bool {
	if signature == "" {
		return false
	}

	// Signature format: sha256=<hex>
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}

	expectedSig := signature[7:] // Remove "sha256=" prefix

	mac := hmac.New(sha256.New, []byte(s.options.Secret))
	mac.Write(body)
	actualSig := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(actualSig))
}

// Webhook represents a webhook configuration
type Webhook struct {
	ID     string `json:"id"`
	URL    string `json:"url"`
	Events string `json:"events"`
	Active bool   `json:"active"`
}

// WebhookDelivery represents a webhook delivery attempt
type WebhookDelivery struct {
	ID         string    `json:"id"`
	WebhookID  string    `json:"webhook_id"`
	Event      string    `json:"event"`
	StatusCode int       `json:"status_code"`
	Delivered  bool      `json:"delivered"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// CreateWebhookRequest represents a request to create a webhook
type CreateWebhookRequest struct {
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"`
	Events string `json:"events"` // Comma-separated: "user.registered,user.login"
}

// CreateWebhook creates a new webhook for the client's app
func (c *Client) CreateWebhook(req *CreateWebhookRequest) (*Webhook, error) {
	// This would typically require the app ID, which should be part of the config
	logInfo("Creating webhook", req.URL)

	// This is a placeholder - actual implementation would call the server API
	return nil, fmt.Errorf("CreateWebhook requires app context - use server API directly")
}

// ListWebhooks lists all webhooks for the client's app
func (c *Client) ListWebhooks() ([]Webhook, error) {
	logInfo("Listing webhooks")

	// This is a placeholder - actual implementation would call the server API
	return nil, fmt.Errorf("ListWebhooks requires app context - use server API directly")
}

// Helper function to parse webhook events from comma-separated string
func ParseWebhookEvents(events string) []WebhookEvent {
	parts := strings.Split(events, ",")
	result := make([]WebhookEvent, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, WebhookEvent(p))
		}
	}
	return result
}

// Helper function to join webhook events to comma-separated string
func JoinWebhookEvents(events []WebhookEvent) string {
	strs := make([]string, len(events))
	for i, e := range events {
		strs[i] = string(e)
	}
	return strings.Join(strs, ",")
}
