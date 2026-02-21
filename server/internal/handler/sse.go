package handler

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

/* AuthEvent 授权事件结构（SSE 推送给客户端的事件数据） */
type AuthEvent struct {
	Type      string    `json:"type"` // user_registered, user_login, oauth_authorized, oauth_revoked
	AppID     string    `json:"app_id"`
	AppName   string    `json:"app_name"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

/* SSEClient SSE 连接客户端，支持按 AppID/UserID 过滤事件 */
type SSEClient struct {
	ID       string
	AppID    string // Filter events by app ID, empty means all
	UserID   string // Filter events by user ID, empty means all
	IsAdmin  bool   // Admin can see all events
	Messages chan AuthEvent
}

/*
 * SSEHub SSE 连接管理中心
 * 功能：管理所有 SSE 客户端连接，广播授权事件到订阅的客户端
 */
type SSEHub struct {
	clients    map[string]*SSEClient
	register   chan *SSEClient
	unregister chan *SSEClient
	broadcast  chan AuthEvent
	mu         sync.RWMutex
}

var sseHub *SSEHub
var sseOnce sync.Once

// GetSSEHub returns the singleton SSE hub
func GetSSEHub() *SSEHub {
	sseOnce.Do(func() {
		sseHub = &SSEHub{
			clients:    make(map[string]*SSEClient),
			register:   make(chan *SSEClient),
			unregister: make(chan *SSEClient),
			broadcast:  make(chan AuthEvent, 100),
		}
		go sseHub.run()
	})
	return sseHub
}

func (h *SSEHub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client.ID] = client
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client.ID]; ok {
				delete(h.clients, client.ID)
				close(client.Messages)
			}
			h.mu.Unlock()

		case event := <-h.broadcast:
			h.mu.RLock()
			for _, client := range h.clients {
				// Filter events based on client permissions
				if client.IsAdmin ||
					(client.AppID != "" && client.AppID == event.AppID) ||
					(client.UserID != "" && client.UserID == event.UserID) ||
					(client.AppID == "" && client.UserID == "") {
					select {
					case client.Messages <- event:
					default:
						// Client buffer full, skip
					}
				}
			}
			h.mu.RUnlock()
		}
	}
}

// EmitAuthEvent broadcasts an auth event to all connected clients
func EmitAuthEvent(event AuthEvent) {
	hub := GetSSEHub()
	select {
	case hub.broadcast <- event:
	default:
		// Buffer full, drop event
	}
}

// SSEHandler handles SSE connections
type SSEHandler struct{}

func NewSSEHandler() *SSEHandler {
	return &SSEHandler{}
}

// Stream handles SSE stream connections
// GET /api/events/stream
func (h *SSEHandler) Stream(c *gin.Context) {
	hub := GetSSEHub()

	// Get client info from context (set by auth middleware)
	userID, _ := c.Get("user_id")
	userRole, _ := c.Get("user_role")

	// Get optional app filter
	appID := c.Query("app_id")

	client := &SSEClient{
		ID:       fmt.Sprintf("%d", time.Now().UnixNano()),
		AppID:    appID,
		UserID:   fmt.Sprintf("%v", userID),
		IsAdmin:  userRole == "admin",
		Messages: make(chan AuthEvent, 10),
	}

	hub.register <- client
	defer func() {
		hub.unregister <- client
	}()

	/* SSE 响应头 - CORS 由全局中间件处理，此处不重复设置 */
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	c.SSEvent("connected", gin.H{
		"message":   "Connected to event stream",
		"client_id": client.ID,
	})
	c.Writer.Flush()

	// Keep connection alive
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	clientGone := c.Request.Context().Done()

	for {
		select {
		case <-clientGone:
			return
		case event := <-client.Messages:
			data, _ := json.Marshal(event)
			c.SSEvent("auth", string(data))
			c.Writer.Flush()
		case <-ticker.C:
			c.SSEvent("ping", gin.H{"time": time.Now().Unix()})
			c.Writer.Flush()
		}
	}
}

// StreamPublic handles public SSE stream for apps (using client credentials)
// GET /api/events/app
func (h *SSEHandler) StreamApp(c *gin.Context) {
	hub := GetSSEHub()

	appID := c.Query("app_id")
	if appID == "" {
		BadRequest(c, "app_id is required")
		return
	}

	client := &SSEClient{
		ID:       fmt.Sprintf("app-%d", time.Now().UnixNano()),
		AppID:    appID,
		Messages: make(chan AuthEvent, 10),
	}

	hub.register <- client
	defer func() {
		hub.unregister <- client
	}()

	/* SSE 响应头 - CORS 由全局中间件处理，此处不重复设置 */
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	c.SSEvent("connected", gin.H{
		"message": "Connected to app event stream",
		"app_id":  appID,
	})
	c.Writer.Flush()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	clientGone := c.Request.Context().Done()

	for {
		select {
		case <-clientGone:
			return
		case event := <-client.Messages:
			data, _ := json.Marshal(event)
			c.SSEvent("auth", string(data))
			c.Writer.Flush()
		case <-ticker.C:
			c.SSEvent("ping", gin.H{"time": time.Now().Unix()})
			c.Writer.Flush()
		}
	}
}
