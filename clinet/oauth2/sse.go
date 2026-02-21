package oauth2

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

/* AuthEvent SSE 推送的授权事件结构 */
type AuthEvent struct {
	Type      string    `json:"type"`
	AppID     string    `json:"app_id"`
	AppName   string    `json:"app_name"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

/*
 * SSEClient Server-Sent Events 客户端
 * 功能：连接服务器 SSE 端点，实时接收授权事件
 */
type SSEClient struct {
	client    *Client
	eventChan chan AuthEvent
	errorChan chan error
	done      chan struct{}
}

/* NewSSEClient 创建新的 SSE 客户端实例 */
func (c *Client) NewSSEClient() *SSEClient {
	return &SSEClient{
		client:    c,
		eventChan: make(chan AuthEvent, 10),
		errorChan: make(chan error, 1),
		done:      make(chan struct{}),
	}
}

/* Events 返回接收授权事件的通道 */
func (s *SSEClient) Events() <-chan AuthEvent {
	return s.eventChan
}

/* Errors 返回接收错误的通道 */
func (s *SSEClient) Errors() <-chan error {
	return s.errorChan
}

// Close stops the SSE connection
func (s *SSEClient) Close() {
	close(s.done)
}

// Connect starts listening for SSE events for the app
func (s *SSEClient) Connect(ctx context.Context) error {
	apiURL := strings.TrimSuffix(s.client.config.AuthURL, "/oauth/authorize")
	sseURL := fmt.Sprintf("%s/api/events/app?app_id=%s", apiURL, s.client.config.ClientID)

	req, err := http.NewRequestWithContext(ctx, "GET", sseURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := s.client.httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("sse: unexpected status code %d", resp.StatusCode)
	}

	go s.readEvents(resp)
	return nil
}

func (s *SSEClient) readEvents(resp *http.Response) {
	defer resp.Body.Close()
	defer close(s.eventChan)
	defer close(s.errorChan)

	scanner := bufio.NewScanner(resp.Body)
	var eventType string
	var data strings.Builder

	for {
		select {
		case <-s.done:
			return
		default:
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					select {
					case s.errorChan <- err:
					default:
					}
				}
				return
			}

			line := scanner.Text()

			if line == "" {
				// Empty line means end of event
				if eventType == "auth" && data.Len() > 0 {
					var event AuthEvent
					if err := json.Unmarshal([]byte(data.String()), &event); err == nil {
						select {
						case s.eventChan <- event:
						case <-s.done:
							return
						}
					}
				}
				eventType = ""
				data.Reset()
				continue
			}

			if strings.HasPrefix(line, "event:") {
				eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
	}
}

// OnEvent is a callback type for handling auth events
type OnEventCallback func(event AuthEvent)

// ListenEvents is a convenience method that calls the callback for each event
func (s *SSEClient) ListenEvents(ctx context.Context, callback OnEventCallback) error {
	if err := s.Connect(ctx); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			s.Close()
			return ctx.Err()
		case event, ok := <-s.Events():
			if !ok {
				return nil
			}
			callback(event)
		case err := <-s.Errors():
			return err
		}
	}
}
