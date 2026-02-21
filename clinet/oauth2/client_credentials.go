package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

/* ClientCredentialsRequest Client Credentials 授权请求参数 */
type ClientCredentialsRequest struct {
	Scope string // Optional: space-separated list of scopes
}

/* ClientCredentialsResponse Client Credentials 授权响应结构 */
type ClientCredentialsResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

/*
 * ClientCredentials 执行 Client Credentials 授权流程
 * 功能：机器对机器认证，无用户上下文，使用 client_id + client_secret 获取 access_token
 * @param ctx - 上下文
 * @param req - 请求参数（可选 scope）
 * @return *ClientCredentialsResponse - 令牌响应
 */
func (c *Client) ClientCredentials(ctx context.Context, req *ClientCredentialsRequest) (*ClientCredentialsResponse, error) {
	c.logger.Debug("Starting client credentials flow")

	if req == nil {
		req = &ClientCredentialsRequest{}
	}

	// Build request data
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)
	if req.Scope != "" {
		data.Set("scope", req.Scope)
	}

	// Make token request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("oauth2: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("oauth2: %s - %s", errResp.Error, errResp.Description)
		}
		return nil, fmt.Errorf("oauth2: client credentials request failed with status %d", resp.StatusCode)
	}

	var result ClientCredentialsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("oauth2: failed to parse response: %w", err)
	}

	// Store the token for later use
	token := &Token{
		AccessToken: result.AccessToken,
		TokenType:   result.TokenType,
	}
	token.SetExpiry(result.ExpiresIn)
	if err := c.tokenStore.SetToken(token); err != nil {
		c.logger.Warn("Failed to store client credentials token", "error", err)
	}

	c.logger.Info("Client credentials flow completed successfully")
	return &result, nil
}

// ClientCredentialsWithAutoRefresh performs client credentials flow and automatically
// refreshes the token when it expires (since refresh_token is not issued for this grant)
type ClientCredentialsManager struct {
	client    *Client
	scope     string
	token     *Token
	expiresAt time.Time
}

// NewClientCredentialsManager creates a new manager for client credentials tokens
func (c *Client) NewClientCredentialsManager(scope string) *ClientCredentialsManager {
	return &ClientCredentialsManager{
		client: c,
		scope:  scope,
	}
}

// GetToken returns a valid access token, refreshing if necessary
func (m *ClientCredentialsManager) GetToken(ctx context.Context) (string, error) {
	// Check if current token is still valid (with 30 second buffer)
	if m.token != nil && time.Now().Add(30*time.Second).Before(m.expiresAt) {
		return m.token.AccessToken, nil
	}

	// Get new token
	resp, err := m.client.ClientCredentials(ctx, &ClientCredentialsRequest{
		Scope: m.scope,
	})
	if err != nil {
		return "", err
	}

	m.token = &Token{
		AccessToken: resp.AccessToken,
		TokenType:   resp.TokenType,
	}
	m.expiresAt = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)

	return m.token.AccessToken, nil
}

// HTTPClient returns an http.Client that automatically adds the Bearer token
func (m *ClientCredentialsManager) HTTPClient(ctx context.Context) *http.Client {
	return &http.Client{
		Transport: &clientCredentialsTransport{
			manager: m,
			ctx:     ctx,
			base:    http.DefaultTransport,
		},
	}
}

type clientCredentialsTransport struct {
	manager *ClientCredentialsManager
	ctx     context.Context
	base    http.RoundTripper
}

func (t *clientCredentialsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.manager.GetToken(t.ctx)
	if err != nil {
		return nil, err
	}

	// Clone request to avoid mutating the original
	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", "Bearer "+token)

	return t.base.RoundTrip(req2)
}
