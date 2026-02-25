package oauth2

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"sync"
	"time"
)

/*
 * Token OAuth2 令牌结构
 * 功能：存储 access_token、refresh_token、过期时间、scope 和原始响应
 */
type Token struct {
	AccessToken  string                 `json:"access_token"`            /* 访问令牌 */
	TokenType    string                 `json:"token_type"`              /* 令牌类型，通常为 "Bearer" */
	RefreshToken string                 `json:"refresh_token,omitempty"` /* 刷新令牌 */
	Expiry       time.Time              `json:"expiry,omitempty"`        /* 过期时间 */
	Scope        string                 `json:"scope,omitempty"`         /* 权限范围 */
	Raw          map[string]interface{} `json:"-"`                       /* 原始响应数据 */
}

/*
 * IsExpired 检查令牌是否已过期
 * 功能：提前 10~15 秒（含随机 jitter）判定为过期，
 *       防止多个客户端实例在同一时刻集中刷新造成惊群效应
 */
func (t *Token) IsExpired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	/* 基础提前量 10 秒 + 随机 jitter 0~5 秒 */
	jitter := time.Duration(0)
	if n, err := rand.Int(rand.Reader, big.NewInt(5000)); err == nil {
		jitter = time.Duration(n.Int64()) * time.Millisecond
	}
	return time.Now().Add(10*time.Second + jitter).After(t.Expiry)
}

/* IsValid 检查令牌是否有效（非空且未过期） */
func (t *Token) IsValid() bool {
	return t != nil && t.AccessToken != "" && !t.IsExpired()
}

/*
 * SetExpiry 根据 expires_in 秒数设置过期时间
 * @param expiresIn - 从当前时间起的有效秒数
 */
func (t *Token) SetExpiry(expiresIn int64) {
	if expiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
}

/* tokenResponse Token 端点的 JSON 响应结构（内部使用） */
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

/*
 * parseTokenResponse 解析 Token 端点的 JSON 响应
 * @param data - JSON 字节数据
 * @return *Token - 解析后的令牌实体
 */
func parseTokenResponse(data []byte) (*Token, error) {
	var resp tokenResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	token := &Token{
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		RefreshToken: resp.RefreshToken,
		Scope:        resp.Scope,
	}
	token.SetExpiry(resp.ExpiresIn)

	// Parse raw response
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	token.Raw = raw

	return token, nil
}

// TokenStore is an interface for storing and retrieving tokens
type TokenStore interface {
	// GetToken retrieves the stored token
	GetToken() (*Token, error)

	// SetToken stores the token
	SetToken(token *Token) error

	// DeleteToken removes the stored token
	DeleteToken() error
}

// MemoryTokenStore is an in-memory token store
type MemoryTokenStore struct {
	mu    sync.RWMutex
	token *Token
}

// NewMemoryTokenStore creates a new in-memory token store
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{}
}

// GetToken retrieves the stored token
func (s *MemoryTokenStore) GetToken() (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token, nil
}

// SetToken stores the token
func (s *MemoryTokenStore) SetToken(token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
	return nil
}

// DeleteToken removes the stored token
func (s *MemoryTokenStore) DeleteToken() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = nil
	return nil
}
