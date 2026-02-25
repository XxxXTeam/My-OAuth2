package oauth2

import (
	"errors"
	"net/url"
)

/*
 * Config OAuth2 客户端配置
 * 功能：定义连接 OAuth2 服务器所需的全部参数
 */
type Config struct {
	ClientID     string   /* 应用 client_id */
	ClientSecret string   /* 应用 client_secret（公开客户端可为空） */
	AuthURL      string   /* 授权端点 URL */
	TokenURL     string   /* Token 端点 URL */
	UserInfoURL  string   /* UserInfo 端点 URL（可选） */
	RedirectURL  string   /* 回调 URL */
	Scopes       []string /* 请求的权限范围 */
	UsePKCE      bool     /* 是否启用 PKCE (RFC 7636) */

	/* HTTP 客户端配置 */
	TimeoutSec int /* 请求超时秒数（默认 30） */
	MaxRetries int /* 最大重试次数（默认 3，仅对可重试错误生效） */
	RetryDelay int /* 重试间隔毫秒（默认 500，指数退避） */
}

/*
 * Validate 校验配置是否有效
 * 功能：检查必填字段和 URL 格式
 * @return error - 配置无效时返回错误
 */
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return errors.New("oauth2: client_id is required")
	}
	if c.AuthURL == "" {
		return errors.New("oauth2: auth_url is required")
	}
	if c.TokenURL == "" {
		return errors.New("oauth2: token_url is required")
	}
	if c.RedirectURL == "" {
		return errors.New("oauth2: redirect_url is required")
	}

	/* 校验 URL 格式和协议安全性 */
	for _, pair := range []struct {
		name, val string
	}{
		{"auth_url", c.AuthURL},
		{"token_url", c.TokenURL},
		{"redirect_url", c.RedirectURL},
	} {
		parsed, err := url.Parse(pair.val)
		if err != nil {
			return errors.New("oauth2: invalid " + pair.name)
		}
		/* 仅允许 http/https 协议，阻止 javascript:/data: 等危险协议 */
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("oauth2: " + pair.name + " must use http or https scheme")
		}
	}

	return nil
}

/*
 * DefaultConfig 返回默认 OAuth2 服务器的配置
 * 功能：预填本地开发服务器地址，默认启用 PKCE
 * @param clientID     - 应用 client_id
 * @param clientSecret - 应用 client_secret
 * @param redirectURL  - 回调 URL
 */
func DefaultConfig(clientID, clientSecret, redirectURL string) *Config {
	return &Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      "http://localhost:3000/oauth/authorize",
		TokenURL:     "http://localhost:8080/oauth/token",
		UserInfoURL:  "http://localhost:8080/oauth/userinfo",
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "profile", "email"},
		UsePKCE:      true,
	}
}
