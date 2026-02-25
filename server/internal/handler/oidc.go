package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"server/internal/repository"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/*
 * OIDCHandler OIDC 发现端点处理器
 * 功能：处理 OpenID Connect Discovery、JWKS、WebFinger、OIDC Logout 等端点
 */
type OIDCHandler struct {
	issuer     string
	privateKey *rsa.PrivateKey
	keyID      string
	mu         sync.RWMutex
	oauthRepo  *repository.OAuthRepository
	jwtManager *jwt.Manager
}

/*
 * NewOIDCHandler 创建 OIDC 处理器实例
 * @param issuer - JWT 签发者标识（iss）
 */
func NewOIDCHandler(issuer string) *OIDCHandler {
	h := &OIDCHandler{
		issuer: issuer,
		keyID:  "oauth2-key-1",
	}
	/* RSA 密钥延迟生成：首次访问 JWKS 端点时触发，不阻塞服务启动 */
	go h.generateKey()
	return h
}

/* SetOAuthRepo 注入 OAuth 仓储和 JWT 管理器（用于 Token 撤销和 OIDC Logout） */
func (h *OIDCHandler) SetOAuthRepo(oauthRepo *repository.OAuthRepository, jwtManager *jwt.Manager) {
	h.oauthRepo = oauthRepo
	h.jwtManager = jwtManager
}

/*
 * generateKey 生成 RSA 密钥对用于 JWT/OIDC 签名
 * 使用 2048 位（NIST 推荐安全等级，生成速度比 4096 位快约 8 倍）
 */
func (h *OIDCHandler) generateKey() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	h.mu.Lock()
	h.privateKey = key
	h.mu.Unlock()
}

/* ensureKey 确保 RSA 密钥已生成，未就绪时同步生成 */
func (h *OIDCHandler) ensureKey() {
	h.mu.RLock()
	hasKey := h.privateKey != nil
	h.mu.RUnlock()
	if !hasKey {
		h.generateKey()
	}
}

// Discovery returns the OIDC discovery document
// GET /.well-known/openid-configuration
func (h *OIDCHandler) Discovery(c *gin.Context) {
	// 动态获取issuer（基于请求的host）
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	issuer := scheme + "://" + c.Request.Host

	discovery := map[string]interface{}{
		// 必需字段
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint":         issuer + "/oauth/token",
		"userinfo_endpoint":      issuer + "/oauth/userinfo",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
		"registration_endpoint":  issuer + "/api/apps", // 动态客户端注册
		"revocation_endpoint":    issuer + "/oauth/revoke",
		"introspection_endpoint": issuer + "/oauth/introspect",
		"end_session_endpoint":   issuer + "/oauth/logout",

		// 支持的响应类型
		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},

		// 支持的响应模式
		"response_modes_supported": []string{
			"query",
			"fragment",
			"form_post",
		},

		// 支持的授权类型
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
			"implicit",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},

		// 支持的主题标识符类型
		"subject_types_supported": []string{
			"public",
		},

		// 支持的ID Token签名算法
		"id_token_signing_alg_values_supported": []string{
			"RS256",
			"HS256",
		},

		// 支持的Token端点认证方法
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"none", // 公开客户端
		},

		// 支持的scope
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
			"phone",
			"address",
			"offline_access",
		},

		// 支持的claims
		"claims_supported": []string{
			// OpenID标准claims
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"auth_time",
			"nonce",
			"acr",
			"amr",
			"azp",
			// Profile claims
			"name",
			"family_name",
			"given_name",
			"middle_name",
			"nickname",
			"preferred_username",
			"profile",
			"picture",
			"website",
			"gender",
			"birthdate",
			"zoneinfo",
			"locale",
			"updated_at",
			// Email claims
			"email",
			"email_verified",
			// Phone claims
			"phone_number",
			"phone_number_verified",
			// Address claims
			"address",
		},

		// PKCE 支持（仅 S256，plain 已禁用以防止中间人攻击）
		"code_challenge_methods_supported": []string{
			"S256",
		},

		// 其他功能
		"claims_parameter_supported":       true,
		"request_parameter_supported":      true,
		"request_uri_parameter_supported":  false,
		"require_request_uri_registration": false,
		"ui_locales_supported":             []string{"zh-CN", "en"},
		"service_documentation":            issuer + "/docs",

		// Device Authorization (RFC 8628)
		"device_authorization_endpoint": issuer + "/oauth/device/code",

		// 自定义扩展
		"sdk_endpoint":        issuer + "/api/sdk",
		"federation_endpoint": issuer + "/api/federation",
	}

	c.JSON(http.StatusOK, discovery)
}

// JWKS returns the JSON Web Key Set
// GET /.well-known/jwks.json
func (h *OIDCHandler) JWKS(c *gin.Context) {
	h.ensureKey()

	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.privateKey == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No signing key available"})
		return
	}

	// 导出公钥
	publicKey := &h.privateKey.PublicKey

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": h.keyID,
				"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
			},
		},
	}

	c.JSON(http.StatusOK, jwks)
}

// WebFinger handles WebFinger requests for OIDC discovery
// GET /.well-known/webfinger
func (h *OIDCHandler) WebFinger(c *gin.Context) {
	resource := c.Query("resource")
	rel := c.Query("rel")

	if resource == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource parameter required"})
		return
	}

	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	issuer := scheme + "://" + c.Request.Host

	// 如果请求的是OIDC issuer发现
	if rel == "http://openid.net/specs/connect/1.0/issuer" || rel == "" {
		response := map[string]interface{}{
			"subject": resource,
			"links": []map[string]string{
				{
					"rel":  "http://openid.net/specs/connect/1.0/issuer",
					"href": issuer,
				},
			},
		}
		c.Header("Content-Type", "application/jrd+json")
		c.JSON(http.StatusOK, response)
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "resource not found"})
}

// Logout handles OIDC logout (RP-initiated)
// GET/POST /oauth/logout
func (h *OIDCHandler) Logout(c *gin.Context) {
	// 获取参数
	idTokenHint := c.Query("id_token_hint")
	if idTokenHint == "" {
		idTokenHint = c.PostForm("id_token_hint")
	}

	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	if postLogoutRedirectURI == "" {
		postLogoutRedirectURI = c.PostForm("post_logout_redirect_uri")
	}

	state := c.Query("state")
	if state == "" {
		state = c.PostForm("state")
	}
	if idTokenHint != "" && h.jwtManager != nil && h.oauthRepo != nil {
		claims, err := h.jwtManager.ValidateToken(idTokenHint)
		if err == nil && claims != nil {
			userID := claims.UserID
			if userID != (uuid.UUID{}) {
				h.oauthRepo.RevokeTokensByUserID(userID)
			}
		}
	}

	// 如果有重定向URI，重定向回去
	if postLogoutRedirectURI != "" {
		redirectURL := postLogoutRedirectURI
		if state != "" {
			if strings.Contains(redirectURL, "?") {
				redirectURL += "&state=" + state
			} else {
				redirectURL += "?state=" + state
			}
		}
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	// 否则显示登出成功页面
	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}
