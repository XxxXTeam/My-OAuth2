package handler

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/cache"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/*
 * OIDCHandler OIDC 发现端点处理器
 * 功能：处理 OpenID Connect Discovery、JWKS、WebFinger、OIDC Logout 等端点
 */
type OIDCHandler struct {
	issuer    string
	oauthRepo *repository.OAuthRepository
	appRepo   *repository.ApplicationRepository
	jwtManager *jwt.Manager
	cache     cache.Cache
}

/*
 * NewOIDCHandler 创建 OIDC 处理器实例
 * @param issuer - JWT 签发者标识（iss）
 * @param jwtManager - JWT 管理器（提供 RSA 公钥用于 JWKS）
 */
func NewOIDCHandler(issuer string, jwtManager *jwt.Manager) *OIDCHandler {
	return &OIDCHandler{
		issuer:     issuer,
		jwtManager: jwtManager,
	}
}

/* SetOAuthRepo 注入 OAuth 仓储（用于 Token 撤销和 OIDC Logout） */
func (h *OIDCHandler) SetOAuthRepo(oauthRepo *repository.OAuthRepository) {
	h.oauthRepo = oauthRepo
}

/* SetApplicationRepo 注入应用仓储（用于校验 OIDC logout 回跳地址） */
func (h *OIDCHandler) SetApplicationRepo(appRepo *repository.ApplicationRepository) {
	h.appRepo = appRepo
}

/* SetCache 注入统一缓存实例（用于 discovery/JWKS 热读缓存） */
func (h *OIDCHandler) SetCache(c cache.Cache) {
	h.cache = c
}

// Discovery returns the OIDC discovery document
// GET /.well-known/openid-configuration
func (h *OIDCHandler) Discovery(c *gin.Context) {
	// 动态获取issuer（基于请求的host）
	issuer := requestScheme(c.Request) + "://" + requestHost(c.Request)
	cacheKey := "oidc:discovery:" + issuer

	if h.cache != nil {
		if cached, err := cache.GetJSON[map[string]interface{}](c.Request.Context(), h.cache, cacheKey); err == nil {
			c.JSON(http.StatusOK, cached)
			return
		}
	}

	discovery := map[string]interface{}{
		// 必需字段
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint":         issuer + "/oauth/token",
		"userinfo_endpoint":      issuer + "/oauth/userinfo",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
		"revocation_endpoint":    issuer + "/oauth/revoke",
		"introspection_endpoint": issuer + "/oauth/introspect",
		"end_session_endpoint":   issuer + "/oauth/logout",

		// 支持的响应类型：授权提交路径当前只接受 authorization code flow
		"response_types_supported": []string{
			"code",
		},

		// 支持的响应模式：redirect URL 构造只使用 query 参数
		"response_modes_supported": []string{
			"query",
		},

		// 支持的 OIDC prompt 值
		"prompt_values_supported": []string{
			"none",
			"login",
			"consent",
		},

		// 支持的授权类型
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},

		// 支持的主题标识符类型
		"subject_types_supported": []string{
			"public",
		},

		// 支持的ID Token签名算法：混合模式，ID Token 使用 RS256
		"id_token_signing_alg_values_supported": []string{
			"RS256",
		},

		// 支持的Token端点认证方法
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"none", // 公开客户端
		},

		// 支持的 scope（OIDC 用户 scope + 机器 scope）
		"scopes_supported": model.AllServerSupportedScopes(),

		// 支持的 claims：仅公布当前 ID Token / UserInfo 实际可输出的标准 claim
		"claims_supported": []string{
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"nonce",
			"auth_time",
			"amr",
			"at_hash",
			"azp",
			"name",
			"family_name",
			"given_name",
			"nickname",
			"preferred_username",
			"picture",
			"website",
			"gender",
			"birthdate",
			"zoneinfo",
			"locale",
			"updated_at",
			"email",
			"email_verified",
			"phone_number",
			"phone_number_verified",
			"address",
			/* 非标准扩展 claims：profile scope 下由 UserInfo 输出 */
			"bio",
			"profile_completed",
			"department",
			"job_title",
			"company",
			/* groups scope 下由 UserInfo 输出：用户所属组/角色 */
			"groups",
		},

		// PKCE 支持（仅 S256，plain 已禁用以防止中间人攻击）
		"code_challenge_methods_supported": []string{
			"S256",
		},

		// 其他功能
		"claims_parameter_supported":       false,
		"request_parameter_supported":      false,
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

	if h.cache != nil {
		_ = cache.SetJSON(c.Request.Context(), h.cache, cacheKey, discovery, 2*time.Minute)
	}
	c.JSON(http.StatusOK, discovery)
}

/* OAuthAuthorizationServerMetadata 返回 RFC 8414 授权服务器元数据 */
func (h *OIDCHandler) OAuthAuthorizationServerMetadata(c *gin.Context) {
	issuer := requestScheme(c.Request) + "://" + requestHost(c.Request)
	metadata := map[string]interface{}{
		"issuer":                                        issuer,
		"authorization_endpoint":                        issuer + "/oauth/authorize",
		"token_endpoint":                                issuer + "/oauth/token",
		"jwks_uri":                                      issuer + "/.well-known/jwks.json",
		"revocation_endpoint":                           issuer + "/oauth/revoke",
		"introspection_endpoint":                        issuer + "/oauth/introspect",
		"device_authorization_endpoint":                 issuer + "/oauth/device/code",
		"response_types_supported":                      []string{"code"},
		"response_modes_supported":                      []string{"query"},
		"grant_types_supported":                         []string{"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"token_endpoint_auth_methods_supported":         []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                              model.AllServerSupportedScopes(),
		"code_challenge_methods_supported":              []string{"S256"},
	}
	c.JSON(http.StatusOK, metadata)
}

// JWKS returns the JSON Web Key Set
// GET /.well-known/jwks.json
func (h *OIDCHandler) JWKS(c *gin.Context) {
	issuer := requestScheme(c.Request) + "://" + requestHost(c.Request)
	cacheKey := "oidc:jwks:" + issuer
	if h.cache != nil {
		if cached, err := cache.GetJSON[map[string]interface{}](c.Request.Context(), h.cache, cacheKey); err == nil {
			c.JSON(http.StatusOK, cached)
			return
		}
	}

	keys := []map[string]interface{}{}
	if h.jwtManager != nil {
		pub := h.jwtManager.PublicKey()
		kid := h.jwtManager.KeyID()
		if pub != nil {
			keys = append(keys, rsaPublicKeyToJWK(pub, kid))
		}
	}

	jwks := map[string]interface{}{
		"keys": keys,
	}

	if h.cache != nil {
		_ = cache.SetJSON(c.Request.Context(), h.cache, cacheKey, jwks, 2*time.Minute)
	}
	c.JSON(http.StatusOK, jwks)
}

/* rsaPublicKeyToJWK 将 RSA 公钥转换为 JWK 格式（RFC 7517） */
func rsaPublicKeyToJWK(pub *rsa.PublicKey, kid string) map[string]interface{} {
	return map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
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

	issuer := requestScheme(c.Request) + "://" + requestHost(c.Request)

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

	var logoutApp *model.Application
	issuer := requestScheme(c.Request) + "://" + requestHost(c.Request)
	if idTokenHint != "" && h.jwtManager != nil {
		claims, err := h.jwtManager.ValidateToken(idTokenHint)
		if err != nil && h.appRepo != nil {
			if unverifiedClaims, parseErr := h.jwtManager.ParseUnverifiedClaims(idTokenHint); parseErr == nil && unverifiedClaims.ClientID != "" {
				if app, findErr := h.appRepo.FindByClientID(unverifiedClaims.ClientID); findErr == nil {
					verifiedClaims, verifyErr := h.jwtManager.ValidateClientIDTokenWithIssuer(idTokenHint, app.ClientID, app.ClientSecret, issuer)
					if verifyErr != nil {
						verifiedClaims, verifyErr = h.jwtManager.ValidateClientIDToken(idTokenHint, app.ClientID, app.ClientSecret)
					}
					if verifyErr == nil {
						claims = verifiedClaims
						err = nil
					}
				}
			}
		}
		if err == nil && claims != nil && claims.TokenType == jwt.TokenTypeIDToken {
			userID := claims.UserID
			if h.oauthRepo != nil && userID != (uuid.UUID{}) {
				h.oauthRepo.RevokeTokensByUserID(userID)
			}
			if h.appRepo != nil && claims.ClientID != "" {
				if app, findErr := h.appRepo.FindByClientID(claims.ClientID); findErr == nil {
					logoutApp = app
				}
			}
		}
	}

	// 如果有已登记登出回跳 URI，重定向回去
	if postLogoutRedirectURI != "" && logoutApp != nil && logoutApp.ValidatePostLogoutRedirectURI(postLogoutRedirectURI) {
		redirectURL := postLogoutRedirectURI
		if state != "" {
			if u, err := url.Parse(redirectURL); err == nil {
				q := u.Query()
				q.Set("state", state)
				u.RawQuery = q.Encode()
				redirectURL = u.String()
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
