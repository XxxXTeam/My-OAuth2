package handler

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"server/internal/config"
	gctx "server/internal/context"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
	gojwt "github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

/*
 * OIDC 授权码流程端到端集成测试
 *
 * 覆盖：
 *   - Authorization Code + PKCE 完整流程（授权 → 换取 token → userinfo）
 *   - ID Token RS256 签名，可通过 JWKS 公钥离线验证
 *   - Discovery 文档声明的端点均可访问
 *
 * 全部使用真实的 handler/service/repository 依赖，不 mock。
 */

const (
	oidcFlowIssuerHost = "auth.example.test"
	oidcFlowIssuer     = "https://auth.example.test"
	oidcFlowRedirect   = "https://client.example.test/callback"
	// RFC 7636 §4.1: code_verifier 长度需在 43-128 之间，字符集 [A-Za-z0-9-._~]
	oidcFlowCodeVerifier = "oidc-flow-pkce-code-verifier-0123456789-abcdefghij"
)

type oidcFlowFixture struct {
	router       *gin.Engine
	manager      *jwt.Manager
	user         *model.User
	app          *model.Application
	clientSecret string
}

func setupOIDCFlowFixture(t *testing.T) oidcFlowFixture {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(
		&model.User{},
		&model.Application{},
		&model.AuthorizationCode{},
		&model.AccessToken{},
		&model.RefreshToken{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	appRepo := repository.NewApplicationRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	userRepo := repository.NewUserRepository(db)

	cfg := &config.Config{
		OAuth: config.OAuthConfig{
			AuthCodeTTL:     10 * time.Minute,
			AccessTokenTTL:  time.Hour,
			RefreshTokenTTL: 24 * time.Hour,
			IDTokenTTL:      time.Hour,
		},
		JWT: config.JWTConfig{
			Secret: "test-secret-with-enough-length",
			Issuer: "test-issuer",
		},
	}

	// 关键：service 与 OIDC handler 共享同一个 Manager，
	// 这样 JWKS 暴露的公钥与 ID Token 的 RS256 签名密钥一致。
	manager := jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer)

	oauthService := service.NewOAuthService(appRepo, oauthRepo, userRepo, nil, cfg)
	oauthService.SetJWTManager(manager)

	user := &model.User{
		Email:        "oidc-flow@example.com",
		Username:     "oidcflow",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:      "oidc-flow-client",
		ClientSecret:  "oidc-flow-secret",
		Name:          "OIDC Flow Client",
		UserID:        user.ID,
		AppType:       model.AppTypeConfidential,
		RedirectURIs:  `["` + oidcFlowRedirect + `"]`,
		GrantTypes:    `["authorization_code","refresh_token"]`,
		Scopes:        `["openid","profile","email"]`,
		AllowedScopes: `["openid","profile","email"]`,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	oauthHandler := NewOAuthHandler(oauthService, nil, "", "")
	oidcHandler := NewOIDCHandler(cfg.JWT.Issuer, manager)
	oidcHandler.SetOAuthRepo(oauthRepo)
	oidcHandler.SetApplicationRepo(appRepo)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 授权提交端点依赖已认证用户上下文，用中间件模拟登录会话。
	router.POST("/api/oauth/authorize", func(c *gin.Context) {
		gctx.SetUser(c, user.ID, user.Email, user.Username, string(user.Role))
		gctx.SetAuthTime(c, time.Now().Unix())
		gctx.SetAuthMethods(c, []string{jwt.AuthenticationMethodPassword})
		c.Next()
	}, oauthHandler.AuthorizeSubmit)

	router.GET("/oauth/authorize", oauthHandler.Authorize)
	router.POST("/oauth/token", oauthHandler.Token)
	router.GET("/oauth/userinfo", oauthHandler.UserInfo)
	router.POST("/oauth/userinfo", oauthHandler.UserInfo)
	router.POST("/oauth/revoke", oauthHandler.Revoke)
	router.POST("/oauth/introspect", oauthHandler.Introspect)

	router.GET("/.well-known/openid-configuration", oidcHandler.Discovery)
	router.GET("/.well-known/jwks.json", oidcHandler.JWKS)

	return oidcFlowFixture{
		router:       router,
		manager:      manager,
		user:         user,
		app:          app,
		clientSecret: app.ClientSecret,
	}
}

/* pkceChallenge 计算 S256 code_challenge */
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

/* newOIDCFlowRequest 构造携带 issuer host 的请求（issuer 由 host + X-Forwarded-Proto 推导） */
func newOIDCFlowRequest(method, target string, body *strings.Reader) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, body)
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Host = oidcFlowIssuerHost
	req.Header.Set("X-Forwarded-Proto", "https")
	return req
}

/*
 * doAuthorize 提交授权同意，返回授权码。
 */
func (f oidcFlowFixture) doAuthorize(t *testing.T, scope, state, nonce, codeChallenge string) string {
	t.Helper()

	payload := map[string]string{
		"client_id":             f.app.ClientID,
		"redirect_uri":          oidcFlowRedirect,
		"response_type":         "code",
		"scope":                 scope,
		"state":                 state,
		"nonce":                 nonce,
		"code_challenge":        codeChallenge,
		"code_challenge_method": "S256",
		"consent":               "allow",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal authorize payload: %v", err)
	}

	req := newOIDCFlowRequest(http.MethodPost, "/api/oauth/authorize", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("authorize status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Code        string `json:"code"`
			State       string `json:"state"`
			RedirectURL string `json:"redirect_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode authorize response: %v body=%s", err, rec.Body.String())
	}
	if !resp.Success {
		t.Fatalf("authorize success=false body=%s", rec.Body.String())
	}
	if resp.Data.Code == "" {
		t.Fatalf("authorize returned empty code body=%s", rec.Body.String())
	}
	if resp.Data.State != state {
		t.Fatalf("authorize state=%q want %q", resp.Data.State, state)
	}
	// redirect_url 应回跳到已登记的 redirect_uri 并携带 code。
	parsed, err := url.Parse(resp.Data.RedirectURL)
	if err != nil {
		t.Fatalf("parse redirect_url=%q: %v", resp.Data.RedirectURL, err)
	}
	if parsed.Query().Get("code") != resp.Data.Code {
		t.Fatalf("redirect_url code=%q want %q", parsed.Query().Get("code"), resp.Data.Code)
	}
	return resp.Data.Code
}

/*
 * doToken 用授权码换取 token。
 */
func (f oidcFlowFixture) doToken(t *testing.T, code, codeVerifier string) service.TokenResult {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", oidcFlowRedirect)
	form.Set("client_id", f.app.ClientID)
	form.Set("client_secret", f.clientSecret)
	form.Set("code_verifier", codeVerifier)

	req := newOIDCFlowRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("token status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result service.TokenResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode token response: %v body=%s", err, rec.Body.String())
	}
	return result
}

/* jwtHeaderAlg 提取 JWT 头部的 alg 值 */
func jwtHeaderAlg(t *testing.T, token string) string {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWS (parts=%d): %q", len(parts), token)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode jwt header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal jwt header: %v", err)
	}
	return header.Alg
}

func TestOIDCFlow_AuthorizationCodeWithPKCE(t *testing.T) {
	f := setupOIDCFlowFixture(t)

	scope := "openid profile email"
	state := "state-abc-123"
	nonce := "nonce-xyz-789"
	challenge := pkceChallenge(oidcFlowCodeVerifier)

	code := f.doAuthorize(t, scope, state, nonce, challenge)
	result := f.doToken(t, code, oidcFlowCodeVerifier)

	if result.AccessToken == "" {
		t.Fatal("access_token is empty")
	}
	if result.TokenType != "Bearer" {
		t.Fatalf("token_type=%q want Bearer", result.TokenType)
	}
	if result.RefreshToken == "" {
		t.Fatal("refresh_token is empty")
	}
	if result.IDToken == "" {
		t.Fatal("id_token is empty")
	}
	if result.Scope != scope {
		t.Fatalf("scope=%q want %q", result.Scope, scope)
	}

	// ID Token 必须为 RS256 签名。
	if alg := jwtHeaderAlg(t, result.IDToken); alg != "RS256" {
		t.Fatalf("id_token alg=%q want RS256", alg)
	}

	// 通过 Provider RSA 公钥校验 ID Token，并断言标准 claims。
	claims, err := f.manager.ValidateClientIDTokenWithIssuer(result.IDToken, f.app.ClientID, f.clientSecret, oidcFlowIssuer)
	if err != nil {
		t.Fatalf("validate id_token: %v", err)
	}
	if claims.TokenType != jwt.TokenTypeIDToken {
		t.Fatalf("id_token token_type=%q want %q", claims.TokenType, jwt.TokenTypeIDToken)
	}
	if claims.Subject != f.user.ID.String() {
		t.Fatalf("id_token sub=%q want %q", claims.Subject, f.user.ID.String())
	}
	if claims.Issuer != oidcFlowIssuer {
		t.Fatalf("id_token iss=%q want %q", claims.Issuer, oidcFlowIssuer)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != f.app.ClientID {
		t.Fatalf("id_token aud=%v want [%s]", claims.Audience, f.app.ClientID)
	}
	if claims.Nonce != nonce {
		t.Fatalf("id_token nonce=%q want %q", claims.Nonce, nonce)
	}
	if claims.AuthorizedParty != f.app.ClientID {
		t.Fatalf("id_token azp=%q want %q", claims.AuthorizedParty, f.app.ClientID)
	}
	if claims.AuthTime <= 0 {
		t.Fatalf("id_token auth_time=%d want > 0", claims.AuthTime)
	}
	if wantHash := jwt.AccessTokenHash(result.AccessToken); claims.ATHash != wantHash {
		t.Fatalf("id_token at_hash=%q want %q", claims.ATHash, wantHash)
	}

	// 用 access_token 请求 userinfo 端点。
	userInfoReq := newOIDCFlowRequest(http.MethodGet, "/oauth/userinfo", nil)
	userInfoReq.Header.Set("Authorization", "Bearer "+result.AccessToken)
	userInfoRec := httptest.NewRecorder()
	f.router.ServeHTTP(userInfoRec, userInfoReq)

	if userInfoRec.Code != http.StatusOK {
		t.Fatalf("userinfo status=%d want %d body=%s", userInfoRec.Code, http.StatusOK, userInfoRec.Body.String())
	}
	var userInfo struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := json.Unmarshal(userInfoRec.Body.Bytes(), &userInfo); err != nil {
		t.Fatalf("decode userinfo: %v body=%s", err, userInfoRec.Body.String())
	}
	if userInfo.Sub != f.user.ID.String() {
		t.Fatalf("userinfo sub=%q want %q", userInfo.Sub, f.user.ID.String())
	}
	if userInfo.PreferredUsername != f.user.Username {
		t.Fatalf("userinfo preferred_username=%q want %q", userInfo.PreferredUsername, f.user.Username)
	}
	if userInfo.Email != f.user.Email {
		t.Fatalf("userinfo email=%q want %q", userInfo.Email, f.user.Email)
	}
}

func TestOIDCFlow_IDTokenRS256Signature(t *testing.T) {
	f := setupOIDCFlowFixture(t)

	scope := "openid profile"
	challenge := pkceChallenge(oidcFlowCodeVerifier)
	code := f.doAuthorize(t, scope, "state-sig", "nonce-sig", challenge)
	result := f.doToken(t, code, oidcFlowCodeVerifier)
	if result.IDToken == "" {
		t.Fatal("id_token is empty")
	}

	// 从 JWKS 端点获取公钥。
	jwksReq := newOIDCFlowRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	jwksRec := httptest.NewRecorder()
	f.router.ServeHTTP(jwksRec, jwksReq)
	if jwksRec.Code != http.StatusOK {
		t.Fatalf("jwks status=%d want %d body=%s", jwksRec.Code, http.StatusOK, jwksRec.Body.String())
	}
	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(jwksRec.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("decode jwks: %v body=%s", err, jwksRec.Body.String())
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("jwks keys length=%d want 1", len(jwks.Keys))
	}

	// ID Token 头部声明的 kid 必须与 JWKS 中的 kid 一致。
	idTokenKid := jwtHeaderKid(t, result.IDToken)
	jwk := jwks.Keys[0]
	if kid, _ := jwk["kid"].(string); kid != idTokenKid {
		t.Fatalf("jwks kid=%v want %q", jwk["kid"], idTokenKid)
	}

	pub := rsaPublicKeyFromJWK(t, jwk)

	// 使用 JWKS 重建的公钥离线验证 RS256 签名。
	parsed, err := gojwt.Parse(result.IDToken, func(token *gojwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*gojwt.SigningMethodRSA); !ok {
			t.Fatalf("id_token signing method=%T want RSA", token.Method)
		}
		return pub, nil
	}, gojwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("verify id_token with jwks public key: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("id_token failed verification against jwks public key")
	}
}

/* jwtHeaderKid 提取 JWT 头部的 kid 值 */
func jwtHeaderKid(t *testing.T, token string) string {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWS (parts=%d)", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode jwt header: %v", err)
	}
	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal jwt header: %v", err)
	}
	return header.Kid
}

/* rsaPublicKeyFromJWK 从 JWK（RFC 7517）的 n/e 参数重建 RSA 公钥 */
func rsaPublicKeyFromJWK(t *testing.T, jwk map[string]interface{}) *rsa.PublicKey {
	t.Helper()

	nStr, ok := jwk["n"].(string)
	if !ok || nStr == "" {
		t.Fatalf("jwk n missing: %#v", jwk)
	}
	eStr, ok := jwk["e"].(string)
	if !ok || eStr == "" {
		t.Fatalf("jwk e missing: %#v", jwk)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		t.Fatalf("decode jwk n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		t.Fatalf("decode jwk e: %v", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}
}

func TestOIDCFlow_DiscoveryEndpointsConsistency(t *testing.T) {
	f := setupOIDCFlowFixture(t)

	discoveryReq := newOIDCFlowRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	discoveryRec := httptest.NewRecorder()
	f.router.ServeHTTP(discoveryRec, discoveryReq)
	if discoveryRec.Code != http.StatusOK {
		t.Fatalf("discovery status=%d want %d body=%s", discoveryRec.Code, http.StatusOK, discoveryRec.Body.String())
	}

	var discovery map[string]interface{}
	if err := json.Unmarshal(discoveryRec.Body.Bytes(), &discovery); err != nil {
		t.Fatalf("decode discovery: %v body=%s", err, discoveryRec.Body.String())
	}

	if got, _ := discovery["issuer"].(string); got != oidcFlowIssuer {
		t.Fatalf("issuer=%q want %q", got, oidcFlowIssuer)
	}

	// Discovery 声明的核心端点应可访问（非 404），且路径与 issuer 同源。
	probes := []struct {
		key    string
		method string
	}{
		{"jwks_uri", http.MethodGet},
		{"authorization_endpoint", http.MethodGet},
		{"userinfo_endpoint", http.MethodGet},
		{"token_endpoint", http.MethodPost},
		{"revocation_endpoint", http.MethodPost},
		{"introspection_endpoint", http.MethodPost},
	}

	for _, probe := range probes {
		endpoint, ok := discovery[probe.key].(string)
		if !ok || endpoint == "" {
			t.Fatalf("discovery %s missing", probe.key)
		}
		if !strings.HasPrefix(endpoint, oidcFlowIssuer+"/") {
			t.Fatalf("discovery %s=%q not under issuer %q", probe.key, endpoint, oidcFlowIssuer)
		}
		path := strings.TrimPrefix(endpoint, oidcFlowIssuer)

		var body *strings.Reader
		req := newOIDCFlowRequest(probe.method, path, body)
		if probe.method == http.MethodPost {
			req = newOIDCFlowRequest(probe.method, path, strings.NewReader(""))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		rec := httptest.NewRecorder()
		f.router.ServeHTTP(rec, req)

		if rec.Code == http.StatusNotFound {
			t.Fatalf("discovery %s endpoint %s returned 404 (route not registered)", probe.key, path)
		}
	}
}
