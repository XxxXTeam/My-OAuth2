package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"server/internal/model"
	"server/internal/repository"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidClientAssertion     = errors.New("invalid client assertion")
	ErrInvalidClientAssertionType = errors.New("invalid client assertion type")
	ErrClientAssertionExpired     = errors.New("client assertion expired")
	ErrInvalidAudience            = errors.New("invalid audience")
	ErrInvalidIssuer              = errors.New("invalid issuer")
)

/*
 * ClientAuthenticator OAuth2 客户端认证器
 * 功能：支持多种客户端认证方式 - Basic Auth、POST Body、client_secret_jwt、private_key_jwt
 */
type ClientAuthenticator struct {
	appRepo *repository.ApplicationRepository
	issuer  string // Expected audience for client assertions
}

/*
 * NewClientAuthenticator 创建客户端认证器实例
 * @param appRepo - 应用仓储
 * @param issuer  - JWT audience 期望值
 */
func NewClientAuthenticator(appRepo *repository.ApplicationRepository, issuer string) *ClientAuthenticator {
	return &ClientAuthenticator{
		appRepo: appRepo,
		issuer:  issuer,
	}
}

/* ClientAuthResult 客户端认证结果 */
type ClientAuthResult struct {
	App        *model.Application
	AuthMethod model.TokenEndpointAuthMethod
}

/*
 * AuthenticateClient 使用多种方式认证客户端
 * 优先级：client_assertion (JWT) > Basic Auth > POST Body
 * @param c - Gin 上下文
 * @return *ClientAuthResult - 认证结果（包含应用实体和认证方式）
 */
func (ca *ClientAuthenticator) AuthenticateClient(c *gin.Context) (*ClientAuthResult, error) {
	// Check for client_assertion (JWT-based authentication)
	assertionType := c.PostForm("client_assertion_type")
	assertion := c.PostForm("client_assertion")

	if assertion != "" && assertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return ca.authenticateWithJWT(c, assertion)
	}

	// Check for Basic Auth (client_secret_basic)
	clientID, clientSecret, hasBasicAuth := c.Request.BasicAuth()
	if hasBasicAuth && clientID != "" {
		return ca.authenticateWithSecret(clientID, clientSecret, model.AuthMethodClientSecretBasic)
	}

	// Check for POST body (client_secret_post)
	clientID = c.PostForm("client_id")
	clientSecret = c.PostForm("client_secret")
	if clientID != "" && clientSecret != "" {
		return ca.authenticateWithSecret(clientID, clientSecret, model.AuthMethodClientSecretPost)
	}

	// Check for public client (no authentication)
	if clientID != "" {
		return ca.authenticatePublicClient(clientID)
	}

	return nil, errors.New("no client credentials provided")
}

// authenticateWithSecret validates client credentials using shared secret
func (ca *ClientAuthenticator) authenticateWithSecret(clientID, clientSecret string, method model.TokenEndpointAuthMethod) (*ClientAuthResult, error) {
	app, err := ca.appRepo.FindByClientID(clientID)
	if err != nil {
		return nil, errors.New("invalid client")
	}

	// Verify the authentication method is allowed
	if app.TokenEndpointAuthMethod != "" && app.TokenEndpointAuthMethod != method {
		// Allow fallback to other secret-based methods
		if app.TokenEndpointAuthMethod != model.AuthMethodClientSecretBasic &&
			app.TokenEndpointAuthMethod != model.AuthMethodClientSecretPost {
			return nil, errors.New("authentication method not allowed")
		}
	}

	/* 使用常量时间比较验证 client_secret，防止时序攻击 */
	if !hmac.Equal([]byte(app.ClientSecret), []byte(clientSecret)) {
		return nil, errors.New("invalid client secret")
	}

	return &ClientAuthResult{
		App:        app,
		AuthMethod: method,
	}, nil
}

// authenticateWithJWT validates client credentials using JWT assertion
func (ca *ClientAuthenticator) authenticateWithJWT(c *gin.Context, assertion string) (*ClientAuthResult, error) {
	// Parse JWT without verification first to get the issuer (client_id)
	token, _, err := new(jwt.Parser).ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return nil, ErrInvalidClientAssertion
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidClientAssertion
	}

	// Get client_id from issuer or sub claim
	clientID, _ := claims["iss"].(string)
	if clientID == "" {
		clientID, _ = claims["sub"].(string)
	}
	if clientID == "" {
		return nil, ErrInvalidIssuer
	}

	// Look up the application
	app, err := ca.appRepo.FindByClientID(clientID)
	if err != nil {
		return nil, errors.New("invalid client")
	}

	// Determine the signing method and verify
	var verifiedToken *jwt.Token

	switch app.TokenEndpointAuthMethod {
	case model.AuthMethodClientSecretJWT:
		// Verify using HMAC with client_secret
		verifiedToken, err = jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(app.ClientSecret), nil
		})

	case model.AuthMethodPrivateKeyJWT:
		// Verify using RSA/EC public key from JWKS
		verifiedToken, err = ca.verifyWithJWKS(assertion, app)

	default:
		// If not configured, try HMAC first
		verifiedToken, err = jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(app.ClientSecret), nil
		})
	}

	if err != nil || !verifiedToken.Valid {
		return nil, ErrInvalidClientAssertion
	}

	// Validate claims
	verifiedClaims, ok := verifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidClientAssertion
	}

	// Validate audience (should be the authorization server)
	if !ca.validateAudience(verifiedClaims) {
		return nil, ErrInvalidAudience
	}

	// Validate expiration
	if exp, ok := verifiedClaims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, ErrClientAssertionExpired
		}
	}

	// Validate not before
	if nbf, ok := verifiedClaims["nbf"].(float64); ok {
		if time.Now().Unix() < int64(nbf) {
			return nil, ErrInvalidClientAssertion
		}
	}

	authMethod := app.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = model.AuthMethodClientSecretJWT
	}

	return &ClientAuthResult{
		App:        app,
		AuthMethod: authMethod,
	}, nil
}

// authenticatePublicClient handles public clients (no secret required)
func (ca *ClientAuthenticator) authenticatePublicClient(clientID string) (*ClientAuthResult, error) {
	app, err := ca.appRepo.FindByClientID(clientID)
	if err != nil {
		return nil, errors.New("invalid client")
	}

	// Check if this is a public client
	if app.AppType != model.AppTypePublic && app.TokenEndpointAuthMethod != model.AuthMethodNone {
		return nil, errors.New("client authentication required")
	}

	return &ClientAuthResult{
		App:        app,
		AuthMethod: model.AuthMethodNone,
	}, nil
}

// validateAudience checks if the audience claim is valid
func (ca *ClientAuthenticator) validateAudience(claims jwt.MapClaims) bool {
	aud, ok := claims["aud"]
	if !ok {
		return false
	}

	// Audience can be a string or array of strings
	switch v := aud.(type) {
	case string:
		return v == ca.issuer || strings.Contains(v, "/oauth/token")
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok {
				if s == ca.issuer || strings.Contains(s, "/oauth/token") {
					return true
				}
			}
		}
	}
	return false
}

// verifyWithJWKS verifies JWT using the client's JWKS
func (ca *ClientAuthenticator) verifyWithJWKS(assertion string, app *model.Application) (*jwt.Token, error) {
	// Parse JWKS from app configuration
	if app.JWKS == "" && app.JWKSURI == "" {
		return nil, errors.New("no JWKS configured for client")
	}

	var jwks JWKSet
	if app.JWKS != "" {
		if err := json.Unmarshal([]byte(app.JWKS), &jwks); err != nil {
			return nil, errors.New("invalid JWKS")
		}
	} else if app.JWKSURI != "" {
		/* 从远程 JWKS URI 获取公钥集合（限制响应体 1MB，防止恶意大响应） */
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(app.JWKSURI)
		if err != nil {
			return nil, errors.New("failed to fetch JWKS from URI: " + err.Error())
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, errors.New("JWKS URI returned non-200 status")
		}
		limitedBody := http.MaxBytesReader(nil, resp.Body, 1<<20) /* 1MB 限制 */
		if err := json.NewDecoder(limitedBody).Decode(&jwks); err != nil {
			return nil, errors.New("failed to parse JWKS from URI")
		}
	}

	// Parse and verify token
	return jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		// Get key ID from token header
		kid, _ := token.Header["kid"].(string)

		// Find matching key in JWKS
		for _, key := range jwks.Keys {
			if kid != "" && key.Kid != kid {
				continue
			}

			switch key.Kty {
			case "RSA":
				return key.ToRSAPublicKey()
			case "EC":
				return key.ToECPublicKey()
			}
		}
		return nil, errors.New("no matching key found")
	})
}

// JWKSet represents a JSON Web Key Set
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	// RSA keys
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC keys
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

/*
 * ToRSAPublicKey 将 JWK 转换为 RSA 公钥
 * 功能：解析 base64url 编码的 N（模数）和 E（指数），构造 crypto/rsa.PublicKey
 */
func (j *JWK) ToRSAPublicKey() (interface{}, error) {
	if j.Kty != "RSA" {
		return nil, errors.New("not an RSA key")
	}
	if j.N == "" || j.E == "" {
		return nil, errors.New("RSA key missing N or E")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, errors.New("invalid RSA N value")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, errors.New("invalid RSA E value")
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

/*
 * ToECPublicKey 将 JWK 转换为 EC 公钥
 * 功能：解析 base64url 编码的 X/Y 坐标和曲线名称，构造 crypto/ecdsa.PublicKey
 */
func (j *JWK) ToECPublicKey() (interface{}, error) {
	if j.Kty != "EC" {
		return nil, errors.New("not an EC key")
	}
	if j.X == "" || j.Y == "" || j.Crv == "" {
		return nil, errors.New("EC key missing X, Y or Crv")
	}

	var curve elliptic.Curve
	switch j.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, errors.New("unsupported EC curve: " + j.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, errors.New("invalid EC X value")
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, errors.New("invalid EC Y value")
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// GenerateClientSecretJWT generates a client_secret_jwt assertion for testing
func GenerateClientSecretJWT(clientID, clientSecret, audience string, expiry time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"exp": time.Now().Add(expiry).Unix(),
		"iat": time.Now().Unix(),
		"jti": generateJTI(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(clientSecret))
}

/*
 * generateJTI 生成唯一的 JWT ID
 * 使用 crypto/rand 生成安全随机字节，替代基于时间的弱随机源
 */
func generateJTI() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		/* 回退：使用时间戳哈希（不应到达此处） */
		h := hmac.New(sha256.New, []byte(time.Now().String()))
		return base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:16]
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ClientAuthMiddleware creates a Gin middleware for client authentication
func ClientAuthMiddleware(authenticator *ClientAuthenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		result, err := authenticator.AuthenticateClient(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_client",
				"error_description": err.Error(),
			})
			return
		}

		// Store result in context
		c.Set("client_auth", result)
		c.Set("client_app", result.App)
		c.Next()
	}
}
