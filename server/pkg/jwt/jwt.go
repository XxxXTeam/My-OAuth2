/**
 * @file        jwt.go
 * @package     jwt
 * @description JWT 令牌管理：生成、验证、Claims 解析；支持 access/refresh 区分与 client audience 隔离
 */
package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

/**
 * TokenType 令牌类型枚举
 * @enum {string}
 */
type TokenType string

const (
	/** 访问令牌 — 短期有效，用于 API 鉴权 */
	TokenTypeAccess TokenType = "access"

	/** 刷新令牌 — 长期有效，用于换取新的 access token */
	TokenTypeRefresh TokenType = "refresh"

	/** OpenID Connect ID Token（JWT，仅用于 OIDC 身份声明） */
	TokenTypeIDToken TokenType = "id_token"

	/** RFC 8176: Password-based authentication AMR value */
	AuthenticationMethodPassword = "pwd"

	/** RFC 8176: Multi-factor one-time or SSO-backed external authentication marker */
	AuthenticationMethodFederated = "federated"
)

var (
	/** token 解析失败或签名不合法 */
	ErrInvalidToken = errors.New("invalid token")

	/** 签发或校验 token 时缺少必要签名密钥 */
	ErrMissingSigningKey = errors.New("missing signing key")

	/** token 已过期 */
	ErrExpiredToken = errors.New("token has expired")

	/** access 与 refresh 类型不匹配（如把 refresh 当 access 使用） */
	ErrTokenTypeMismatch = errors.New("token type mismatch")
)

/**
 * Claims JWT 自定义声明
 *
 * @description
 *   包含用户身份、角色、令牌类型与可选的 client 归属。
 *   ClientID 用于区分"中央 token"（=""）与"外部 SDK token"（=client_id），
 *   中央 AdminOnly 中间件会拒绝 ClientID!="" 的 token 防止 SDK 越权进控制台。
 *
 * @field {uuid.UUID}  UserID    - 用户唯一标识
 * @field {string}     Email     - 用户邮箱
 * @field {string}     Username  - 用户名
 * @field {string}     Role      - 角色（admin/user/service）
 * @field {TokenType}  TokenType - access 或 refresh
 * @field {string}     ClientID  - 颁发方 client_id；""=中央颁发；非空=外部应用 scoped token
 * @field {string}     Nonce     - OIDC id_token nonce；由授权请求原样传递
 * @field {int64}      AuthTime  - 终端用户最近一次完成认证的 Unix 秒级时间
 * @field {[]string}   AMR       - OIDC Authentication Methods References
 * @field {string}     ATHash    - OIDC at_hash，绑定同一响应中的 access_token
 * @field {string}     AuthorizedParty - OIDC azp，标识 ID Token 授权给哪个 client
 * @security ClientID!="" 的 token 不能进入 /api/admin/*
 */
type Claims struct {
	UserID          uuid.UUID `json:"user_id"`
	Email           string    `json:"email"`
	Username        string    `json:"username"`
	Role            string    `json:"role"`
	TokenType       TokenType `json:"token_type"`
	ClientID        string    `json:"client_id,omitempty"`
	Scope           string    `json:"scope,omitempty"` /* OIDC id_token 授权 scope */
	Nonce           string    `json:"nonce,omitempty"`
	AuthTime        int64     `json:"auth_time,omitempty"`
	AMR             []string  `json:"amr,omitempty"`
	ATHash          string    `json:"at_hash,omitempty"`
	AuthorizedParty string    `json:"azp,omitempty"`
	jwt.RegisteredClaims
}

/**
 * Manager JWT 管理器
 *
 * @description Access/Refresh token 使用 HS256（HMAC-SHA256）签名；
 *              ID Token 使用 RS256（RSA-SHA256）签名，公钥通过 JWKS 端点暴露。
 */
type Manager struct {
	secretKey []byte
	encKey    []byte
	issuer    string
	rsaKey    *rsa.PrivateKey
	rsaPub    *rsa.PublicKey
	keyID     string
}

/**
 * NewManager 创建 JWT 管理器实例
 *
 * @param  {string} secretKey - HMAC 签名密钥（至少 32 字节）
 * @param  {string} issuer    - JWT iss 字段
 * @returns {*Manager}
 */
func NewManager(secretKey, issuer string) *Manager {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &Manager{
		secretKey: []byte(secretKey),
		encKey:    deriveEncryptionKey(secretKey),
		issuer:    issuer,
		rsaKey:    key,
		rsaPub:    &key.PublicKey,
		keyID:     "oauth2-key-1",
	}
}

/** SetRSAKey 注入持久化的 RSA 密钥对（用于 ID Token RS256 签名） */
func (m *Manager) SetRSAKey(key *rsa.PrivateKey) {
	if key != nil {
		m.rsaKey = key
		m.rsaPub = &key.PublicKey
	}
}

/** PublicKey 返回 RSA 公钥（供 JWKS 端点暴露） */
func (m *Manager) PublicKey() *rsa.PublicKey {
	return m.rsaPub
}

/** KeyID 返回 JWKS kid */
func (m *Manager) KeyID() string {
	return m.keyID
}

/** RSAPrivateKey 返回 RSA 私钥（仅供测试使用） */
func (m *Manager) RSAPrivateKey() *rsa.PrivateKey {
	return m.rsaKey
}

/**
 * GenerateToken 生成"中央 token"（aud=issuer，ClientID=""）
 *
 * @description
 *   适用于 /api/auth/login、密码刷新等中央认证流程颁发的 token。
 *   这类 token 通过 AdminOnly 中间件后可访问 /api/admin/*。
 *
 * @param  {uuid.UUID}     userID    - 用户 UUID
 * @param  {string}        email     - 用户邮箱
 * @param  {string}        username  - 用户名
 * @param  {string}        role      - 角色（admin/user）
 * @param  {TokenType}     tokenType - access 或 refresh
 * @param  {time.Duration} ttl       - token 有效期
 * @returns {string, error} 签名后的 JWT 字符串
 */
func (m *Manager) GenerateToken(userID uuid.UUID, email, username, role string, tokenType TokenType, ttl time.Duration) (string, error) {
	return m.GenerateTokenWithAuthTime(userID, email, username, role, tokenType, time.Now().Unix(), ttl)
}

/* GenerateTokenWithAuthTime 生成带 auth_time 的中央 token */
func (m *Manager) GenerateTokenWithAuthTime(userID uuid.UUID, email, username, role string, tokenType TokenType, authTime int64, ttl time.Duration) (string, error) {
	return m.GenerateTokenWithAuthTimeAndAMR(userID, email, username, role, tokenType, authTime, nil, ttl)
}

/* GenerateTokenWithAuthTimeAndAMR 生成带 auth_time/amr 的中央 token */
func (m *Manager) GenerateTokenWithAuthTimeAndAMR(userID uuid.UUID, email, username, role string, tokenType TokenType, authTime int64, amr []string, ttl time.Duration) (string, error) {
	return m.generate(userID, email, username, role, "", tokenType, "", "", authTime, amr, ttl)
}

/**
 * GenerateClientToken 生成"外部 client scoped token"（aud=client_id，ClientID=client_id）
 *
 * @description
 *   适用于 SDK 端点（/api/sdk/login 等）、/token/sign 颁发给外部 client 的 token。
 *   这类 token 携带 ClientID 标识颁发方，中央 AdminOnly 中间件会拒绝其访问 /api/admin/*。
 *
 * @param  {uuid.UUID}     userID    - 用户 UUID（=app 所有者或登录用户）
 * @param  {string}        email     - 用户邮箱
 * @param  {string}        username  - 用户名
 * @param  {string}        role      - 角色（中央颁发时透传；/token/sign 应强制 "service"）
 * @param  {string}        clientID  - 颁发方 client_id（非空）
 * @param  {TokenType}     tokenType - access 或 refresh
 * @param  {time.Duration} ttl       - token 有效期
 * @returns {string, error} 签名后的 JWT 字符串
 * @security ClientID!="" 在 AdminOnly 中间件会被拒绝
 */
func (m *Manager) GenerateClientToken(userID uuid.UUID, email, username, role, clientID string, tokenType TokenType, ttl time.Duration) (string, error) {
	return m.GenerateClientTokenWithScope(userID, email, username, role, clientID, "", tokenType, ttl)
}

/* GenerateClientTokenWithScope 签发带 scope 的外部 client JWT（OAuth access/refresh） */
func (m *Manager) GenerateClientTokenWithScope(userID uuid.UUID, email, username, role, clientID, scope string, tokenType TokenType, ttl time.Duration) (string, error) {
	return m.GenerateClientTokenWithScopeAndAuthTime(userID, email, username, role, clientID, scope, tokenType, time.Now().Unix(), ttl)
}

/* GenerateClientTokenWithScopeAndAuthTime 签发带 scope/auth_time 的外部 client JWT */
func (m *Manager) GenerateClientTokenWithScopeAndAuthTime(userID uuid.UUID, email, username, role, clientID, scope string, tokenType TokenType, authTime int64, ttl time.Duration) (string, error) {
	return m.GenerateClientTokenWithScopeAndAuthTimeAndAMR(userID, email, username, role, clientID, scope, tokenType, authTime, nil, ttl)
}

/* GenerateClientTokenWithScopeAndAuthTimeAndAMR 签发带 scope/auth_time/amr 的外部 client JWT */
func (m *Manager) GenerateClientTokenWithScopeAndAuthTimeAndAMR(userID uuid.UUID, email, username, role, clientID, scope string, tokenType TokenType, authTime int64, amr []string, ttl time.Duration) (string, error) {
	return m.generate(userID, email, username, role, clientID, tokenType, scope, "", authTime, amr, ttl)
}

/*
 * GenerateIDToken 签发 OpenID Connect id_token（JWT）
 * @param scope - 授权 scope 字符串（含 openid 时由调用方保证）
 */
func (m *Manager) GenerateIDToken(userID uuid.UUID, email, username, role, clientID, scope string, ttl time.Duration) (string, error) {
	return m.GenerateIDTokenWithNonce(userID, email, username, role, clientID, scope, "", ttl)
}

/*
 * GenerateIDTokenWithNonce 签发带 OIDC nonce 的 id_token
 */
func (m *Manager) GenerateIDTokenWithNonce(userID uuid.UUID, email, username, role, clientID, scope, nonce string, ttl time.Duration) (string, error) {
	return m.GenerateIDTokenWithNonceAndAuthTime(userID, email, username, role, clientID, scope, nonce, 0, ttl)
}

/*
 * GenerateIDTokenWithNonceAndAuthTime 签发带 OIDC nonce/auth_time 的 id_token
 */
func (m *Manager) GenerateIDTokenWithNonceAndAuthTime(userID uuid.UUID, email, username, role, clientID, scope, nonce string, authTime int64, ttl time.Duration) (string, error) {
	return m.GenerateIDTokenWithNonceAndAuthTimeAndAMR(userID, email, username, role, clientID, scope, nonce, authTime, nil, ttl)
}

/* GenerateIDTokenWithNonceAndAuthTimeAndAMR 签发带 OIDC nonce/auth_time/amr 的 id_token */
func (m *Manager) GenerateIDTokenWithNonceAndAuthTimeAndAMR(userID uuid.UUID, email, username, role, clientID, scope, nonce string, authTime int64, amr []string, ttl time.Duration) (string, error) {
	return m.generate(userID, email, username, role, clientID, TokenTypeIDToken, scope, nonce, authTime, amr, ttl)
}

/* GenerateIDTokenWithNonceAndAuthTimeAndAMRAndATHash 签发带 at_hash 的 OIDC id_token */
func (m *Manager) GenerateIDTokenWithNonceAndAuthTimeAndAMRAndATHash(userID uuid.UUID, email, username, role, clientID, scope, nonce string, authTime int64, amr []string, atHash string, ttl time.Duration) (string, error) {
	return m.generateWithATHash(userID, email, username, role, clientID, TokenTypeIDToken, scope, nonce, authTime, amr, atHash, ttl)
}

/*
 * GenerateClientIDTokenWithNonceAndAuthTime 签发外部 client 可按 OIDC HS256 校验的明文 JWS id_token
 * OIDC Core 要求 HS256 id_token 使用 client_secret 作为 HMAC 密钥。
 */
func (m *Manager) GenerateClientIDTokenWithNonceAndAuthTime(userID uuid.UUID, email, username, role, clientID, clientSecret, scope, nonce string, authTime int64, ttl time.Duration) (string, error) {
	return m.GenerateClientIDTokenWithNonceAndAuthTimeAndAMR(userID, email, username, role, clientID, clientSecret, scope, nonce, authTime, nil, ttl)
}

func (m *Manager) GenerateClientIDTokenWithNonceAndAuthTimeAndAMR(userID uuid.UUID, email, username, role, clientID, clientSecret, scope, nonce string, authTime int64, amr []string, ttl time.Duration) (string, error) {
	return m.GenerateClientIDTokenWithIssuerAndNonceAndAuthTimeAndAMR(userID, email, username, role, clientID, clientSecret, "", scope, nonce, authTime, amr, ttl)
}

func (m *Manager) GenerateClientIDTokenWithNonceAndAuthTimeAndAMRAndATHash(userID uuid.UUID, email, username, role, clientID, clientSecret, scope, nonce string, authTime int64, amr []string, atHash string, ttl time.Duration) (string, error) {
	return m.GenerateClientIDTokenWithIssuerAndNonceAndAuthTimeAndAMRAndATHash(userID, email, username, role, clientID, clientSecret, "", scope, nonce, authTime, amr, atHash, ttl)
}

func (m *Manager) GenerateClientIDTokenWithIssuerAndNonceAndAuthTime(userID uuid.UUID, email, username, role, clientID, clientSecret, issuer, scope, nonce string, authTime int64, ttl time.Duration) (string, error) {
	return m.GenerateClientIDTokenWithIssuerAndNonceAndAuthTimeAndAMR(userID, email, username, role, clientID, clientSecret, issuer, scope, nonce, authTime, nil, ttl)
}

func (m *Manager) GenerateClientIDTokenWithIssuerAndNonceAndAuthTimeAndAMR(userID uuid.UUID, email, username, role, clientID, clientSecret, issuer, scope, nonce string, authTime int64, amr []string, ttl time.Duration) (string, error) {
	return m.GenerateClientIDTokenWithIssuerAndNonceAndAuthTimeAndAMRAndATHash(userID, email, username, role, clientID, clientSecret, issuer, scope, nonce, authTime, amr, "", ttl)
}

func (m *Manager) GenerateClientIDTokenWithIssuerAndNonceAndAuthTimeAndAMRAndATHash(userID uuid.UUID, email, username, role, clientID, clientSecret, issuer, scope, nonce string, authTime int64, amr []string, atHash string, ttl time.Duration) (string, error) {
	if clientID == "" {
		return "", ErrMissingSigningKey
	}
	return m.generateIDTokenRS256(userID, email, username, role, clientID, scope, nonce, authTime, amr, atHash, ttl, issuer)
}

/** generateIDTokenRS256 使用 RSA-SHA256 签发 ID Token（供 RP 通过 JWKS 离线验证） */
func (m *Manager) generateIDTokenRS256(userID uuid.UUID, email, username, role, clientID, scope, nonce string, authTime int64, amr []string, atHash string, ttl time.Duration, issuer string) (string, error) {
	if m.rsaKey == nil {
		return "", ErrMissingSigningKey
	}
	if issuer == "" {
		issuer = m.issuer
	}
	now := time.Now()
	if authTime < 0 {
		authTime = 0
	}

	claims := &Claims{
		UserID:          userID,
		Email:           email,
		Username:        username,
		Role:            role,
		TokenType:       TokenTypeIDToken,
		ClientID:        clientID,
		Scope:           scope,
		Nonce:           nonce,
		AuthTime:        authTime,
		AMR:             normalizeAMR(amr),
		ATHash:          atHash,
		AuthorizedParty: clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        generateSecureJTI(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.keyID
	return token.SignedString(m.rsaKey)
}

/**
 * generate 内部统一签发逻辑
 *
 * @param  {string} clientID - 空字符串=中央 token；非空=client scoped
 * @returns {string, error}
 */
func (m *Manager) generate(userID uuid.UUID, email, username, role, clientID string, tokenType TokenType, scope, nonce string, authTime int64, amr []string, ttl time.Duration) (string, error) {
	return m.generateWithIssuerAndKey(userID, email, username, role, clientID, tokenType, scope, nonce, authTime, amr, ttl, "", m.secretKey, true)
}

func (m *Manager) generateWithATHash(userID uuid.UUID, email, username, role, clientID string, tokenType TokenType, scope, nonce string, authTime int64, amr []string, atHash string, ttl time.Duration) (string, error) {
	return m.generateWithIssuerAndKeyAndATHash(userID, email, username, role, clientID, tokenType, scope, nonce, authTime, amr, atHash, ttl, "", m.secretKey, true)
}

func (m *Manager) generateWithKey(userID uuid.UUID, email, username, role, clientID string, tokenType TokenType, scope, nonce string, authTime int64, amr []string, ttl time.Duration, signingKey []byte, encrypt bool) (string, error) {
	return m.generateWithIssuerAndKey(userID, email, username, role, clientID, tokenType, scope, nonce, authTime, amr, ttl, "", signingKey, encrypt)
}

func (m *Manager) generateWithIssuerAndKey(userID uuid.UUID, email, username, role, clientID string, tokenType TokenType, scope, nonce string, authTime int64, amr []string, ttl time.Duration, issuer string, signingKey []byte, encrypt bool) (string, error) {
	return m.generateWithIssuerAndKeyAndATHash(userID, email, username, role, clientID, tokenType, scope, nonce, authTime, amr, "", ttl, issuer, signingKey, encrypt)
}

func (m *Manager) generateWithIssuerAndKeyAndATHash(userID uuid.UUID, email, username, role, clientID string, tokenType TokenType, scope, nonce string, authTime int64, amr []string, atHash string, ttl time.Duration, issuer string, signingKey []byte, encrypt bool) (string, error) {
	if len(signingKey) == 0 {
		return "", ErrMissingSigningKey
	}
	if issuer == "" {
		issuer = m.issuer
	}
	now := time.Now()
	if authTime < 0 {
		authTime = 0
	}

	/* audience：中央 token 用 issuer；client token 用 client_id，便于资源服务器按 aud 路由 */
	aud := jwt.ClaimStrings{issuer}
	if clientID != "" {
		aud = jwt.ClaimStrings{clientID}
	}
	authorizedParty := ""
	if tokenType == TokenTypeIDToken && clientID != "" {
		authorizedParty = clientID
	}

	claims := &Claims{
		UserID:          userID,
		Email:           email,
		Username:        username,
		Role:            role,
		TokenType:       tokenType,
		ClientID:        clientID,
		Scope:           scope,
		Nonce:           nonce,
		AuthTime:        authTime,
		AMR:             normalizeAMR(amr),
		ATHash:          atHash,
		AuthorizedParty: authorizedParty,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID.String(),
			Audience:  aud,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        generateSecureJTI(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}
	if !encrypt {
		return signed, nil
	}
	return encryptSignedJWT(m.encKey, signed)
}

func AccessTokenHash(accessToken string) string {
	if accessToken == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
}

func normalizeAMR(amr []string) []string {
	if len(amr) == 0 {
		return nil
	}
	out := make([]string, 0, len(amr))
	for _, value := range amr {
		if value == "" || slices.Contains(out, value) {
			continue
		}
		out = append(out, value)
	}
	return out
}

/**
 * ValidateToken 验证 token 并返回 claims（不校验 token 类型）
 *
 * @description
 *   强制校验 alg=HS256 防止 alg:none / RS256 混淆攻击；强制校验 issuer 防止跨服务 token 混用。
 *   注意：本方法不校验 audience（既允许中央 token 也允许 client token），调用方自行处理。
 *
 * @param  {string} tokenString - JWT 字符串
 * @returns {*Claims, error}
 * @throws {ErrExpiredToken} token 已过期
 * @throws {ErrInvalidToken} 签名/算法/issuer 不合法
 */
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	signed, err := decryptTokenIfNeeded(m.encKey, tokenString)
	if err != nil {
		return nil, ErrInvalidToken
	}
	token, err := jwt.ParseWithClaims(signed, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		/* 强制 HMAC 签名算法，阻止 alg:none / alg:RS256 混淆攻击 */
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return m.secretKey, nil
	}, jwt.WithIssuer(m.issuer), jwt.WithValidMethods([]string{"HS256"}))

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

/*
 * ValidateClientIDToken 校验 RS256 签名的 ID Token。
 * 使用 Provider RSA 公钥验证，同时校验 issuer、audience、token_type 和 client_id。
 * clientSecret 参数保留以兼容接口签名，但不再用于验证（ID Token 统一使用 Provider RSA 密钥签名）。
 */
func (m *Manager) ValidateClientIDToken(tokenString, clientID, clientSecret string) (*Claims, error) {
	return m.ValidateClientIDTokenWithIssuer(tokenString, clientID, clientSecret, "")
}

func (m *Manager) ValidateClientIDTokenWithIssuer(tokenString, clientID, clientSecret, issuer string) (*Claims, error) {
	if clientID == "" {
		return nil, ErrMissingSigningKey
	}
	if issuer == "" {
		issuer = m.issuer
	}
	if m.rsaPub == nil {
		return nil, ErrMissingSigningKey
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrInvalidToken
		}
		return m.rsaPub, nil
	}, jwt.WithIssuer(issuer), jwt.WithAudience(clientID), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	if claims.TokenType != TokenTypeIDToken || claims.ClientID != clientID {
		return nil, ErrInvalidToken
	}
	if claims.AuthorizedParty != "" && claims.AuthorizedParty != clientID {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

/* ParseUnverifiedClaims 仅解析 claims，用于根据 client_id 定位校验密钥；不能作为认证结果使用。 */
func (m *Manager) ParseUnverifiedClaims(tokenString string) (*Claims, error) {
	signed, err := decryptTokenIfNeeded(m.encKey, tokenString)
	if err != nil {
		return nil, ErrInvalidToken
	}
	parser := jwt.NewParser()
	claims := &Claims{}
	if _, _, err := parser.ParseUnverified(signed, claims); err != nil {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

/**
 * ValidateAccessToken 验证 token 且确保是 access 类型
 *
 * @param  {string} tokenString
 * @returns {*Claims, error}
 * @throws {ErrTokenTypeMismatch} 当传入非 access token
 */
func (m *Manager) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != TokenTypeAccess {
		return nil, ErrTokenTypeMismatch
	}
	return claims, nil
}

/**
 * ValidateRefreshToken 验证 token 且确保是 refresh 类型
 *
 * @param  {string} tokenString
 * @returns {*Claims, error}
 * @throws {ErrTokenTypeMismatch} 当传入 access token
 */
func (m *Manager) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != TokenTypeRefresh {
		return nil, ErrTokenTypeMismatch
	}
	return claims, nil
}

/**
 * generateSecureJTI 使用 crypto/rand 生成 32 字符 hex JTI
 *
 * @description 比 uuid.New()（基于 math/rand）更适合安全场景。
 * @returns {string} 32 字符十六进制串
 */
func generateSecureJTI() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return uuid.New().String()
	}
	return hex.EncodeToString(b)
}

func audienceContains(audience jwt.ClaimStrings, value string) bool {
	for _, item := range audience {
		if item == value {
			return true
		}
	}
	return false
}
