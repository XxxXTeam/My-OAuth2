/*
 * Package jwt JWT 令牌管理包
 * 功能：提供 JWT 的生成、验证和 Claims 解析，支持 access/refresh 令牌类型区分
 */
package jwt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

/*
 * TokenType 令牌类型枚举
 * @value TokenTypeAccess  - 访问令牌
 * @value TokenTypeRefresh - 刷新令牌
 */
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrExpiredToken      = errors.New("token has expired")
	ErrTokenTypeMismatch = errors.New("token type mismatch")
)

/*
 * Claims JWT 自定义声明
 * 功能：包含用户 ID、邮箱、用户名、角色和令牌类型，继承 JWT 标准声明
 */
type Claims struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	TokenType TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

/*
 * Manager JWT 管理器
 * 功能：使用 HMAC-SHA256 签名算法生成和验证 JWT
 */
type Manager struct {
	secretKey []byte
	issuer    string
}

/*
 * NewManager 创建 JWT 管理器实例
 * @param secretKey - HMAC 签名密钥
 * @param issuer    - JWT 签发者标识 (iss)
 */
func NewManager(secretKey, issuer string) *Manager {
	return &Manager{
		secretKey: []byte(secretKey),
		issuer:    issuer,
	}
}

/*
 * GenerateToken 生成 JWT token
 * tokenType: 区分 access/refresh，防止 refresh token 被当作 access token 使用
 * audience:  token 受众（可选，为空时使用 issuer）
 */
func (m *Manager) GenerateToken(userID uuid.UUID, email, username, role string, tokenType TokenType, ttl time.Duration) (string, error) {
	now := time.Now()
	aud := jwt.ClaimStrings{m.issuer}

	claims := &Claims{
		UserID:    userID,
		Email:     email,
		Username:  username,
		Role:      role,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			Audience:  aud,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        generateSecureJTI(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

/*
 * ValidateToken 验证 JWT token 并返回 claims（不校验 token 类型）
 * 安全增强：
 *   - 强制校验签名算法为 HMAC，防止 alg=none 攻击
 *   - 校验 issuer 一致性，防止跨服务 token 混用
 */
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		/* 强制校验签名算法，阻止 alg:none / alg:RS256 等算法混淆攻击 */
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

/* ValidateAccessToken 验证 token 且确保是 access 类型 */
func (m *Manager) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.TokenType == TokenTypeRefresh {
		return nil, ErrTokenTypeMismatch
	}
	return claims, nil
}

/* ValidateRefreshToken 验证 token 且确保是 refresh 类型 */
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

/*
 * generateSecureJTI 使用 crypto/rand 生成安全的 JWT ID
 * 功能：16 字节随机数 → 32 字符十六进制字符串，比 uuid.New() 的 PRNG 更适合安全场景
 */
func generateSecureJTI() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return uuid.New().String()
	}
	return hex.EncodeToString(b)
}
