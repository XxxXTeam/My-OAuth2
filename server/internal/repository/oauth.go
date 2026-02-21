package repository

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* OAuth 仓储层错误定义 */
var (
	ErrAuthCodeNotFound = errors.New("authorization code not found")
	ErrTokenNotFound    = errors.New("token not found")
)

/*
 * OAuthRepository OAuth2 令牌数据仓储
 * 功能：封装授权码、access_token、refresh_token 的全部 CRUD 操作
 *       同时支持 Auth 认证系统的 Refresh Token Rotation
 */
type OAuthRepository struct {
	db *gorm.DB
}

/*
 * NewOAuthRepository 创建 OAuth 仓储实例
 * @param db - GORM 数据库连接
 */
func NewOAuthRepository(db *gorm.DB) *OAuthRepository {
	return &OAuthRepository{db: db}
}

/*
 * CreateAuthorizationCode 创建新的授权码
 * 功能：自动生成随机授权码（如未设置）
 * @param code - 授权码实体
 */
func (r *OAuthRepository) CreateAuthorizationCode(code *model.AuthorizationCode) error {
	if code.Code == "" {
		code.Code = generateAuthCode()
	}
	return r.db.Create(code).Error
}

/*
 * FindAuthorizationCode 查找授权码
 * @param code - 授权码字符串
 * @return *model.AuthorizationCode - 授权码实体，未找到时返回 ErrAuthCodeNotFound
 */
func (r *OAuthRepository) FindAuthorizationCode(code string) (*model.AuthorizationCode, error) {
	var authCode model.AuthorizationCode
	result := r.db.First(&authCode, "code = ?", code)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrAuthCodeNotFound
		}
		return nil, result.Error
	}
	return &authCode, nil
}

/* MarkAuthorizationCodeUsed 标记授权码为已使用 */
func (r *OAuthRepository) MarkAuthorizationCodeUsed(code string) error {
	return r.db.Model(&model.AuthorizationCode{}).Where("code = ?", code).Update("used", true).Error
}

/* DeleteExpiredAuthorizationCodes 清理已过期的授权码 */
func (r *OAuthRepository) DeleteExpiredAuthorizationCodes() error {
	return r.db.Delete(&model.AuthorizationCode{}, "expires_at < ?", time.Now()).Error
}

/*
 * CreateAccessToken 创建新的访问令牌
 * 功能：自动生成随机 token（如未设置）
 * @param token - 访问令牌实体
 */
func (r *OAuthRepository) CreateAccessToken(token *model.AccessToken) error {
	if token.Token == "" {
		token.Token = generateToken()
	}
	return r.db.Create(token).Error
}

/*
 * FindAccessToken 查找访问令牌（预加载关联用户）
 * @param token - 令牌字符串
 * @return *model.AccessToken - 令牌实体，未找到时返回 ErrTokenNotFound
 */
func (r *OAuthRepository) FindAccessToken(token string) (*model.AccessToken, error) {
	var accessToken model.AccessToken
	result := r.db.Preload("User").First(&accessToken, "token = ?", token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, result.Error
	}
	return &accessToken, nil
}

/*
 * FindAccessTokenByID 根据 UUID 查找访问令牌
 * @param id - 令牌 UUID
 */
func (r *OAuthRepository) FindAccessTokenByID(id uuid.UUID) (*model.AccessToken, error) {
	var accessToken model.AccessToken
	result := r.db.First(&accessToken, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, result.Error
	}
	return &accessToken, nil
}

/* RevokeAccessToken 撤销访问令牌 */
func (r *OAuthRepository) RevokeAccessToken(token string) error {
	return r.db.Model(&model.AccessToken{}).Where("token = ?", token).Update("revoked", true).Error
}

/*
 * CreateRefreshToken 创建新的刷新令牌
 * 功能：自动生成随机 token（如未设置）
 * @param token - 刷新令牌实体
 */
func (r *OAuthRepository) CreateRefreshToken(token *model.RefreshToken) error {
	if token.Token == "" {
		token.Token = generateToken()
	}
	return r.db.Create(token).Error
}

/*
 * FindRefreshToken 查找刷新令牌（预加载关联 AccessToken）
 * @param token - 令牌字符串
 * @return *model.RefreshToken - 令牌实体，未找到时返回 ErrTokenNotFound
 */
func (r *OAuthRepository) FindRefreshToken(token string) (*model.RefreshToken, error) {
	var refreshToken model.RefreshToken
	result := r.db.Preload("AccessToken").First(&refreshToken, "token = ?", token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, result.Error
	}
	return &refreshToken, nil
}

/* RevokeRefreshToken 撤销刷新令牌 */
func (r *OAuthRepository) RevokeRefreshToken(token string) error {
	return r.db.Model(&model.RefreshToken{}).Where("token = ?", token).Update("revoked", true).Error
}

/* RevokeRefreshTokenByAccessTokenID 根据关联的 access_token_id 撤销刷新令牌 */
func (r *OAuthRepository) RevokeRefreshTokenByAccessTokenID(accessTokenID uuid.UUID) error {
	return r.db.Model(&model.RefreshToken{}).Where("access_token_id = ?", accessTokenID).Update("revoked", true).Error
}

/*
 * RevokeTokensByClientAndUser 撤销指定应用+用户的所有 OAuth 令牌
 * 功能：用户撤销对某个应用的授权时，同时撤销该应用签发给该用户的所有 token
 * @param clientID - 应用的 client_id
 * @param userID   - 用户 UUID
 */
func (r *OAuthRepository) RevokeTokensByClientAndUser(clientID string, userID uuid.UUID) error {
	/* 撤销该用户在该应用的所有 access_token */
	if err := r.db.Model(&model.AccessToken{}).
		Where("client_id = ? AND user_id = ? AND revoked = ?", clientID, userID, false).
		Update("revoked", true).Error; err != nil {
		return err
	}
	/* 撤销关联的所有 refresh_token（通过子查询找到 access_token_id） */
	return r.db.Exec(`
		UPDATE refresh_tokens SET revoked = true 
		WHERE revoked = false AND access_token_id IN (
			SELECT id FROM access_tokens WHERE client_id = ? AND user_id = ?
		)`, clientID, userID).Error
}

/* DeleteExpiredTokens 清理已过期的访问令牌和刷新令牌 */
func (r *OAuthRepository) DeleteExpiredTokens() error {
	now := time.Now()
	if err := r.db.Delete(&model.AccessToken{}, "expires_at < ?", now).Error; err != nil {
		return err
	}
	return r.db.Delete(&model.RefreshToken{}, "expires_at < ?", now).Error
}

/*
 * RevokeTokensByUserID 撤销用户的所有令牌（用于登出）
 * @param userID - 用户 UUID
 */
func (r *OAuthRepository) RevokeTokensByUserID(userID uuid.UUID) error {
	if err := r.db.Model(&model.AccessToken{}).Where("user_id = ?", userID).Update("revoked", true).Error; err != nil {
		return err
	}
	return r.db.Model(&model.RefreshToken{}).Where("user_id = ?", userID).Update("revoked", true).Error
}

/*
 * === Auth Refresh Token Rotation ===
 * 以下方法用于用户认证系统的 refresh token 轮换（单次使用）
 * 使用 JWT 的 jti（Token 字段）作为唯一标识
 */

/*
 * StoreAuthRefreshToken 存储 Auth Refresh Token 记录
 * 功能：用于 Token Rotation 轮换追踪，以 JWT 的 jti 作为唯一标识
 * @param jti       - JWT Token ID
 * @param userID    - 用户 UUID
 * @param expiresAt - 过期时间
 */
func (r *OAuthRepository) StoreAuthRefreshToken(jti string, userID uuid.UUID, expiresAt time.Time) error {
	record := &model.RefreshToken{
		Token:     jti,
		UserID:    &userID,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}
	return r.db.Create(record).Error
}

/*
 * FindAuthRefreshToken 按 JTI 查找未撤销的 Auth Refresh Token
 * @param jti - JWT Token ID
 * @return *model.RefreshToken - 令牌实体，未找到时返回 ErrTokenNotFound
 */
func (r *OAuthRepository) FindAuthRefreshToken(jti string) (*model.RefreshToken, error) {
	var token model.RefreshToken
	result := r.db.Where("token = ? AND user_id IS NOT NULL", jti).First(&token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, result.Error
	}
	return &token, nil
}

/* RevokeAuthRefreshToken 按 JTI 撤销 Auth Refresh Token（单次使用后失效，同时记录撤销时间） */
func (r *OAuthRepository) RevokeAuthRefreshToken(jti string) error {
	now := time.Now()
	return r.db.Model(&model.RefreshToken{}).
		Where("token = ? AND user_id IS NOT NULL", jti).
		Updates(map[string]interface{}{"revoked": true, "revoked_at": now}).Error
}

/*
 * RevokeUserAuthRefreshTokens 撤销用户所有 Auth Refresh Token（用于登出）
 * @param userID - 用户 UUID
 */
func (r *OAuthRepository) RevokeUserAuthRefreshTokens(userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Updates(map[string]interface{}{"revoked": true, "revoked_at": now}).Error
}

/* CleanExpiredAuthRefreshTokens 清理过期的 Auth Refresh Token */
func (r *OAuthRepository) CleanExpiredAuthRefreshTokens() error {
	return r.db.Where("user_id IS NOT NULL AND expires_at < ?", time.Now()).Delete(&model.RefreshToken{}).Error
}

/* generateAuthCode 生成随机授权码（32 字节 Base64 URL 编码） */
func generateAuthCode() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

/* generateToken 生成随机令牌（48 字节 Base64 URL 编码） */
func generateToken() string {
	bytes := make([]byte, 48)
	if _, err := rand.Read(bytes); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
