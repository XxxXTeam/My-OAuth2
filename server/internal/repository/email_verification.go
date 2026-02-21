package repository

import (
	"errors"
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* 邮箱验证仓储层错误定义 */
var (
	ErrVerifyTokenNotFound = errors.New("verification token not found")
	ErrVerifyTokenExpired  = errors.New("verification token expired")
	ErrVerifyTokenUsed     = errors.New("verification token already used")
)

/*
 * EmailVerificationRepository 邮箱验证数据仓储
 * 功能：封装邮箱验证/更换令牌的全部 CRUD 操作
 */
type EmailVerificationRepository struct {
	db *gorm.DB
}

/*
 * NewEmailVerificationRepository 创建邮箱验证仓储实例
 * @param db - GORM 数据库连接
 */
func NewEmailVerificationRepository(db *gorm.DB) *EmailVerificationRepository {
	return &EmailVerificationRepository{db: db}
}

/* Create 创建邮箱验证记录 */
func (r *EmailVerificationRepository) Create(v *model.EmailVerification) error {
	return r.db.Create(v).Error
}

/*
 * FindValidByToken 查找有效的验证令牌（未过期且未使用）
 * @param token - 验证令牌字符串
 * @return error - 已使用返回 ErrVerifyTokenUsed，已过期返回 ErrVerifyTokenExpired
 */
func (r *EmailVerificationRepository) FindValidByToken(token string) (*model.EmailVerification, error) {
	var v model.EmailVerification
	result := r.db.Where("token = ?", token).First(&v)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrVerifyTokenNotFound
		}
		return nil, result.Error
	}

	if v.Used {
		return nil, ErrVerifyTokenUsed
	}
	if v.IsExpired() {
		return nil, ErrVerifyTokenExpired
	}

	return &v, nil
}

/*
 * MarkAsUsed 标记验证令牌为已使用
 * @param id - 验证记录 UUID
 */
func (r *EmailVerificationRepository) MarkAsUsed(id uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&model.EmailVerification{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		}).Error
}

/*
 * InvalidateUserTokens 使用户所有未使用的验证令牌失效
 * @param userID - 用户 UUID
 */
func (r *EmailVerificationRepository) InvalidateUserTokens(userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&model.EmailVerification{}).
		Where("user_id = ? AND used = ?", userID, false).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		}).Error
}

/* DeleteExpired 清理所有已过期的验证记录 */
func (r *EmailVerificationRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&model.EmailVerification{}).Error
}

/*
 * CountRecentByUserID 统计用户在指定时间内的验证请求次数（用于限流）
 * @param userID   - 用户 UUID
 * @param duration - 时间窗口
 * @return int64   - 请求次数
 */
func (r *EmailVerificationRepository) CountRecentByUserID(userID uuid.UUID, duration time.Duration) (int64, error) {
	var count int64
	since := time.Now().Add(-duration)
	err := r.db.Model(&model.EmailVerification{}).
		Where("user_id = ? AND created_at > ?", userID, since).
		Count(&count).Error
	return count, err
}
