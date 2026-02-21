package repository

import (
	"errors"
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* 密码重置仓储层错误定义 */
var (
	ErrResetTokenNotFound = errors.New("reset token not found")
	ErrResetTokenExpired  = errors.New("reset token expired")
	ErrResetTokenUsed     = errors.New("reset token already used")
)

/*
 * PasswordResetRepository 密码重置数据仓储
 * 功能：封装密码重置令牌的全部 CRUD 操作，包括创建、查找、标记使用、失效和清理
 */
type PasswordResetRepository struct {
	db *gorm.DB
}

/*
 * NewPasswordResetRepository 创建密码重置仓储实例
 * @param db - GORM 数据库连接
 */
func NewPasswordResetRepository(db *gorm.DB) *PasswordResetRepository {
	return &PasswordResetRepository{db: db}
}

/* Create 创建密码重置记录 */
func (r *PasswordResetRepository) Create(reset *model.PasswordReset) error {
	return r.db.Create(reset).Error
}

/*
 * FindByToken 通过令牌查找密码重置记录
 * @param token - 重置令牌字符串
 * @return *model.PasswordReset - 重置记录，未找到时返回 ErrResetTokenNotFound
 */
func (r *PasswordResetRepository) FindByToken(token string) (*model.PasswordReset, error) {
	var reset model.PasswordReset
	result := r.db.Where("token = ?", token).First(&reset)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrResetTokenNotFound
		}
		return nil, result.Error
	}
	return &reset, nil
}

/*
 * FindValidByToken 查找有效的令牌（未过期且未使用）
 * @param token - 重置令牌字符串
 * @return error - 已使用返回 ErrResetTokenUsed，已过期返回 ErrResetTokenExpired
 */
func (r *PasswordResetRepository) FindValidByToken(token string) (*model.PasswordReset, error) {
	reset, err := r.FindByToken(token)
	if err != nil {
		return nil, err
	}

	if reset.Used {
		return nil, ErrResetTokenUsed
	}

	if reset.IsExpired() {
		return nil, ErrResetTokenExpired
	}

	return reset, nil
}

/*
 * MarkAsUsed 标记令牌为已使用
 * @param id - 重置记录 UUID
 */
func (r *PasswordResetRepository) MarkAsUsed(id uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&model.PasswordReset{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		}).Error
}

/*
 * InvalidateUserTokens 使用户所有未使用的重置令牌失效
 * @param userID - 用户 UUID
 */
func (r *PasswordResetRepository) InvalidateUserTokens(userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&model.PasswordReset{}).
		Where("user_id = ? AND used = ?", userID, false).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		}).Error
}

/* DeleteExpired 清理所有已过期的重置记录 */
func (r *PasswordResetRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&model.PasswordReset{}).Error
}

/*
 * CountRecentByUserID 统计用户在指定时间内的重置请求次数（用于限流）
 * @param userID   - 用户 UUID
 * @param duration - 时间窗口
 * @return int64   - 请求次数
 */
func (r *PasswordResetRepository) CountRecentByUserID(userID uuid.UUID, duration time.Duration) (int64, error) {
	var count int64
	since := time.Now().Add(-duration)
	err := r.db.Model(&model.PasswordReset{}).
		Where("user_id = ? AND created_at > ?", userID, since).
		Count(&count).Error
	return count, err
}
