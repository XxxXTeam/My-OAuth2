package repository

import (
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type LoginLogRepository struct {
	db *gorm.DB
}

func NewLoginLogRepository(db *gorm.DB) *LoginLogRepository {
	return &LoginLogRepository{db: db}
}

// Create creates a new login log entry
func (r *LoginLogRepository) Create(log *model.LoginLog) error {
	return r.db.Create(log).Error
}

// CreateLoginLog is a helper to create a login log with common fields
func (r *LoginLogRepository) CreateLoginLog(
	userID *uuid.UUID,
	appID *uuid.UUID,
	loginType model.LoginType,
	ipAddress, userAgent, email string,
	success bool,
	failureReason string,
) error {
	log := &model.LoginLog{
		UserID:        userID,
		AppID:         appID,
		LoginType:     loginType,
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		Email:         email,
		Success:       success,
		FailureReason: failureReason,
	}
	return r.Create(log)
}

// FindByUser finds login logs for a user with pagination
func (r *LoginLogRepository) FindByUser(userID uuid.UUID, offset, limit int) ([]model.LoginLog, int64, error) {
	var logs []model.LoginLog
	var total int64

	r.db.Model(&model.LoginLog{}).Where("user_id = ?", userID).Count(&total)

	result := r.db.Preload("App").
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Offset(offset).Limit(limit).
		Find(&logs)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return logs, total, nil
}

/*
 * FindByApp 分页查询应用的登录日志
 * @param appID  - 应用 UUID
 * @param offset - 偏移量
 * @param limit  - 每页数量
 */
func (r *LoginLogRepository) FindByApp(appID uuid.UUID, offset, limit int) ([]model.LoginLog, int64, error) {
	var logs []model.LoginLog
	var total int64

	r.db.Model(&model.LoginLog{}).Where("app_id = ?", appID).Count(&total)

	result := r.db.Preload("User").
		Where("app_id = ?", appID).
		Order("created_at DESC").
		Offset(offset).Limit(limit).
		Find(&logs)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return logs, total, nil
}

/*
 * FindRecent 分页查询最近的登录日志（预加载用户和应用）
 * @param offset - 偏移量
 * @param limit  - 每页数量
 */
func (r *LoginLogRepository) FindRecent(offset, limit int) ([]model.LoginLog, int64, error) {
	var logs []model.LoginLog
	var total int64

	r.db.Model(&model.LoginLog{}).Count(&total)

	result := r.db.Preload("User").Preload("App").
		Order("created_at DESC").
		Offset(offset).Limit(limit).
		Find(&logs)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return logs, total, nil
}

/*
 * GetStats 获取全局登录统计数据
 * 功能：统计总登录数、成功/失败数、独立用户数、24h/7d 登录数、按类型分布
 * @return *model.LoginStats - 登录统计数据
 */
func (r *LoginLogRepository) GetStats() (*model.LoginStats, error) {
	stats := &model.LoginStats{}

	// Total logins
	r.db.Model(&model.LoginLog{}).Count(&stats.TotalLogins)

	// Successful logins
	r.db.Model(&model.LoginLog{}).Where("success = true").Count(&stats.SuccessfulLogins)

	// Failed logins
	r.db.Model(&model.LoginLog{}).Where("success = false").Count(&stats.FailedLogins)

	// Unique users (only successful logins)
	r.db.Model(&model.LoginLog{}).
		Where("success = true AND user_id IS NOT NULL").
		Distinct("user_id").
		Count(&stats.UniqueUsers)

	// Last 24h logins
	r.db.Model(&model.LoginLog{}).
		Where("created_at > ?", time.Now().Add(-24*time.Hour)).
		Count(&stats.Last24hLogins)

	// Last 7d logins
	r.db.Model(&model.LoginLog{}).
		Where("created_at > ?", time.Now().Add(-7*24*time.Hour)).
		Count(&stats.Last7dLogins)

	// Login type breakdown
	r.db.Model(&model.LoginLog{}).
		Where("login_type = ?", model.LoginTypeDirect).
		Count(&stats.DirectLogins)
	r.db.Model(&model.LoginLog{}).
		Where("login_type = ?", model.LoginTypeOAuth).
		Count(&stats.OAuthLogins)
	r.db.Model(&model.LoginLog{}).
		Where("login_type = ?", model.LoginTypeSDK).
		Count(&stats.SDKLogins)

	return stats, nil
}

/*
 * GetStatsForUser 获取指定用户的登录统计数据
 * @param userID - 用户 UUID
 * @return *model.LoginStats - 用户的登录统计
 */
func (r *LoginLogRepository) GetStatsForUser(userID uuid.UUID) (*model.LoginStats, error) {
	stats := &model.LoginStats{}

	r.db.Model(&model.LoginLog{}).Where("user_id = ?", userID).Count(&stats.TotalLogins)
	r.db.Model(&model.LoginLog{}).Where("user_id = ? AND success = true", userID).Count(&stats.SuccessfulLogins)
	r.db.Model(&model.LoginLog{}).Where("user_id = ? AND success = false", userID).Count(&stats.FailedLogins)
	r.db.Model(&model.LoginLog{}).
		Where("user_id = ? AND created_at > ?", userID, time.Now().Add(-24*time.Hour)).
		Count(&stats.Last24hLogins)
	r.db.Model(&model.LoginLog{}).
		Where("user_id = ? AND created_at > ?", userID, time.Now().Add(-7*24*time.Hour)).
		Count(&stats.Last7dLogins)

	return stats, nil
}

/*
 * GetTrend 获取指定天数的登录趋势数据
 * 功能：按天统计每日总登录数、成功数和失败数
 * @param days - 统计天数
 * @return []model.LoginTrend - 每日登录趋势数据点列表
 */
func (r *LoginLogRepository) GetTrend(days int) ([]model.LoginTrend, error) {
	var trends []model.LoginTrend

	startDate := time.Now().AddDate(0, 0, -days).Truncate(24 * time.Hour)

	// SQLite and PostgreSQL have different date functions
	// Using a simple approach that works for both
	for i := 0; i <= days; i++ {
		date := startDate.AddDate(0, 0, i)
		nextDate := date.AddDate(0, 0, 1)

		var total, success, failed int64
		r.db.Model(&model.LoginLog{}).
			Where("created_at >= ? AND created_at < ?", date, nextDate).
			Count(&total)
		r.db.Model(&model.LoginLog{}).
			Where("created_at >= ? AND created_at < ? AND success = true", date, nextDate).
			Count(&success)
		r.db.Model(&model.LoginLog{}).
			Where("created_at >= ? AND created_at < ? AND success = false", date, nextDate).
			Count(&failed)

		trends = append(trends, model.LoginTrend{
			Date:       date.Format("2006-01-02"),
			TotalCount: total,
			Success:    success,
			Failed:     failed,
		})
	}

	return trends, nil
}

/*
 * CountActiveUsers 统计指定时间范围内登录过的独立用户数
 * @param duration - 时间范围
 * @return int64   - 活跃用户数
 */
func (r *LoginLogRepository) CountActiveUsers(duration time.Duration) (int64, error) {
	var count int64
	result := r.db.Model(&model.LoginLog{}).
		Where("success = true AND user_id IS NOT NULL AND created_at > ?", time.Now().Add(-duration)).
		Distinct("user_id").
		Count(&count)
	return count, result.Error
}

/* CountTodayLogins 统计今日登录数 */
func (r *LoginLogRepository) CountTodayLogins() (int64, error) {
	var count int64
	today := time.Now().Truncate(24 * time.Hour)
	result := r.db.Model(&model.LoginLog{}).
		Where("created_at >= ?", today).
		Count(&count)
	return count, result.Error
}

/*
 * GetFailedLoginAttempts 获取指定 IP 在指定时间内的失败登录次数
 * @param ipAddress - 客户端 IP
 * @param duration  - 时间窗口
 * @return int64    - 失败次数
 */
func (r *LoginLogRepository) GetFailedLoginAttempts(ipAddress string, duration time.Duration) (int64, error) {
	var count int64
	result := r.db.Model(&model.LoginLog{}).
		Where("ip_address = ? AND success = false AND created_at > ?", ipAddress, time.Now().Add(-duration)).
		Count(&count)
	return count, result.Error
}

/*
 * FindRecentByUserID 查找用户的最近登录日志
 * @param userID - 用户 UUID
 * @param limit  - 最大返回数量
 */
func (r *LoginLogRepository) FindRecentByUserID(userID uuid.UUID, limit int) ([]model.LoginLog, error) {
	var logs []model.LoginLog
	result := r.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&logs)
	return logs, result.Error
}
