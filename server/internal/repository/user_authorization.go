package repository

import (
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * UserAuthorizationRepository 用户授权记录数据仓储
 * 功能：封装用户对应用的 OAuth2 授权记录 CRUD 操作，包括创建、查找、撤销、统计和删除
 */
type UserAuthorizationRepository struct {
	db *gorm.DB
}

/*
 * NewUserAuthorizationRepository 创建用户授权仓储实例
 * @param db - GORM 数据库连接
 */
func NewUserAuthorizationRepository(db *gorm.DB) *UserAuthorizationRepository {
	return &UserAuthorizationRepository{db: db}
}

/* Create 创建新的用户授权记录 */
func (r *UserAuthorizationRepository) Create(auth *model.UserAuthorization) error {
	return r.db.Create(auth).Error
}

/*
 * FindByID 根据 UUID 查找授权记录（预加载用户和应用）
 * @param id - 授权记录 UUID
 */
func (r *UserAuthorizationRepository) FindByID(id uuid.UUID) (*model.UserAuthorization, error) {
	var auth model.UserAuthorization
	result := r.db.Preload("User").Preload("App").First(&auth, "id = ?", id)
	if result.Error != nil {
		return nil, result.Error
	}
	return &auth, nil
}

/*
 * FindByUserAndApp 根据用户 ID 和应用 ID 查找未撤销的授权记录
 * @param userID - 用户 UUID
 * @param appID  - 应用 UUID
 */
func (r *UserAuthorizationRepository) FindByUserAndApp(userID, appID uuid.UUID) (*model.UserAuthorization, error) {
	var auth model.UserAuthorization
	result := r.db.Where("user_id = ? AND app_id = ? AND revoked = false", userID, appID).First(&auth)
	if result.Error != nil {
		return nil, result.Error
	}
	return &auth, nil
}

/*
 * FindByApp 分页查询应用的所有授权记录
 * @param appID  - 应用 UUID
 * @param offset - 偏移量
 * @param limit  - 每页数量
 */
func (r *UserAuthorizationRepository) FindByApp(appID uuid.UUID, offset, limit int) ([]model.UserAuthorization, int64, error) {
	var auths []model.UserAuthorization
	var total int64

	r.db.Model(&model.UserAuthorization{}).Where("app_id = ?", appID).Count(&total)

	result := r.db.Preload("User").
		Where("app_id = ?", appID).
		Order("authorized_at DESC").
		Offset(offset).Limit(limit).
		Find(&auths)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return auths, total, nil
}

/*
 * FindByUser 查找用户的所有授权记录（预加载应用）
 * @param userID - 用户 UUID
 */
func (r *UserAuthorizationRepository) FindByUser(userID uuid.UUID) ([]model.UserAuthorization, error) {
	var auths []model.UserAuthorization
	result := r.db.Preload("App").
		Where("user_id = ?", userID).
		Order("authorized_at DESC").
		Find(&auths)
	if result.Error != nil {
		return nil, result.Error
	}
	return auths, nil
}

/*
 * FindActiveByApp 分页查询应用的所有活跃（未撤销）授权记录
 * @param appID  - 应用 UUID
 * @param offset - 偏移量
 * @param limit  - 每页数量
 */
func (r *UserAuthorizationRepository) FindActiveByApp(appID uuid.UUID, offset, limit int) ([]model.UserAuthorization, int64, error) {
	var auths []model.UserAuthorization
	var total int64

	r.db.Model(&model.UserAuthorization{}).Where("app_id = ? AND revoked = false", appID).Count(&total)

	result := r.db.Preload("User").
		Where("app_id = ? AND revoked = false", appID).
		Order("authorized_at DESC").
		Offset(offset).Limit(limit).
		Find(&auths)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return auths, total, nil
}

/*
 * Revoke 撤销授权记录
 * @param id - 授权记录 UUID
 */
func (r *UserAuthorizationRepository) Revoke(id uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&model.UserAuthorization{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"revoked":    true,
			"revoked_at": now,
		}).Error
}

/*
 * RevokeByUserAndApp 撤销用户对指定应用的授权
 * @param userID - 用户 UUID
 * @param appID  - 应用 UUID
 */
func (r *UserAuthorizationRepository) RevokeByUserAndApp(userID, appID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&model.UserAuthorization{}).
		Where("user_id = ? AND app_id = ? AND revoked = false", userID, appID).
		Updates(map[string]interface{}{
			"revoked":    true,
			"revoked_at": now,
		}).Error
}

/*
 * GetStatsForApp 获取应用的授权统计数据
 * 功能：统计总授权数、独立用户数、活跃/撤销授权数、24h/7d 授权数
 * @param appID - 应用 UUID
 * @return *model.UserAuthorizationStats - 授权统计数据
 */
func (r *UserAuthorizationRepository) GetStatsForApp(appID uuid.UUID) (*model.UserAuthorizationStats, error) {
	stats := &model.UserAuthorizationStats{}

	// Total authorizations
	r.db.Model(&model.UserAuthorization{}).Where("app_id = ?", appID).Count(&stats.TotalAuthorizations)

	// Unique users
	r.db.Model(&model.UserAuthorization{}).
		Where("app_id = ?", appID).
		Distinct("user_id").
		Count(&stats.UniqueUsers)

	// Active (non-revoked) authorizations
	r.db.Model(&model.UserAuthorization{}).
		Where("app_id = ? AND revoked = false", appID).
		Count(&stats.ActiveAuthorizations)

	// Revoked authorizations
	r.db.Model(&model.UserAuthorization{}).
		Where("app_id = ? AND revoked = true", appID).
		Count(&stats.RevokedAuthorizations)

	// Last 24h authorizations
	r.db.Model(&model.UserAuthorization{}).
		Where("app_id = ? AND authorized_at > ?", appID, time.Now().Add(-24*time.Hour)).
		Count(&stats.Last24hAuthorizations)

	// Last 7d authorizations
	r.db.Model(&model.UserAuthorization{}).
		Where("app_id = ? AND authorized_at > ?", appID, time.Now().Add(-7*24*time.Hour)).
		Count(&stats.Last7dAuthorizations)

	return stats, nil
}

/*
 * CreateOrUpdate 创建或更新授权记录（upsert 语义）
 * 功能：已存在则更新 scope、grant_type 和授权时间并取消撤销，不存在则创建新记录
 * @param userID    - 用户 UUID
 * @param appID     - 应用 UUID
 * @param scope     - 授权范围
 * @param grantType - 授权方式（authorization_code / device_code / client_credentials 等）
 */
func (r *UserAuthorizationRepository) CreateOrUpdate(userID, appID uuid.UUID, scope string, grantType string) (*model.UserAuthorization, error) {
	var auth model.UserAuthorization

	// Try to find existing
	result := r.db.Where("user_id = ? AND app_id = ?", userID, appID).First(&auth)

	if result.Error == gorm.ErrRecordNotFound {
		// Create new
		auth = model.UserAuthorization{
			UserID:       userID,
			AppID:        appID,
			Scope:        scope,
			GrantType:    grantType,
			AuthorizedAt: time.Now(),
		}
		if err := r.db.Create(&auth).Error; err != nil {
			return nil, err
		}
		return &auth, nil
	}

	if result.Error != nil {
		return nil, result.Error
	}

	// Update existing
	auth.Scope = scope
	auth.GrantType = grantType
	auth.AuthorizedAt = time.Now()
	auth.Revoked = false
	auth.RevokedAt = nil

	if err := r.db.Save(&auth).Error; err != nil {
		return nil, err
	}

	return &auth, nil
}

/*
 * CountUniqueUsersByApp 统计应用的独立授权用户数
 * @param appID - 应用 UUID
 */
func (r *UserAuthorizationRepository) CountUniqueUsersByApp(appID uuid.UUID) (int64, error) {
	var count int64
	result := r.db.Model(&model.UserAuthorization{}).
		Where("app_id = ? AND revoked = false", appID).
		Distinct("user_id").
		Count(&count)
	return count, result.Error
}

/*
 * FindByUserPaginated 分页查询用户的所有授权记录
 * @param userID - 用户 UUID
 * @param offset - 偏移量
 * @param limit  - 每页数量
 */
func (r *UserAuthorizationRepository) FindByUserPaginated(userID uuid.UUID, offset, limit int) ([]model.UserAuthorization, int64, error) {
	var auths []model.UserAuthorization
	var total int64

	r.db.Model(&model.UserAuthorization{}).Where("user_id = ?", userID).Count(&total)

	result := r.db.Preload("App").
		Where("user_id = ?", userID).
		Order("authorized_at DESC").
		Offset(offset).Limit(limit).
		Find(&auths)
	if result.Error != nil {
		return nil, 0, result.Error
	}
	return auths, total, nil
}

/* Delete 删除授权记录 */
func (r *UserAuthorizationRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.UserAuthorization{}, "id = ?", id).Error
}

/*
 * BatchDelete 批量删除授权记录
 * @param ids   - 授权记录 UUID 列表
 * @return int64 - 受影响行数
 */
func (r *UserAuthorizationRepository) BatchDelete(ids []uuid.UUID) (int64, error) {
	result := r.db.Where("id IN ?", ids).Delete(&model.UserAuthorization{})
	return result.RowsAffected, result.Error
}

/*
 * DeleteByApp 删除应用的所有授权记录
 * @param appID - 应用 UUID
 * @return int64 - 受影响行数
 */
func (r *UserAuthorizationRepository) DeleteByApp(appID uuid.UUID) (int64, error) {
	result := r.db.Where("app_id = ?", appID).Delete(&model.UserAuthorization{})
	return result.RowsAffected, result.Error
}

/*
 * DeleteByUser 删除用户的所有授权记录
 * @param userID - 用户 UUID
 * @return int64  - 受影响行数
 */
func (r *UserAuthorizationRepository) DeleteByUser(userID uuid.UUID) (int64, error) {
	result := r.db.Where("user_id = ?", userID).Delete(&model.UserAuthorization{})
	return result.RowsAffected, result.Error
}
