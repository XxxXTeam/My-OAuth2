/*
 * Package repository 数据仓储层
 * 功能：封装所有数据库 CRUD 操作，提供统一的数据访问接口
 */
package repository

import (
	"errors"
	"strings"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * escapeLike 转义 SQL LIKE 通配符
 * 功能：将用户输入中的 %、_、\ 字符转义，防止注入通配符导致全表扫描
 */
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

/* 用户仓储层错误定义 */
var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
)

/*
 * UserRepository 用户数据仓储
 * 功能：封装用户表的全部 CRUD 操作，包括查找、创建、更新、删除、统计和搜索
 */
type UserRepository struct {
	db *gorm.DB
}

/*
 * NewUserRepository 创建用户仓储实例
 * @param db - GORM 数据库连接
 */
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

/*
 * Create 创建新用户
 * @param user - 用户实体
 * @return error - 邮箱/用户名重复时返回 ErrUserAlreadyExists
 */
func (r *UserRepository) Create(user *model.User) error {
	result := r.db.Create(user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return ErrUserAlreadyExists
		}
		return result.Error
	}
	return nil
}

/*
 * FindByID 根据 UUID 查找用户
 * @param id - 用户 UUID
 * @return *model.User - 用户实体，未找到时返回 ErrUserNotFound
 */
func (r *UserRepository) FindByID(id uuid.UUID) (*model.User, error) {
	var user model.User
	result := r.db.First(&user, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

/*
 * FindByEmail 根据邮箱查找用户
 * @param email - 用户邮箱
 * @return *model.User - 用户实体，未找到时返回 ErrUserNotFound
 */
func (r *UserRepository) FindByEmail(email string) (*model.User, error) {
	var user model.User
	result := r.db.First(&user, "email = ?", email)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

/*
 * FindByUsername 根据用户名查找用户
 * @param username - 用户名
 * @return *model.User - 用户实体，未找到时返回 ErrUserNotFound
 */
func (r *UserRepository) FindByUsername(username string) (*model.User, error) {
	var user model.User
	result := r.db.First(&user, "username = ?", username)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

/*
 * Update 更新用户信息
 * @param user - 包含更新字段的用户实体
 */
func (r *UserRepository) Update(user *model.User) error {
	return r.db.Save(user).Error
}

/*
 * Delete 删除用户
 * @param id - 用户 UUID
 */
func (r *UserRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.User{}, "id = ?", id).Error
}

/*
 * ExistsByEmail 检查邮箱是否已被注册
 * @param email - 邮箱地址
 * @return bool - 已存在返回 true
 */
func (r *UserRepository) ExistsByEmail(email string) (bool, error) {
	var count int64
	err := r.db.Model(&model.User{}).Where("email = ?", email).Count(&count).Error
	return count > 0, err
}

/*
 * ExistsByUsername 检查用户名是否已被使用
 * @param username - 用户名
 * @return bool    - 已存在返回 true
 */
func (r *UserRepository) ExistsByUsername(username string) (bool, error) {
	var count int64
	err := r.db.Model(&model.User{}).Where("username = ?", username).Count(&count).Error
	return count > 0, err
}

/* Count 返回用户总数 */
func (r *UserRepository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&model.User{}).Count(&count).Error
	return count, err
}

/*
 * FindAll 分页查询所有用户
 * @param offset - 偏移量
 * @param limit  - 每页数量
 * @return []model.User - 用户列表
 * @return int64        - 总数
 */
func (r *UserRepository) FindAll(offset, limit int) ([]model.User, int64, error) {
	var users []model.User
	var total int64

	if err := r.db.Model(&model.User{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	if err := r.db.Offset(offset).Limit(limit).Order("created_at DESC").Find(&users).Error; err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

/*
 * UpdateRole 更新用户角色
 * @param id   - 用户 UUID
 * @param role - 新角色
 */
func (r *UserRepository) UpdateRole(id uuid.UUID, role model.UserRole) error {
	return r.db.Model(&model.User{}).Where("id = ?", id).Update("role", role).Error
}

/*
 * BatchUpdateStatus 批量更新用户状态
 * @param ids    - 用户 UUID 列表
 * @param status - 新状态 (active/suspended/pending)
 * @return int64 - 受影响行数
 */
func (r *UserRepository) BatchUpdateStatus(ids []uuid.UUID, status string) (int64, error) {
	result := r.db.Model(&model.User{}).Where("id IN ?", ids).Update("status", status)
	return result.RowsAffected, result.Error
}

/*
 * BatchDelete 批量删除用户
 * @param ids   - 用户 UUID 列表
 * @return int64 - 受影响行数
 */
func (r *UserRepository) BatchDelete(ids []uuid.UUID) (int64, error) {
	result := r.db.Where("id IN ?", ids).Delete(&model.User{})
	return result.RowsAffected, result.Error
}

/*
 * CountByStatus 按状态分组统计用户数
 * @return map[string]int64 - 状态 → 用户数映射
 */
func (r *UserRepository) CountByStatus() (map[string]int64, error) {
	type Result struct {
		Status string
		Count  int64
	}
	var results []Result
	err := r.db.Model(&model.User{}).
		Select("COALESCE(NULLIF(status,''), 'active') as status, COUNT(*) as count").
		Group("status").Find(&results).Error
	if err != nil {
		return nil, err
	}
	countMap := make(map[string]int64)
	for _, r := range results {
		if r.Status == "" {
			countMap["active"] += r.Count
		} else {
			countMap[r.Status] += r.Count
		}
	}
	return countMap, nil
}

/*
 * CountByRole 按角色分组统计用户数
 * @return map[string]int64 - 角色 → 用户数映射
 */
func (r *UserRepository) CountByRole() (map[string]int64, error) {
	type Result struct {
		Role  string
		Count int64
	}
	var results []Result
	err := r.db.Model(&model.User{}).
		Select("role, COUNT(*) as count").
		Group("role").Find(&results).Error
	if err != nil {
		return nil, err
	}
	countMap := make(map[string]int64)
	for _, r := range results {
		countMap[r.Role] = r.Count
	}
	return countMap, nil
}

/*
 * SearchUsers 高级搜索用户
 * 功能：支持关键词搜索（邮箱/用户名/昵称/手机）+ 筛选条件（角色/状态/邮箱验证）+ 分页
 * @param query   - 搜索关键词
 * @param filters - 筛选条件 (role, status, email_verified)
 * @param offset  - 偏移量
 * @param limit   - 每页数量
 * @return []model.User - 用户列表
 * @return int64        - 符合条件总数
 */
func (r *UserRepository) SearchUsers(query string, filters map[string]interface{}, offset, limit int) ([]model.User, int64, error) {
	var users []model.User
	var total int64

	db := r.db.Model(&model.User{})

	/* 文本搜索：转义 LIKE 通配符（%、_、\），防止用户输入干扰查询逻辑 */
	if query != "" {
		escaped := escapeLike(query)
		searchPattern := "%" + escaped + "%"
		db = db.Where("email LIKE ? OR username LIKE ? OR nickname LIKE ? OR phone_number LIKE ?",
			searchPattern, searchPattern, searchPattern, searchPattern)
	}

	// Apply filters
	if role, ok := filters["role"]; ok && role != "" {
		db = db.Where("role = ?", role)
	}
	if status, ok := filters["status"]; ok && status != "" {
		db = db.Where("status = ?", status)
	}
	if emailVerified, ok := filters["email_verified"]; ok {
		db = db.Where("email_verified = ?", emailVerified)
	}

	// Count total
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	if err := db.Offset(offset).Limit(limit).Order("created_at DESC").Find(&users).Error; err != nil {
		return nil, 0, err
	}

	return users, total, nil
}
