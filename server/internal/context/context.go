/*
 * Package context 请求上下文工具包
 * 功能：在 Gin 上下文中存取当前用户信息（ID、邮箱、用户名、角色）
 */
package context

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/* 上下文键名常量 */
const (
	UserIDKey       = "user_id"
	UserEmailKey    = "user_email"
	UserUsernameKey = "user_username"
	UserRoleKey     = "user_role"
)

/*
 * SetUser 将用户信息存入请求上下文
 * @param c        - Gin 上下文
 * @param userID   - 用户 UUID
 * @param email    - 邮箱
 * @param username - 用户名
 * @param role     - 角色
 */
func SetUser(c *gin.Context, userID uuid.UUID, email, username, role string) {
	c.Set(UserIDKey, userID)
	c.Set(UserEmailKey, email)
	c.Set(UserUsernameKey, username)
	c.Set(UserRoleKey, role)
}

/* GetUserID 从上下文提取用户 UUID */
func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	userID, exists := c.Get(UserIDKey)
	if !exists {
		return uuid.Nil, false
	}
	id, ok := userID.(uuid.UUID)
	return id, ok
}

/* GetUserEmail 从上下文提取用户邮箱 */
func GetUserEmail(c *gin.Context) (string, bool) {
	email, exists := c.Get(UserEmailKey)
	if !exists {
		return "", false
	}
	e, ok := email.(string)
	return e, ok
}

/* GetUserUsername 从上下文提取用户名 */
func GetUserUsername(c *gin.Context) (string, bool) {
	username, exists := c.Get(UserUsernameKey)
	if !exists {
		return "", false
	}
	u, ok := username.(string)
	return u, ok
}

/* GetUserRole 从上下文提取用户角色 */
func GetUserRole(c *gin.Context) (string, bool) {
	role, exists := c.Get(UserRoleKey)
	if !exists {
		return "", false
	}
	r, ok := role.(string)
	return r, ok
}

/* IsAdmin 检查当前用户是否为管理员 */
func IsAdmin(c *gin.Context) bool {
	role, ok := GetUserRole(c)
	return ok && role == "admin"
}
