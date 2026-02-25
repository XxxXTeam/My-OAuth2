package handler

import (
	crand "crypto/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	ctx "server/internal/context"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/audit"
	"server/pkg/email"
	"server/pkg/password"
	"server/pkg/sanitize"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/*
 * AdminHandler 管理后台请求处理器
 * 功能：处理用户管理、应用管理、登录日志、授权统计、系统概览等管理员 HTTP 请求
 */
type AdminHandler struct {
	userRepo     *repository.UserRepository
	appRepo      *repository.ApplicationRepository
	loginLogRepo *repository.LoginLogRepository
	userAuthRepo *repository.UserAuthorizationRepository
	resetService *service.PasswordResetService
	emailService *email.Service
}

/*
 * NewAdminHandler 创建管理后台处理器实例
 * @param userRepo     - 用户仓储
 * @param appRepo      - 应用仓储
 * @param loginLogRepo - 登录日志仓储
 * @param userAuthRepo - 用户授权仓储
 */
func NewAdminHandler(
	userRepo *repository.UserRepository,
	appRepo *repository.ApplicationRepository,
	loginLogRepo *repository.LoginLogRepository,
	userAuthRepo *repository.UserAuthorizationRepository,
) *AdminHandler {
	return &AdminHandler{
		userRepo:     userRepo,
		appRepo:      appRepo,
		loginLogRepo: loginLogRepo,
		userAuthRepo: userAuthRepo,
	}
}

/* SetPasswordResetService 注入密码重置服务 */
func (h *AdminHandler) SetPasswordResetService(svc *service.PasswordResetService) {
	h.resetService = svc
}

/* SetEmailService 注入邮件服务（用于管理员发送密码重置邮件等） */
func (h *AdminHandler) SetEmailService(svc *email.Service) {
	h.emailService = svc
}

// UserListItem represents user info in admin list
type UserListItem struct {
	ID               string  `json:"id"`
	Email            string  `json:"email"`
	Username         string  `json:"username"`
	Role             string  `json:"role"`
	Status           string  `json:"status"`
	Avatar           string  `json:"avatar,omitempty"`
	EmailVerified    bool    `json:"email_verified"`
	ProfileCompleted bool    `json:"profile_completed"`
	Nickname         string  `json:"nickname,omitempty"`
	GivenName        string  `json:"given_name,omitempty"`
	FamilyName       string  `json:"family_name,omitempty"`
	PhoneNumber      string  `json:"phone_number,omitempty"`
	Company          string  `json:"company,omitempty"`
	Department       string  `json:"department,omitempty"`
	JobTitle         string  `json:"job_title,omitempty"`
	ExternalSource   string  `json:"external_source,omitempty"`
	LastLoginAt      *string `json:"last_login_at,omitempty"`
	CreatedAt        string  `json:"created_at"`
	UpdatedAt        string  `json:"updated_at"`
}

// ListUsers returns all users (admin only)
func (h *AdminHandler) ListUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit
	users, total, err := h.userRepo.FindAll(offset, limit)
	if err != nil {
		InternalError(c, "Failed to fetch users")
		return
	}

	// Convert to response format with more info
	userList := make([]UserListItem, len(users))
	for i, u := range users {
		item := UserListItem{
			ID:               u.ID.String(),
			Email:            u.Email,
			Username:         u.Username,
			Role:             string(u.Role),
			Status:           u.Status,
			Avatar:           u.Avatar,
			EmailVerified:    u.EmailVerified,
			ProfileCompleted: u.ProfileCompleted,
			Nickname:         u.Nickname,
			GivenName:        u.GivenName,
			FamilyName:       u.FamilyName,
			PhoneNumber:      u.PhoneNumber,
			Company:          u.Company,
			Department:       u.Department,
			JobTitle:         u.JobTitle,
			ExternalSource:   u.ExternalSource,
			CreatedAt:        u.CreatedAt.Format(time.RFC3339),
			UpdatedAt:        u.UpdatedAt.Format(time.RFC3339),
		}
		if item.Status == "" {
			item.Status = "active"
		}
		if u.LastLoginAt != nil {
			t := u.LastLoginAt.Format(time.RFC3339)
			item.LastLoginAt = &t
		}
		userList[i] = item
	}

	Success(c, gin.H{
		"users": userList,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

/*
 * GetUser 获取单个用户详情（管理员专用）
 * 功能：返回结构化响应，隐藏 password_hash 等敏感字段
 * @route GET /api/admin/users/:id
 */
func (h *AdminHandler) GetUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	user, err := h.userRepo.FindByID(id)
	if err != nil {
		NotFound(c, "User not found")
		return
	}

	/* 返回结构化响应，避免直接序列化 model 暴露 json:"-" 以外的内部字段 */
	Success(c, buildFullUserResponse(user))
}

// UpdateUserRole updates a user's role (admin only)
func (h *AdminHandler) UpdateUserRole(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	var input struct {
		Role string `json:"role" binding:"required,oneof=admin user"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		BadRequest(c, "Invalid role")
		return
	}

	oldUser, _ := h.userRepo.FindByID(id)
	oldRole := ""
	if oldUser != nil {
		oldRole = string(oldUser.Role)
	}

	if err := h.userRepo.UpdateRole(id, model.UserRole(input.Role)); err != nil {
		InternalError(c, "Failed to update role")
		return
	}

	actorID := getActorID(c)
	audit.Log(audit.ActionRoleChange, audit.ResultSuccess, actorID, id.String(), c.ClientIP(), "old_role", oldRole, "new_role", input.Role)
	Success(c, gin.H{"message": "Role updated successfully"})
}

/*
 * DeleteUser 删除单个用户（管理员专用）
 * 安全：禁止管理员删除自己的账号
 * @route DELETE /api/admin/users/:id
 */
func (h *AdminHandler) DeleteUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	/* 自删保护：禁止删除当前登录的管理员账号 */
	if currentUserID, exists := c.Get("user_id"); exists {
		if cuid, ok := currentUserID.(uuid.UUID); ok && cuid == id {
			BadRequest(c, "Cannot delete your own account")
			return
		}
	}

	if err := h.userRepo.Delete(id); err != nil {
		InternalError(c, "Failed to delete user")
		return
	}

	actorID := getActorID(c)
	audit.Log(audit.ActionAccountDelete, audit.ResultSuccess, actorID, id.String(), c.ClientIP())
	Success(c, gin.H{"message": "User deleted successfully"})
}

// ResetUserPassword 管理员重置用户密码
// PUT /api/admin/users/:id/reset-password
func (h *AdminHandler) ResetUserPassword(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	var input struct {
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		BadRequest(c, err.Error())
		return
	}

	/* 校验新密码强度（含常见弱密码黑名单） */
	if err := password.ValidateStrength(input.NewPassword); err != nil {
		BadRequest(c, err.Error())
		return
	}

	user, err := h.userRepo.FindByID(id)
	if err != nil {
		NotFound(c, "User not found")
		return
	}

	if err := user.SetPassword(input.NewPassword); err != nil {
		InternalError(c, "Failed to hash password")
		return
	}
	/* 重置失败计数和锁定状态 */
	user.FailedLogins = 0
	user.LockedUntil = nil
	if err := h.userRepo.Update(user); err != nil {
		InternalError(c, "Failed to reset password")
		return
	}

	actorID := getActorID(c)
	audit.Log(audit.ActionPasswordReset, audit.ResultSuccess, actorID, id.String(), c.ClientIP())
	Success(c, gin.H{"message": "Password reset successfully"})
}

// UpdateUserStatus 管理员更新单个用户状态（停用/启用）
// PUT /api/admin/users/:id/status
func (h *AdminHandler) UpdateUserStatus(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	var input struct {
		Status string `json:"status" binding:"required,oneof=active suspended pending"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		BadRequest(c, err.Error())
		return
	}

	user, err := h.userRepo.FindByID(id)
	if err != nil {
		NotFound(c, "User not found")
		return
	}

	oldStatus := user.Status
	user.Status = input.Status
	if err := h.userRepo.Update(user); err != nil {
		InternalError(c, "Failed to update status")
		return
	}

	actorID := getActorID(c)
	audit.Log(audit.ActionStatusChange, audit.ResultSuccess, actorID, id.String(), c.ClientIP(), "old_status", oldStatus, "new_status", input.Status)
	Success(c, gin.H{"message": "User status updated successfully"})
}

// ListAllApps returns all applications (admin only)
func (h *AdminHandler) ListAllApps(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit
	apps, total, err := h.appRepo.FindAll(offset, limit)
	if err != nil {
		InternalError(c, "Failed to fetch applications")
		return
	}

	Success(c, gin.H{
		"apps":  apps,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

// GetStats returns system statistics (admin only)
func (h *AdminHandler) GetStats(c *gin.Context) {
	userCount, _ := h.userRepo.Count()
	appCount, _ := h.appRepo.Count()

	// Get login stats
	var loginStats *model.LoginStats
	var activeUsers int64
	var todayLogins int64
	if h.loginLogRepo != nil {
		loginStats, _ = h.loginLogRepo.GetStats()
		activeUsers, _ = h.loginLogRepo.CountActiveUsers(30 * 24 * time.Hour) // 30 days
		todayLogins, _ = h.loginLogRepo.CountTodayLogins()
	}

	stats := gin.H{
		"users":        userCount,
		"applications": appCount,
		"active_users": activeUsers,
		"today_logins": todayLogins,
	}

	if loginStats != nil {
		stats["login_stats"] = loginStats
	}

	// 用户状态分布
	if statusCounts, err := h.userRepo.CountByStatus(); err == nil {
		stats["users_by_status"] = statusCounts
	}
	// 用户角色分布
	if roleCounts, err := h.userRepo.CountByRole(); err == nil {
		stats["users_by_role"] = roleCounts
	}

	Success(c, stats)
}

// GetLoginLogs returns recent login logs (admin only)
// GET /api/admin/login-logs
func (h *AdminHandler) GetLoginLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit
	logs, total, err := h.loginLogRepo.FindRecent(offset, limit)
	if err != nil {
		InternalError(c, "Failed to fetch login logs")
		return
	}

	Success(c, gin.H{
		"logs":  logs,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

// GetLoginTrend returns login trend data (admin only)
// GET /api/admin/stats/login-trend
func (h *AdminHandler) GetLoginTrend(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	if days < 1 || days > 90 {
		days = 7
	}

	trend, err := h.loginLogRepo.GetTrend(days)
	if err != nil {
		InternalError(c, "Failed to fetch login trend")
		return
	}

	Success(c, gin.H{"trend": trend})
}

// GetAppAuthorizedUsers returns authorized users for an app (admin only)
// GET /api/admin/apps/:id/users
func (h *AdminHandler) GetAppAuthorizedUsers(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid app ID")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit
	auths, total, err := h.userAuthRepo.FindByApp(id, offset, limit)
	if err != nil {
		InternalError(c, "Failed to fetch authorized users")
		return
	}

	Success(c, gin.H{
		"authorizations": auths,
		"total":          total,
		"page":           page,
		"limit":          limit,
	})
}

// GetAppStats returns detailed stats for an app (admin only)
// GET /api/admin/apps/:id/stats
func (h *AdminHandler) GetAppStats(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid app ID")
		return
	}

	stats, err := h.userAuthRepo.GetStatsForApp(id)
	if err != nil {
		InternalError(c, "Failed to fetch app stats")
		return
	}

	Success(c, stats)
}

// ========== Batch Operations ==========

// BatchUpdateStatusRequest represents a batch status update request
type BatchUpdateStatusRequest struct {
	UserIDs []string `json:"user_ids" binding:"required,min=1"`
	Status  string   `json:"status" binding:"required,oneof=active suspended pending"`
}

// BatchUpdateStatus updates status for multiple users
// PUT /api/admin/users/batch/status
func (h *AdminHandler) BatchUpdateStatus(c *gin.Context) {
	var req BatchUpdateStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Parse UUIDs
	ids := make([]uuid.UUID, 0, len(req.UserIDs))
	for _, idStr := range req.UserIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			continue // Skip invalid IDs
		}
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		BadRequest(c, "No valid user IDs provided")
		return
	}

	// Update status
	updated, err := h.userRepo.BatchUpdateStatus(ids, req.Status)
	if err != nil {
		InternalError(c, "Failed to update users")
		return
	}

	Success(c, gin.H{
		"message": "Users updated successfully",
		"updated": updated,
	})
}

// BatchDeleteRequest represents a batch delete request
type BatchDeleteRequest struct {
	UserIDs []string `json:"user_ids" binding:"required,min=1"`
}

/*
 * BatchDeleteUsers 批量删除用户（管理员专用）
 * 安全：禁止管理员删除自己的账号
 * @route DELETE /api/admin/users/batch
 */
func (h *AdminHandler) BatchDeleteUsers(c *gin.Context) {
	var req BatchDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	/* 获取当前管理员 ID，用于自删保护 */
	currentUserID, _ := c.Get("user_id")

	// Parse UUIDs
	ids := make([]uuid.UUID, 0, len(req.UserIDs))
	for _, idStr := range req.UserIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			continue
		}
		/* 禁止管理员删除自己 */
		if currentUserID != nil {
			if cuid, ok := currentUserID.(uuid.UUID); ok && cuid == id {
				BadRequest(c, "Cannot delete your own account")
				return
			}
		}
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		BadRequest(c, "No valid user IDs provided")
		return
	}

	// Delete users
	deleted, err := h.userRepo.BatchDelete(ids)
	if err != nil {
		InternalError(c, "Failed to delete users")
		return
	}

	actorID := getActorID(c)
	for _, id := range ids {
		audit.Log(audit.ActionAccountDelete, audit.ResultSuccess, actorID, id.String(), c.ClientIP(), "batch", "true")
	}

	Success(c, gin.H{
		"message": "Users deleted successfully",
		"deleted": deleted,
	})
}

// ExportUsersRequest represents user export options
type ExportUsersRequest struct {
	Format string   `form:"format" binding:"omitempty,oneof=json csv"`
	Fields []string `form:"fields"`
}

// ExportUsers exports users to JSON or CSV
// GET /api/admin/users/export
func (h *AdminHandler) ExportUsers(c *gin.Context) {
	format := c.DefaultQuery("format", "json")

	// Get all users
	users, _, err := h.userRepo.FindAll(0, 10000) // Max 10000 users
	if err != nil {
		InternalError(c, "Failed to fetch users")
		return
	}

	if format == "csv" {
		// Export as CSV
		c.Header("Content-Type", "text/csv; charset=utf-8")
		c.Header("Content-Disposition", "attachment; filename=users.csv")

		/* BOM 头确保 Excel 正确识别 UTF-8 */
		c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})
		c.Writer.WriteString("id,email,username,role,status,email_verified,created_at\n")

		for _, u := range users {
			status := u.Status
			if status == "" {
				status = "active"
			}
			/*
			 * CSV 字段转义：
			 * - 包含逗号、引号、换行的字段用双引号包裹
			 * - 以 =、+、-、@ 开头的字段前加单引号（防 CSV 公式注入）
			 */
			line := csvEscape(u.ID.String()) + "," +
				csvEscape(u.Email) + "," +
				csvEscape(u.Username) + "," +
				csvEscape(string(u.Role)) + "," +
				csvEscape(status) + "," +
				strconv.FormatBool(u.EmailVerified) + "," +
				u.CreatedAt.Format(time.RFC3339) + "\n"
			c.Writer.WriteString(line)
		}
		return
	}

	// Default: Export as JSON
	c.Header("Content-Type", "application/json")
	c.Header("Content-Disposition", "attachment; filename=users.json")

	// Convert to export format
	exportData := make([]map[string]interface{}, len(users))
	for i, u := range users {
		status := u.Status
		if status == "" {
			status = "active"
		}
		exportData[i] = map[string]interface{}{
			"id":             u.ID.String(),
			"email":          u.Email,
			"username":       u.Username,
			"role":           string(u.Role),
			"status":         status,
			"email_verified": u.EmailVerified,
			"nickname":       u.Nickname,
			"phone_number":   u.PhoneNumber,
			"company":        u.Company,
			"department":     u.Department,
			"job_title":      u.JobTitle,
			"created_at":     u.CreatedAt.Format(time.RFC3339),
		}
	}

	c.JSON(http.StatusOK, exportData)
}

// ImportUsersRequest represents user import data
type ImportUserData struct {
	Email       string `json:"email" binding:"required,email"`
	Username    string `json:"username" binding:"required"`
	Password    string `json:"password"` // Optional, will generate if empty
	Role        string `json:"role" binding:"omitempty,oneof=admin user"`
	Status      string `json:"status" binding:"omitempty,oneof=active suspended pending"`
	Nickname    string `json:"nickname"`
	PhoneNumber string `json:"phone_number"`
	Company     string `json:"company"`
	Department  string `json:"department"`
	JobTitle    string `json:"job_title"`
}

type ImportUsersRequest struct {
	Users []ImportUserData `json:"users" binding:"required,min=1,dive"`
}

// ImportUsers imports users from JSON
// POST /api/admin/users/import
func (h *AdminHandler) ImportUsers(c *gin.Context) {
	var req ImportUsersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	created := 0
	skipped := 0
	errors := []string{}

	for _, userData := range req.Users {
		/* 输入清洗：邮箱转小写去空白，用户名校验合法性 */
		cleanEmail := sanitize.Email(userData.Email)
		cleanUsername, validUsername := sanitize.Username(userData.Username)
		if !validUsername {
			skipped++
			errors = append(errors, "Invalid username for "+cleanEmail)
			continue
		}

		// Check if user already exists
		if _, err := h.userRepo.FindByEmail(cleanEmail); err == nil {
			skipped++
			errors = append(errors, "User with email "+cleanEmail+" already exists")
			continue
		}

		// Create user
		user := &model.User{
			Email:       cleanEmail,
			Username:    cleanUsername,
			Role:        model.RoleUser,
			Status:      "active",
			Nickname:    sanitize.PlainText(userData.Nickname, 100),
			PhoneNumber: sanitize.String(userData.PhoneNumber, 30),
			Company:     sanitize.PlainText(userData.Company, 200),
			Department:  sanitize.PlainText(userData.Department, 200),
			JobTitle:    sanitize.PlainText(userData.JobTitle, 200),
		}

		if userData.Role != "" {
			user.Role = model.UserRole(userData.Role)
		}
		if userData.Status != "" {
			user.Status = userData.Status
		}

		/* 设置密码：未提供则生成随机密码，提供则校验强度 */
		pwd := userData.Password
		if pwd == "" {
			pwd = generateRandomPassword(16)
		} else if err := password.ValidateStrength(pwd); err != nil {
			skipped++
			errors = append(errors, "Weak password for "+cleanEmail+": "+err.Error())
			continue
		}
		user.SetPassword(pwd)

		if err := h.userRepo.Create(user); err != nil {
			skipped++
			errors = append(errors, "Failed to create user "+userData.Email+": "+err.Error())
			continue
		}

		created++
	}

	Success(c, gin.H{
		"message": "Import completed",
		"created": created,
		"skipped": skipped,
		"errors":  errors,
	})
}

/*
 * csvEscape CSV 字段安全转义
 * 功能：防止 CSV 注入攻击（公式注入）和字段分隔符冲突
 * 规则：
 *   - 以 =、+、-、@、\t、\r 开头的字段前加单引号（阻止 Excel 公式执行）
 *   - 包含逗号、双引号、换行的字段用双引号包裹
 */
func csvEscape(s string) string {
	if len(s) == 0 {
		return s
	}
	/* 防止 CSV 公式注入 */
	first := s[0]
	if first == '=' || first == '+' || first == '-' || first == '@' || first == '\t' || first == '\r' {
		s = "'" + s
	}
	/* 包含特殊字符时用双引号包裹 */
	needsQuote := false
	for _, c := range s {
		if c == ',' || c == '"' || c == '\n' || c == '\r' {
			needsQuote = true
			break
		}
	}
	if needsQuote {
		escaped := strings.ReplaceAll(s, "\"", "\"\"")
		return "\"" + escaped + "\""
	}
	return s
}

/*
 * generateRandomPassword 生成安全随机密码
 * 使用 crypto/rand 确保密码不可预测
 */
func generateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
	b := make([]byte, length)
	randBytes := make([]byte, length)
	if _, err := crand.Read(randBytes); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	for i := range b {
		b[i] = charset[int(randBytes[i])%len(charset)]
	}
	return string(b)
}

// ========== Advanced Search ==========

// SearchUsers performs advanced user search with filters
// GET /api/admin/users/search
func (h *AdminHandler) SearchUsers(c *gin.Context) {
	// Parse pagination
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	// Parse search query
	query := c.Query("q")

	// Parse filters
	filters := make(map[string]interface{})
	if role := c.Query("role"); role != "" {
		filters["role"] = role
	}
	if status := c.Query("status"); status != "" {
		filters["status"] = status
	}
	if emailVerified := c.Query("email_verified"); emailVerified != "" {
		filters["email_verified"] = emailVerified == "true"
	}

	// Execute search
	users, total, err := h.userRepo.SearchUsers(query, filters, offset, limit)
	if err != nil {
		InternalError(c, "Search failed")
		return
	}

	// Convert to response format
	userList := make([]UserListItem, len(users))
	for i, u := range users {
		item := UserListItem{
			ID:               u.ID.String(),
			Email:            u.Email,
			Username:         u.Username,
			Role:             string(u.Role),
			Status:           u.Status,
			Avatar:           u.Avatar,
			EmailVerified:    u.EmailVerified,
			ProfileCompleted: u.ProfileCompleted,
			Nickname:         u.Nickname,
			GivenName:        u.GivenName,
			FamilyName:       u.FamilyName,
			PhoneNumber:      u.PhoneNumber,
			Company:          u.Company,
			Department:       u.Department,
			JobTitle:         u.JobTitle,
			ExternalSource:   u.ExternalSource,
			CreatedAt:        u.CreatedAt.Format(time.RFC3339),
			UpdatedAt:        u.UpdatedAt.Format(time.RFC3339),
		}
		if item.Status == "" {
			item.Status = "active"
		}
		if u.LastLoginAt != nil {
			t := u.LastLoginAt.Format(time.RFC3339)
			item.LastLoginAt = &t
		}
		userList[i] = item
	}

	Success(c, gin.H{
		"users": userList,
		"total": total,
		"page":  page,
		"limit": limit,
		"query": query,
	})
}

// ========== Authorization Management ==========

// GetUserAuthorizations returns all authorizations for a user
// GET /api/admin/users/:id/authorizations
func (h *AdminHandler) GetUserAuthorizations(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	auths, total, err := h.userAuthRepo.FindByUserPaginated(id, offset, limit)
	if err != nil {
		InternalError(c, "Failed to fetch authorizations")
		return
	}

	Success(c, gin.H{
		"authorizations": auths,
		"total":          total,
		"page":           page,
		"limit":          limit,
	})
}

// RevokeUserAuthorization revokes a specific authorization
// DELETE /api/admin/users/:id/authorizations/:auth_id
func (h *AdminHandler) RevokeUserAuthorization(c *gin.Context) {
	authIDStr := c.Param("auth_id")
	authID, err := uuid.Parse(authIDStr)
	if err != nil {
		BadRequest(c, "Invalid authorization ID")
		return
	}

	if err := h.userAuthRepo.Delete(authID); err != nil {
		InternalError(c, "Failed to revoke authorization")
		return
	}

	Success(c, gin.H{"message": "Authorization revoked successfully"})
}

// BatchRevokeAuthorizationsRequest represents batch revoke request
type BatchRevokeAuthorizationsRequest struct {
	AuthorizationIDs []string `json:"authorization_ids" binding:"required,min=1"`
}

// BatchRevokeAuthorizations revokes multiple authorizations
// DELETE /api/admin/authorizations/batch
func (h *AdminHandler) BatchRevokeAuthorizations(c *gin.Context) {
	var req BatchRevokeAuthorizationsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	ids := make([]uuid.UUID, 0, len(req.AuthorizationIDs))
	for _, idStr := range req.AuthorizationIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		BadRequest(c, "No valid authorization IDs provided")
		return
	}

	deleted, err := h.userAuthRepo.BatchDelete(ids)
	if err != nil {
		InternalError(c, "Failed to revoke authorizations")
		return
	}

	Success(c, gin.H{
		"message": "Authorizations revoked successfully",
		"revoked": deleted,
	})
}

// ========== Create & Update User ==========

// CreateUserRequest 管理员创建用户请求
type CreateUserRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Username    string `json:"username" binding:"required,min=2"`
	Password    string `json:"password"` // 可选，为空则自动生成
	Role        string `json:"role" binding:"omitempty,oneof=admin user"`
	Status      string `json:"status" binding:"omitempty,oneof=active suspended pending"`
	Nickname    string `json:"nickname"`
	PhoneNumber string `json:"phone_number"`
	Company     string `json:"company"`
	Department  string `json:"department"`
	JobTitle    string `json:"job_title"`
	SendWelcome bool   `json:"send_welcome"` // 是否发送欢迎邮件
}

// CreateUser 管理员创建用户
// POST /api/admin/users
func (h *AdminHandler) CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	/* 输入清洗 */
	req.Email = sanitize.Email(req.Email)
	if u, ok := sanitize.Username(req.Username); ok {
		req.Username = u
	} else {
		BadRequest(c, "Invalid username format")
		return
	}
	req.Nickname = sanitize.PlainText(req.Nickname, 100)

	// 检查 email 和 username 是否已存在
	if _, err := h.userRepo.FindByEmail(req.Email); err == nil {
		Conflict(c, "Email already exists")
		return
	}
	if _, err := h.userRepo.FindByUsername(req.Username); err == nil {
		Conflict(c, "Username already exists")
		return
	}

	user := &model.User{
		Email:       req.Email,
		Username:    req.Username,
		Role:        model.RoleUser,
		Status:      "active",
		Nickname:    req.Nickname,
		PhoneNumber: req.PhoneNumber,
		Company:     req.Company,
		Department:  req.Department,
		JobTitle:    req.JobTitle,
	}
	if req.Role != "" {
		user.Role = model.UserRole(req.Role)
	}
	if req.Status != "" {
		user.Status = req.Status
	}

	/* 设置密码：未提供则生成随机密码，提供则校验强度 */
	pwd := req.Password
	if pwd == "" {
		pwd = generateRandomPassword(16)
	} else if err := password.ValidateStrength(pwd); err != nil {
		BadRequest(c, err.Error())
		return
	}
	user.SetPassword(pwd)

	if err := h.userRepo.Create(user); err != nil {
		InternalError(c, "Failed to create user: "+err.Error())
		return
	}

	// 发送欢迎邮件
	if req.SendWelcome && h.emailService != nil {
		go h.emailService.SendWelcome(user.Email, user.Username)
	}

	response := gin.H{
		"message": "User created successfully",
		"user": gin.H{
			"id":       user.ID.String(),
			"email":    user.Email,
			"username": user.Username,
			"role":     string(user.Role),
			"status":   user.Status,
		},
	}
	// 如果密码是自动生成的，返回给管理员
	if req.Password == "" {
		response["generated_password"] = pwd
	}

	actorID := getActorID(c)
	audit.Log(audit.ActionAccountCreate, audit.ResultSuccess, actorID, user.ID.String(), c.ClientIP(), "email", user.Email)
	Created(c, response)
}

// UpdateUserRequest 管理员编辑用户请求
type UpdateUserRequest struct {
	Email         *string `json:"email" binding:"omitempty,email"`
	Username      *string `json:"username" binding:"omitempty,min=2"`
	Role          *string `json:"role" binding:"omitempty,oneof=admin user"`
	Status        *string `json:"status" binding:"omitempty,oneof=active suspended pending"`
	Nickname      *string `json:"nickname"`
	GivenName     *string `json:"given_name"`
	FamilyName    *string `json:"family_name"`
	PhoneNumber   *string `json:"phone_number"`
	Gender        *string `json:"gender"`
	Company       *string `json:"company"`
	Department    *string `json:"department"`
	JobTitle      *string `json:"job_title"`
	EmailVerified *bool   `json:"email_verified"`
}

// UpdateUser 管理员编辑用户完整资料
// POST /api/admin/users/:id
func (h *AdminHandler) UpdateUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	user, err := h.userRepo.FindByID(id)
	if err != nil {
		NotFound(c, "User not found")
		return
	}

	// 更新 email（需检查唯一性）
	if req.Email != nil && *req.Email != user.Email {
		exists, _ := h.userRepo.ExistsByEmail(*req.Email)
		if exists {
			Conflict(c, "Email already exists")
			return
		}
		user.Email = *req.Email
	}
	// 更新 username（需检查唯一性）
	if req.Username != nil && *req.Username != user.Username {
		exists, _ := h.userRepo.ExistsByUsername(*req.Username)
		if exists {
			Conflict(c, "Username already exists")
			return
		}
		user.Username = *req.Username
	}
	if req.Role != nil {
		user.Role = model.UserRole(*req.Role)
	}
	if req.Status != nil {
		user.Status = *req.Status
	}
	/* 输入清洗：对文本字段进行 HTML 剥离和长度截断 */
	if req.Nickname != nil {
		user.Nickname = sanitize.PlainText(*req.Nickname, 100)
	}
	if req.GivenName != nil {
		user.GivenName = sanitize.PlainText(*req.GivenName, 100)
	}
	if req.FamilyName != nil {
		user.FamilyName = sanitize.PlainText(*req.FamilyName, 100)
	}
	if req.PhoneNumber != nil {
		user.PhoneNumber = sanitize.String(*req.PhoneNumber, 30)
	}
	if req.Gender != nil {
		user.Gender = sanitize.String(*req.Gender, 20)
	}
	if req.Company != nil {
		user.Company = sanitize.PlainText(*req.Company, 200)
	}
	if req.Department != nil {
		user.Department = sanitize.PlainText(*req.Department, 200)
	}
	if req.JobTitle != nil {
		user.JobTitle = sanitize.PlainText(*req.JobTitle, 200)
	}
	if req.EmailVerified != nil {
		user.EmailVerified = *req.EmailVerified
	}

	if err := h.userRepo.Update(user); err != nil {
		InternalError(c, "Failed to update user")
		return
	}

	/* 角色或状态变更时记录审计日志 */
	if req.Role != nil || req.Status != nil || req.Email != nil {
		actorID := getActorID(c)
		extra := []any{}
		if req.Role != nil {
			extra = append(extra, "new_role", *req.Role)
		}
		if req.Status != nil {
			extra = append(extra, "new_status", *req.Status)
		}
		if req.Email != nil {
			extra = append(extra, "new_email", *req.Email)
		}
		audit.Log(audit.ActionStatusChange, audit.ResultSuccess, actorID, id.String(), c.ClientIP(), extra...)
	}

	/* 返回结构化响应，避免直接序列化 model 暴露内部字段 */
	Success(c, gin.H{"message": "User updated successfully", "user": buildFullUserResponse(user)})
}

// SendResetEmail 管理员主动向用户发送密码重置邮件
// POST /api/admin/users/:id/send-reset-email
func (h *AdminHandler) SendResetEmail(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	user, err := h.userRepo.FindByID(id)
	if err != nil {
		NotFound(c, "User not found")
		return
	}

	if h.resetService == nil {
		ServiceUnavailable(c, "Password reset service is currently unavailable")
		return
	}

	_, err = h.resetService.AdminRequestPasswordReset(user.Email, c.ClientIP(), "admin")
	if err != nil {
		InternalError(c, "Failed to process password reset request")
		return
	}

	Success(c, gin.H{"message": "Password reset email has been queued"})
}

/*
 * UnlockUser 管理员解锁用户账户
 * @route POST /api/admin/users/:id/unlock
 * 功能：重置登录失败计数和锁定状态，允许用户立即登录
 */
func (h *AdminHandler) UnlockUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	user, err := h.userRepo.FindByID(id)
	if err != nil {
		NotFound(c, "User not found")
		return
	}

	user.FailedLogins = 0
	user.LockedUntil = nil

	if err := h.userRepo.Update(user); err != nil {
		InternalError(c, "Failed to unlock user")
		return
	}

	actorID := getActorID(c)
	audit.Log(audit.ActionAccountUnlock, audit.ResultSuccess, actorID, id.String(), c.ClientIP())
	Success(c, gin.H{"message": "User account unlocked successfully"})
}

// RevokeAppAuthorizations revokes all authorizations for an app
// DELETE /api/admin/apps/:id/authorizations
func (h *AdminHandler) RevokeAppAuthorizations(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid app ID")
		return
	}

	deleted, err := h.userAuthRepo.DeleteByApp(id)
	if err != nil {
		InternalError(c, "Failed to revoke authorizations")
		return
	}

	actorID := getActorID(c)
	audit.Log(audit.ActionTokenRevoke, audit.ResultSuccess, actorID, id.String(), c.ClientIP(), "revoked_count", deleted)

	Success(c, gin.H{
		"message": "All authorizations for app revoked",
		"revoked": deleted,
	})
}

/* getActorID 从 Gin 上下文提取当前操作者（管理员）的 ID */
func getActorID(c *gin.Context) string {
	if uid, ok := ctx.GetUserID(c); ok {
		return uid.String()
	}
	return "unknown"
}
