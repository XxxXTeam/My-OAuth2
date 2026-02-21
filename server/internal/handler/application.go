package handler

import (
	"errors"

	ctx "server/internal/context"
	"server/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/*
 * ApplicationHandler 应用管理请求处理器
 * 功能：处理 OAuth2 应用的 CRUD、密钥重置、统计查询等 HTTP 请求
 */
type ApplicationHandler struct {
	appService *service.ApplicationService
}

/*
 * NewApplicationHandler 创建应用管理处理器实例
 * @param appService - 应用管理服务
 */
func NewApplicationHandler(appService *service.ApplicationService) *ApplicationHandler {
	return &ApplicationHandler{appService: appService}
}

/* CreateAppRequest 创建应用请求体 */
type CreateAppRequest struct {
	Name         string   `json:"name" binding:"required,min=1,max=200"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris" binding:"required,min=1"`
	Scopes       []string `json:"scopes"`
	GrantTypes   []string `json:"grant_types"`
}

/* AppResponse 应用 API 响应结构 */
type AppResponse struct {
	ID           string   `json:"id"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	GrantTypes   []string `json:"grant_types"`
	CreatedAt    string   `json:"created_at"`
}

/*
 * CreateApp 创建新应用
 * @route POST /api/apps
 */
func (h *ApplicationHandler) CreateApp(c *gin.Context) {
	var req CreateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	app, err := h.appService.CreateApp(&service.CreateAppInput{
		Name:         req.Name,
		Description:  req.Description,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
		GrantTypes:   req.GrantTypes,
		UserID:       userID,
	})
	if err != nil {
		InternalError(c, "Failed to create application")
		return
	}

	// Return with client_secret (only shown once)
	Created(c, AppResponse{
		ID:           app.ID.String(),
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Name:         app.Name,
		Description:  app.Description,
		RedirectURIs: app.GetRedirectURIs(),
		Scopes:       app.GetScopes(),
		GrantTypes:   app.GetGrantTypes(),
		CreatedAt:    app.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

/*
 * ListApps 获取当前用户的所有应用
 * @route GET /api/apps
 */
func (h *ApplicationHandler) ListApps(c *gin.Context) {
	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	apps, err := h.appService.GetUserApps(userID)
	if err != nil {
		InternalError(c, "Failed to get applications")
		return
	}

	var response []AppResponse
	for _, app := range apps {
		response = append(response, AppResponse{
			ID:           app.ID.String(),
			ClientID:     app.ClientID,
			Name:         app.Name,
			Description:  app.Description,
			RedirectURIs: app.GetRedirectURIs(),
			Scopes:       app.GetScopes(),
			GrantTypes:   app.GetGrantTypes(),
			CreatedAt:    app.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	Success(c, response)
}

/*
 * GetApp 根据 ID 获取应用详情
 * @route GET /api/apps/:id
 * 功能：管理员可查看任意应用，普通用户仅能查看自己的
 */
func (h *ApplicationHandler) GetApp(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid application ID")
		return
	}

	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	userRole, _ := ctx.GetUserRole(c)

	app, err := h.appService.GetApp(id)
	if err != nil {
		if errors.Is(err, service.ErrAppNotFound) {
			NotFound(c, "Application not found")
			return
		}
		InternalError(c, "Failed to get application")
		return
	}

	// Check ownership (admin can view any app)
	if userRole != "admin" && app.UserID != userID {
		Forbidden(c, "Not the application owner")
		return
	}

	Success(c, AppResponse{
		ID:           app.ID.String(),
		ClientID:     app.ClientID,
		Name:         app.Name,
		Description:  app.Description,
		RedirectURIs: app.GetRedirectURIs(),
		Scopes:       app.GetScopes(),
		GrantTypes:   app.GetGrantTypes(),
		CreatedAt:    app.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

/* UpdateAppRequest 更新应用请求体 */
type UpdateAppRequest struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	GrantTypes   []string `json:"grant_types"`
}

/*
 * UpdateApp 更新应用信息
 * @route PUT /api/apps/:id
 */
func (h *ApplicationHandler) UpdateApp(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid application ID")
		return
	}

	var req UpdateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	app, err := h.appService.UpdateApp(&service.UpdateAppInput{
		ID:           id,
		Name:         req.Name,
		Description:  req.Description,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
		GrantTypes:   req.GrantTypes,
		UserID:       userID,
	})
	if err != nil {
		if errors.Is(err, service.ErrAppNotFound) {
			NotFound(c, "Application not found")
			return
		}
		if errors.Is(err, service.ErrNotAppOwner) {
			Forbidden(c, "Not the application owner")
			return
		}
		InternalError(c, "Failed to update application")
		return
	}

	Success(c, AppResponse{
		ID:           app.ID.String(),
		ClientID:     app.ClientID,
		Name:         app.Name,
		Description:  app.Description,
		RedirectURIs: app.GetRedirectURIs(),
		Scopes:       app.GetScopes(),
		GrantTypes:   app.GetGrantTypes(),
		CreatedAt:    app.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

/*
 * ResetSecret 重置应用的客户端密钥
 * @route POST /api/apps/:id/reset-secret
 */
func (h *ApplicationHandler) ResetSecret(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid application ID")
		return
	}

	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	app, newSecret, err := h.appService.ResetSecret(id, userID)
	if err != nil {
		if errors.Is(err, service.ErrAppNotFound) {
			NotFound(c, "Application not found")
			return
		}
		if errors.Is(err, service.ErrNotAppOwner) {
			Forbidden(c, "Not the application owner")
			return
		}
		InternalError(c, "Failed to reset secret")
		return
	}

	Success(c, AppResponse{
		ID:           app.ID.String(),
		ClientID:     app.ClientID,
		ClientSecret: newSecret,
		Name:         app.Name,
		Description:  app.Description,
		RedirectURIs: app.GetRedirectURIs(),
		Scopes:       app.GetScopes(),
		GrantTypes:   app.GetGrantTypes(),
		CreatedAt:    app.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

/*
 * DeleteApp 删除应用
 * @route DELETE /api/apps/:id
 */
func (h *ApplicationHandler) DeleteApp(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid application ID")
		return
	}

	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	if err := h.appService.DeleteApp(id, userID); err != nil {
		if errors.Is(err, service.ErrAppNotFound) {
			NotFound(c, "Application not found")
			return
		}
		if errors.Is(err, service.ErrNotAppOwner) {
			Forbidden(c, "Not the application owner")
			return
		}
		InternalError(c, "Failed to delete application")
		return
	}

	Success(c, gin.H{"message": "Application deleted successfully"})
}

/*
 * GetAppStats 获取应用统计数据
 * @route GET /api/apps/:id/stats
 */
func (h *ApplicationHandler) GetAppStats(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		BadRequest(c, "Invalid application ID")
		return
	}

	userID, ok := ctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	stats, err := h.appService.GetAppStats(id, userID)
	if err != nil {
		if errors.Is(err, service.ErrAppNotFound) {
			NotFound(c, "Application not found")
			return
		}
		if errors.Is(err, service.ErrNotAppOwner) {
			Forbidden(c, "Not the application owner")
			return
		}
		InternalError(c, "Failed to get application stats")
		return
	}

	Success(c, stats)
}
