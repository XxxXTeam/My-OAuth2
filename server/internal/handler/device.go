package handler

import (
	"net/http"
	"time"

	gctx "server/internal/context"
	"server/internal/model"
	"server/internal/repository"

	"github.com/gin-gonic/gin"
)

/*
 * DeviceHandler 设备授权请求处理器 (RFC 8628)
 * 功能：处理设备授权码申请、用户授权提交、设备信息查询等 HTTP 请求
 */
type DeviceHandler struct {
	deviceRepo  *repository.DeviceCodeRepository
	appRepo     *repository.ApplicationRepository
	baseURL     string
	frontendURL string
}

/*
 * NewDeviceHandler 创建设备授权处理器实例
 * @param deviceRepo  - 设备码仓储
 * @param appRepo     - 应用仓储
 * @param baseURL     - 服务器 URL
 * @param frontendURL - 前端 URL
 */
func NewDeviceHandler(deviceRepo *repository.DeviceCodeRepository, appRepo *repository.ApplicationRepository, baseURL, frontendURL string) *DeviceHandler {
	return &DeviceHandler{
		deviceRepo:  deviceRepo,
		appRepo:     appRepo,
		baseURL:     baseURL,
		frontendURL: frontendURL,
	}
}

/* DeviceAuthorizationRequest 设备授权请求参数 */
type DeviceAuthorizationRequest struct {
	ClientID string `form:"client_id" binding:"required"`
	Scope    string `form:"scope"`
}

/* DeviceAuthorizationResponse 设备授权响应结构 (RFC 8628) */
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// DeviceAuthorization handles the device authorization endpoint
// POST /oauth/device/code
func (h *DeviceHandler) DeviceAuthorization(c *gin.Context) {
	var req DeviceAuthorizationRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Validate client
	app, err := h.appRepo.FindByClientID(req.ClientID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Unknown client",
		})
		return
	}

	// Check if device_code grant is allowed
	if !app.SupportsGrantType("urn:ietf:params:oauth:grant-type:device_code") && !app.SupportsGrantType("device_code") {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Client is not authorized to use device authorization grant",
		})
		return
	}

	// Build verification URI
	verificationURI := h.frontendURL + "/device"
	if h.frontendURL == "" {
		verificationURI = h.baseURL + "/device"
	}

	// Create device code
	deviceCode := &model.DeviceCode{
		ClientID:        req.ClientID,
		Scope:           req.Scope,
		VerificationURI: verificationURI,
		ExpiresAt:       time.Now().Add(30 * time.Minute), // 30 minutes expiry
		Interval:        5,
	}

	if err := h.deviceRepo.Create(deviceCode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to create device code",
		})
		return
	}

	// Set verification_uri_complete with user_code
	deviceCode.VerificationURIComplete = verificationURI + "?user_code=" + deviceCode.UserCode

	c.JSON(http.StatusOK, DeviceAuthorizationResponse{
		DeviceCode:              deviceCode.DeviceCode,
		UserCode:                deviceCode.UserCode,
		VerificationURI:         deviceCode.VerificationURI,
		VerificationURIComplete: deviceCode.VerificationURIComplete,
		ExpiresIn:               int(time.Until(deviceCode.ExpiresAt).Seconds()),
		Interval:                deviceCode.Interval,
	})
}

// GetDeviceInfo returns device code info for authorization page
// GET /api/oauth/device/info
func (h *DeviceHandler) GetDeviceInfo(c *gin.Context) {
	userCode := c.Query("user_code")
	if userCode == "" {
		BadRequest(c, "user_code is required")
		return
	}

	dc, err := h.deviceRepo.FindByUserCode(userCode)
	if err != nil {
		NotFound(c, "Device code not found or expired")
		return
	}

	if dc.IsExpired() {
		BadRequest(c, "Device code has expired")
		return
	}

	if !dc.IsPending() {
		BadRequest(c, "Device code has already been used")
		return
	}

	// Get application info
	app, err := h.appRepo.FindByClientID(dc.ClientID)
	if err != nil {
		InternalError(c, "Application not found")
		return
	}

	Success(c, gin.H{
		"user_code": dc.UserCode,
		"scope":     dc.Scope,
		"app": gin.H{
			"id":          app.ID.String(),
			"name":        app.Name,
			"description": app.Description,
		},
		"expires_in": int(time.Until(dc.ExpiresAt).Seconds()),
	})
}

// DeviceAuthorizeSubmitRequest represents the device authorization submission
type DeviceAuthorizeSubmitRequest struct {
	UserCode string `json:"user_code" binding:"required"`
	Consent  string `json:"consent" binding:"required"` // "allow" or "deny"
}

// DeviceAuthorizeSubmit handles user authorization for device code
// POST /api/oauth/device/authorize
func (h *DeviceHandler) DeviceAuthorizeSubmit(c *gin.Context) {
	var req DeviceAuthorizeSubmitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Get authenticated user
	userID, ok := gctx.GetUserID(c)
	if !ok {
		Unauthorized(c, "User not authenticated")
		return
	}

	// Find device code
	dc, err := h.deviceRepo.FindByUserCode(req.UserCode)
	if err != nil {
		NotFound(c, "Device code not found")
		return
	}

	if dc.IsExpired() {
		BadRequest(c, "Device code has expired")
		return
	}

	if !dc.IsPending() {
		BadRequest(c, "Device code has already been processed")
		return
	}

	if req.Consent == "allow" {
		// Authorize the device
		if err := h.deviceRepo.Authorize(req.UserCode, userID); err != nil {
			InternalError(c, "Failed to authorize device")
			return
		}
		Success(c, gin.H{
			"message": "Device authorized successfully",
		})
	} else {
		// Deny the device
		if err := h.deviceRepo.Deny(req.UserCode); err != nil {
			InternalError(c, "Failed to deny device")
			return
		}
		Success(c, gin.H{
			"message": "Device authorization denied",
		})
	}
}
