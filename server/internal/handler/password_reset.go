package handler

import (
	"errors"

	"server/internal/service"

	"github.com/gin-gonic/gin"
)

/*
 * PasswordResetHandler 密码重置请求处理器
 * 功能：处理忘记密码、验证重置令牌、重置密码等 HTTP 请求
 */
type PasswordResetHandler struct {
	resetService *service.PasswordResetService
}

/*
 * NewPasswordResetHandler 创建密码重置处理器实例
 * @param resetService - 密码重置服务
 */
func NewPasswordResetHandler(resetService *service.PasswordResetService) *PasswordResetHandler {
	return &PasswordResetHandler{resetService: resetService}
}

/* ForgotPasswordRequest 忘记密码请求体 */
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

/* ResetPasswordRequest 重置密码请求体 */
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

/* ValidateTokenRequest 验证令牌请求体 */
type ValidateTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

/*
 * ForgotPassword 发送密码重置邮件
 * @route POST /api/auth/forgot-password
 * 功能：接受邮箱，入队发送重置链接，不透露用户是否存在
 */
func (h *PasswordResetHandler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	token, err := h.resetService.RequestPasswordReset(
		req.Email,
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil {
		if errors.Is(err, service.ErrResetTooManyRequests) {
			TooManyRequests(c, "Too many password reset requests. Please try again later.")
			return
		}
		if errors.Is(err, service.ErrUserNotFoundForReset) {
			// 为了安全，不透露用户是否存在，返回成功消息
			Success(c, gin.H{
				"message": "If an account with that email exists, a password reset link has been sent.",
			})
			return
		}
		if errors.Is(err, service.ErrEmailSendFailed) {
			InternalError(c, "Failed to send password reset email. Please try again later or contact support.")
			return
		}
		InternalError(c, "Failed to process password reset request")
		return
	}

	/* token 不再通过 API 响应暴露，开发模式下可查看服务端日志 */
	_ = token
	Success(c, gin.H{
		"message": "If an account with that email exists, a password reset link has been sent.",
	})
}

/*
 * ValidateResetToken 验证重置令牌是否有效
 * @route POST /api/auth/validate-reset-token
 */
func (h *PasswordResetHandler) ValidateResetToken(c *gin.Context) {
	var req ValidateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	user, err := h.resetService.ValidateResetToken(req.Token)
	if err != nil {
		if errors.Is(err, service.ErrResetTokenInvalid) {
			BadRequest(c, "Invalid or expired reset token")
			return
		}
		if errors.Is(err, service.ErrResetTokenExpired) {
			BadRequest(c, "Reset token has expired")
			return
		}
		InternalError(c, "Failed to validate reset token")
		return
	}

	Success(c, gin.H{
		"valid": true,
		"email": user.Email,
	})
}

/*
 * ResetPassword 重置密码
 * @route POST /api/auth/reset-password
 * 功能：校验令牌后设置新密码
 */
func (h *PasswordResetHandler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	err := h.resetService.ResetPassword(req.Token, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrResetTokenInvalid) {
			BadRequest(c, "Invalid or expired reset token")
			return
		}
		if errors.Is(err, service.ErrResetTokenExpired) {
			BadRequest(c, "Reset token has expired")
			return
		}
		InternalError(c, "Failed to reset password")
		return
	}

	Success(c, gin.H{
		"message": "Password has been reset successfully. You can now login with your new password.",
	})
}
