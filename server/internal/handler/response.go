/*
 * Package handler HTTP 请求处理层
 * 功能：接收 HTTP 请求、参数校验、调用 service 层、返回统一格式的 JSON 响应
 */
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

/*
 * Response 统一 API 响应结构
 * 功能：所有 API 接口均返回此结构，包含 success 标志、data 和 error 字段
 */
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *ErrorInfo  `json:"error,omitempty"`
}

/* ErrorInfo 错误详情结构，包含错误码和可读消息 */
type ErrorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

/* Success 发送 200 成功响应 */
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    data,
	})
}

/* Created 发送 201 创建成功响应 */
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, Response{
		Success: true,
		Data:    data,
	})
}

/*
 * Error 发送错误响应
 * @param c       - Gin 上下文
 * @param status  - HTTP 状态码
 * @param code    - 业务错误码
 * @param message - 可读错误消息
 */
func Error(c *gin.Context, status int, code, message string) {
	c.JSON(status, Response{
		Success: false,
		Error: &ErrorInfo{
			Code:    code,
			Message: message,
		},
	})
}

/* BadRequest 发送 400 错误请求响应 */
func BadRequest(c *gin.Context, message string) {
	Error(c, http.StatusBadRequest, "BAD_REQUEST", message)
}

/* Unauthorized 发送 401 未认证响应 */
func Unauthorized(c *gin.Context, message string) {
	Error(c, http.StatusUnauthorized, "UNAUTHORIZED", message)
}

/* Forbidden 发送 403 无权限响应 */
func Forbidden(c *gin.Context, message string) {
	Error(c, http.StatusForbidden, "FORBIDDEN", message)
}

/* NotFound 发送 404 未找到响应 */
func NotFound(c *gin.Context, message string) {
	Error(c, http.StatusNotFound, "NOT_FOUND", message)
}

/* Conflict 发送 409 冲突响应 */
func Conflict(c *gin.Context, message string) {
	Error(c, http.StatusConflict, "CONFLICT", message)
}

/* InternalError 发送 500 内部错误响应 */
func InternalError(c *gin.Context, message string) {
	Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", message)
}

/* TooManyRequests 发送 429 请求过多响应 */
func TooManyRequests(c *gin.Context, message string) {
	Error(c, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", message)
}

/* ServiceUnavailable 发送 503 服务不可用响应 */
func ServiceUnavailable(c *gin.Context, message string) {
	Error(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", message)
}
