package handler

/*
 * 统一错误码定义
 * 前端通过 error.code 映射 i18n 翻译，实现错误信息国际化
 * 命名规范: 大写蛇形, 按模块分组
 */

/* ===== 认证/授权错误 ===== */
const (
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"
	ErrCodeInvalidCredentials = "INVALID_CREDENTIALS"
	ErrCodeTokenExpired       = "TOKEN_EXPIRED"
	ErrCodeTokenInvalid       = "TOKEN_INVALID"
	ErrCodeCSRFInvalid        = "CSRF_INVALID"
	ErrCodeSessionExpired     = "SESSION_EXPIRED"
	ErrCodeAdminRequired      = "ADMIN_REQUIRED"
)

/* ===== 注册/用户错误 ===== */
const (
	ErrCodeEmailExists        = "EMAIL_EXISTS"
	ErrCodeUsernameExists     = "USERNAME_EXISTS"
	ErrCodeRegistrationClosed = "REGISTRATION_CLOSED"
	ErrCodeUserNotFound       = "USER_NOT_FOUND"
	ErrCodeInvalidPassword    = "INVALID_PASSWORD"
	ErrCodeWeakPassword       = "WEAK_PASSWORD"
	ErrCodeUserDisabled       = "USER_DISABLED"
)

/* ===== 请求/验证错误 ===== */
const (
	ErrCodeBadRequest      = "BAD_REQUEST"
	ErrCodeNotFound        = "NOT_FOUND"
	ErrCodeConflict        = "CONFLICT"
	ErrCodeTooManyRequests = "TOO_MANY_REQUESTS"
)

/* ===== OAuth 错误 ===== */
const (
	ErrCodeInvalidClient       = "INVALID_CLIENT"
	ErrCodeInvalidGrant        = "INVALID_GRANT"
	ErrCodeInvalidScope        = "INVALID_SCOPE"
	ErrCodeInvalidRedirectURI  = "INVALID_REDIRECT_URI"
	ErrCodeAccessDenied        = "ACCESS_DENIED"
	ErrCodeAuthCodeExpired     = "AUTH_CODE_EXPIRED"
	ErrCodeInvalidCodeVerifier = "INVALID_CODE_VERIFIER"
)

/* ===== 系统错误 ===== */
const (
	ErrCodeInternalError = "INTERNAL_ERROR"
)
