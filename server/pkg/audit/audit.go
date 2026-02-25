/*
 * Package audit 敏感操作审计日志
 * 功能：记录密码修改、密钥重置、角色变更、账户锁定/解锁等安全敏感操作
 *       所有日志通过结构化 logger 输出，便于 SIEM 系统采集和告警
 */
package audit

import (
	"server/pkg/logger"
)

/* Action 审计操作类型 */
type Action string

const (
	ActionPasswordChange  Action = "password_change"
	ActionPasswordReset   Action = "password_reset"
	ActionSecretReset     Action = "app_secret_reset"
	ActionRoleChange      Action = "role_change"
	ActionAccountLock     Action = "account_lock"
	ActionAccountUnlock   Action = "account_unlock"
	ActionAccountDelete   Action = "account_delete"
	ActionAccountCreate   Action = "account_create"
	ActionStatusChange    Action = "status_change"
	ActionTokenIssue      Action = "token_issue"
	ActionTokenRevoke     Action = "token_revoke"
	ActionAppCreate       Action = "app_create"
	ActionAppDelete       Action = "app_delete"
	ActionConfigChange    Action = "config_change"
	ActionEmailChange     Action = "email_change"
	ActionMFAEnable       Action = "mfa_enable"
	ActionMFADisable      Action = "mfa_disable"
	ActionProviderCreate  Action = "provider_create"
	ActionProviderDelete  Action = "provider_delete"
	ActionJWTSecretRotate Action = "jwt_secret_rotate"
)

/* Result 操作结果 */
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
	ResultDenied  Result = "denied"
)

/*
 * Log 记录一条审计日志
 * @param action   - 操作类型
 * @param result   - 操作结果
 * @param actorID  - 执行者 ID（管理员或用户自身）
 * @param targetID - 目标对象 ID（被操作的用户/应用）
 * @param ip       - 客户端 IP
 * @param extra    - 附加键值对（可选，如 reason、old_role、new_role 等）
 */
func Log(action Action, result Result, actorID, targetID, ip string, extra ...any) {
	args := []any{
		"audit_action", string(action),
		"audit_result", string(result),
		"actor_id", actorID,
		"target_id", targetID,
		"client_ip", ip,
	}
	args = append(args, extra...)

	log := logger.Default()
	switch result {
	case ResultFailure, ResultDenied:
		log.Warn("[AUDIT] "+string(action), args...)
	default:
		log.Info("[AUDIT] "+string(action), args...)
	}
}
