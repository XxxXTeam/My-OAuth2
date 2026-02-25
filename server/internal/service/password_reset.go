package service

import (
	"errors"
	"fmt"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/password"
)

var (
	ErrResetTokenInvalid    = errors.New("invalid reset token")
	ErrResetTokenExpired    = errors.New("reset token expired")
	ErrResetTooManyRequests = errors.New("too many reset requests")
	ErrUserNotFoundForReset = errors.New("user not found")
	ErrEmailSendFailed      = errors.New("failed to send email")
	ErrEmailNotConfigured   = errors.New("email service not configured")
)

const (
	ResetTokenTTL      = 1 * time.Hour // 重置令牌有效期
	ResetRateLimitTime = 1 * time.Hour // 限流时间窗口
	ResetRateLimitMax  = 3             // 每小时最多请求次数
)

type PasswordResetService struct {
	userRepo    *repository.UserRepository
	resetRepo   *repository.PasswordResetRepository
	oauthRepo   *repository.OAuthRepository
	emailQueue  *EmailQueueService
	frontendURL string
}

func NewPasswordResetService(
	userRepo *repository.UserRepository,
	resetRepo *repository.PasswordResetRepository,
) *PasswordResetService {
	return &PasswordResetService{
		userRepo:  userRepo,
		resetRepo: resetRepo,
	}
}

/* SetEmailQueue 注入邮件队列服务 */
func (s *PasswordResetService) SetEmailQueue(queue *EmailQueueService, frontendURL string) {
	s.emailQueue = queue
	s.frontendURL = frontendURL
}

/* SetOAuthRepo 注入 OAuth 仓储（用于密码重置后撤销旧 token） */
func (s *PasswordResetService) SetOAuthRepo(repo *repository.OAuthRepository) {
	s.oauthRepo = repo
}

// RequestPasswordReset 请求密码重置
// 如果配置了邮件服务，会发送重置链接到用户邮箱
// 返回值: token (开发环境) 或空字符串 (生产环境，通过邮件发送)
func (s *PasswordResetService) RequestPasswordReset(userEmail, ipAddress, userAgent string) (string, error) {
	// 查找用户
	user, err := s.userRepo.FindByEmail(userEmail)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return "", ErrUserNotFoundForReset
		}
		return "", err
	}

	// 检查限流
	count, err := s.resetRepo.CountRecentByUserID(user.ID, ResetRateLimitTime)
	if err != nil {
		return "", err
	}
	if count >= ResetRateLimitMax {
		return "", ErrResetTooManyRequests
	}

	// 生成令牌
	token, err := model.GenerateResetToken()
	if err != nil {
		return "", err
	}

	// 创建重置记录
	reset := &model.PasswordReset{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(ResetTokenTTL),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.resetRepo.Create(reset); err != nil {
		return "", err
	}

	// 入队发送密码重置邮件（后台 worker 异步处理）
	if s.emailQueue != nil && s.frontendURL != "" {
		resetLink := fmt.Sprintf("%s/reset-password?token=%s", s.frontendURL, token)
		username := user.Username
		if username == "" {
			username = user.Email
		}
		if err := s.emailQueue.EnqueuePasswordReset(user.Email, username, resetLink); err != nil {
			_ = s.resetRepo.MarkAsUsed(reset.ID)
			return "", ErrEmailSendFailed
		}
		return "", nil
	}

	// 未配置邮件队列，开发环境返回 token
	return token, nil
}

// ValidateResetToken 验证重置令牌
func (s *PasswordResetService) ValidateResetToken(token string) (*model.User, error) {
	reset, err := s.resetRepo.FindValidByToken(token)
	if err != nil {
		if errors.Is(err, repository.ErrResetTokenNotFound) {
			return nil, ErrResetTokenInvalid
		}
		if errors.Is(err, repository.ErrResetTokenExpired) {
			return nil, ErrResetTokenExpired
		}
		if errors.Is(err, repository.ErrResetTokenUsed) {
			return nil, ErrResetTokenInvalid
		}
		return nil, err
	}

	// 获取用户信息
	user, err := s.userRepo.FindByID(reset.UserID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// ResetPassword 重置密码
func (s *PasswordResetService) ResetPassword(token, newPassword string) error {
	// 验证令牌
	reset, err := s.resetRepo.FindValidByToken(token)
	if err != nil {
		if errors.Is(err, repository.ErrResetTokenNotFound) {
			return ErrResetTokenInvalid
		}
		if errors.Is(err, repository.ErrResetTokenExpired) {
			return ErrResetTokenExpired
		}
		if errors.Is(err, repository.ErrResetTokenUsed) {
			return ErrResetTokenInvalid
		}
		return err
	}

	// 获取用户
	user, err := s.userRepo.FindByID(reset.UserID)
	if err != nil {
		return err
	}

	/* 校验新密码强度（含常见弱密码黑名单） */
	if err := password.ValidateStrength(newPassword); err != nil {
		return err
	}

	// 哈希新密码
	hashedPassword, err := password.Hash(newPassword)
	if err != nil {
		return err
	}

	/* 更新密码并重置锁定状态（用户可能因连续登录失败被锁定后通过重置密码恢复） */
	user.PasswordHash = hashedPassword
	user.FailedLogins = 0
	user.LockedUntil = nil
	if err := s.userRepo.Update(user); err != nil {
		return err
	}

	// 标记令牌为已使用
	if err := s.resetRepo.MarkAsUsed(reset.ID); err != nil {
		return err
	}

	// 使该用户的其他未使用令牌失效
	if err := s.resetRepo.InvalidateUserTokens(user.ID); err != nil {
		// 非关键错误，仅记录
		return nil
	}

	/* 密码重置后撤销该用户所有 auth refresh token，强制重新登录 */
	if s.oauthRepo != nil {
		_ = s.oauthRepo.RevokeUserAuthRefreshTokens(user.ID)
	}

	// 入队发送密码重置成功通知邮件
	if s.emailQueue != nil {
		username := user.Username
		if username == "" {
			username = user.Email
		}
		_ = s.emailQueue.EnqueueResetSuccess(user.Email, username)
	}

	return nil
}

// AdminRequestPasswordReset 管理员发起的密码重置（跳过限流）
func (s *PasswordResetService) AdminRequestPasswordReset(userEmail, ipAddress, userAgent string) (string, error) {
	// 查找用户
	user, err := s.userRepo.FindByEmail(userEmail)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return "", ErrUserNotFoundForReset
		}
		return "", err
	}

	// 生成令牌
	token, err := model.GenerateResetToken()
	if err != nil {
		return "", err
	}

	// 创建重置记录
	reset := &model.PasswordReset{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(ResetTokenTTL),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.resetRepo.Create(reset); err != nil {
		return "", err
	}

	// 入队发送密码重置邮件
	if s.emailQueue != nil && s.frontendURL != "" {
		resetLink := fmt.Sprintf("%s/reset-password?token=%s", s.frontendURL, token)
		username := user.Username
		if username == "" {
			username = user.Email
		}
		if err := s.emailQueue.EnqueuePasswordReset(user.Email, username, resetLink); err != nil {
			_ = s.resetRepo.MarkAsUsed(reset.ID)
			return "", ErrEmailSendFailed
		}
		return "", nil
	}

	// 未配置邮件队列，返回 token
	return token, nil
}

// CleanupExpiredTokens 清理过期令牌
func (s *PasswordResetService) CleanupExpiredTokens() error {
	return s.resetRepo.DeleteExpired()
}
