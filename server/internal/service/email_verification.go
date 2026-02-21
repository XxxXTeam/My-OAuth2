package service

import (
	"errors"
	"fmt"
	"time"

	"server/internal/model"
	"server/internal/repository"

	"github.com/google/uuid"
)

var (
	ErrVerifyTokenInvalid    = errors.New("invalid verification token")
	ErrVerifyTokenExpired    = errors.New("verification token expired")
	ErrVerifyTooManyRequests = errors.New("too many verification requests")
	ErrEmailAlreadyVerified  = errors.New("email already verified")
	ErrEmailAlreadyInUse     = errors.New("email already in use")
	ErrEmailServiceRequired  = errors.New("email service not configured")
)

const (
	VerifyTokenTTL      = 24 * time.Hour // 验证令牌有效期
	VerifyRateLimitTime = 1 * time.Hour  // 限流时间窗口
	VerifyRateLimitMax  = 5              // 每小时最多请求次数
)

type EmailVerificationService struct {
	userRepo    *repository.UserRepository
	verifyRepo  *repository.EmailVerificationRepository
	emailQueue  *EmailQueueService
	frontendURL string
}

func NewEmailVerificationService(
	userRepo *repository.UserRepository,
	verifyRepo *repository.EmailVerificationRepository,
) *EmailVerificationService {
	return &EmailVerificationService{
		userRepo:   userRepo,
		verifyRepo: verifyRepo,
	}
}

/* SetEmailQueue 注入邮件队列服务 */
func (s *EmailVerificationService) SetEmailQueue(queue *EmailQueueService, frontendURL string) {
	s.emailQueue = queue
	s.frontendURL = frontendURL
}

/* RequestVerification 请求验证当前邮箱（入队模式） */
func (s *EmailVerificationService) RequestVerification(userID uuid.UUID) error {
	if s.emailQueue == nil {
		return ErrEmailServiceRequired
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	if user.EmailVerified {
		return ErrEmailAlreadyVerified
	}

	// 限流检查
	count, err := s.verifyRepo.CountRecentByUserID(userID, VerifyRateLimitTime)
	if err != nil {
		return err
	}
	if count >= VerifyRateLimitMax {
		return ErrVerifyTooManyRequests
	}

	// 使旧令牌失效
	_ = s.verifyRepo.InvalidateUserTokens(userID)

	// 生成令牌
	token, err := model.GenerateResetToken()
	if err != nil {
		return err
	}

	v := &model.EmailVerification{
		UserID:    userID,
		Email:     user.Email,
		Token:     token,
		ExpiresAt: time.Now().Add(VerifyTokenTTL),
	}

	if err := s.verifyRepo.Create(v); err != nil {
		return err
	}

	// 入队发送验证邮件（后台 worker 异步处理）
	verifyLink := fmt.Sprintf("%s/verify-email?token=%s", s.frontendURL, token)
	username := user.Username
	if username == "" {
		username = user.Email
	}
	if err := s.emailQueue.EnqueueVerification(user.Email, username, verifyLink); err != nil {
		_ = s.verifyRepo.MarkAsUsed(v.ID)
		return fmt.Errorf("failed to enqueue verification email: %w", err)
	}

	return nil
}

/* RequestEmailChange 请求更换邮箱（入队模式，向新邮箱发送验证） */
func (s *EmailVerificationService) RequestEmailChange(userID uuid.UUID, newEmail string) error {
	if s.emailQueue == nil {
		return ErrEmailServiceRequired
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	// 检查新邮箱是否已被占用
	exists, err := s.userRepo.ExistsByEmail(newEmail)
	if err != nil {
		return err
	}
	if exists {
		return ErrEmailAlreadyInUse
	}

	// 限流检查
	count, err := s.verifyRepo.CountRecentByUserID(userID, VerifyRateLimitTime)
	if err != nil {
		return err
	}
	if count >= VerifyRateLimitMax {
		return ErrVerifyTooManyRequests
	}

	// 使旧令牌失效
	_ = s.verifyRepo.InvalidateUserTokens(userID)

	// 生成令牌
	token, err := model.GenerateResetToken()
	if err != nil {
		return err
	}

	v := &model.EmailVerification{
		UserID:    userID,
		Email:     newEmail,
		Token:     token,
		ExpiresAt: time.Now().Add(VerifyTokenTTL),
	}

	if err := s.verifyRepo.Create(v); err != nil {
		return err
	}

	// 入队发送验证邮件到新邮箱（后台 worker 异步处理）
	verifyLink := fmt.Sprintf("%s/verify-email?token=%s", s.frontendURL, token)
	username := user.Username
	if username == "" {
		username = user.Email
	}
	if err := s.emailQueue.EnqueueEmailChange(newEmail, username, verifyLink); err != nil {
		_ = s.verifyRepo.MarkAsUsed(v.ID)
		return fmt.Errorf("failed to enqueue email change verification: %w", err)
	}

	return nil
}

// VerifyEmail 验证邮箱令牌
func (s *EmailVerificationService) VerifyEmail(token string) error {
	v, err := s.verifyRepo.FindValidByToken(token)
	if err != nil {
		if errors.Is(err, repository.ErrVerifyTokenNotFound) {
			return ErrVerifyTokenInvalid
		}
		if errors.Is(err, repository.ErrVerifyTokenExpired) {
			return ErrVerifyTokenExpired
		}
		if errors.Is(err, repository.ErrVerifyTokenUsed) {
			return ErrVerifyTokenInvalid
		}
		return err
	}

	user, err := s.userRepo.FindByID(v.UserID)
	if err != nil {
		return err
	}

	// 如果是更换邮箱，再次检查新邮箱唯一性
	if v.Email != user.Email {
		exists, err := s.userRepo.ExistsByEmail(v.Email)
		if err != nil {
			return err
		}
		if exists {
			_ = s.verifyRepo.MarkAsUsed(v.ID)
			return ErrEmailAlreadyInUse
		}
		user.Email = v.Email
	}

	user.EmailVerified = true
	if err := s.userRepo.Update(user); err != nil {
		return err
	}

	// 标记令牌为已使用
	if err := s.verifyRepo.MarkAsUsed(v.ID); err != nil {
		return nil // 非关键错误
	}

	// 使该用户其他令牌失效
	_ = s.verifyRepo.InvalidateUserTokens(user.ID)

	return nil
}
