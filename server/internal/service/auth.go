package service

import (
	"errors"
	"fmt"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"
	"server/pkg/logger"
	"server/pkg/password"

	"github.com/google/uuid"
)

/* 认证服务层错误定义 */
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrEmailExists        = errors.New("email already exists")
	ErrUsernameExists     = errors.New("username already exists")
	ErrPasswordTooWeak    = errors.New("password does not meet strength requirements")
	ErrAccountLocked      = errors.New("account temporarily locked due to too many failed attempts")
)

/*
 * AuthService 用户认证服务
 * 功能：用户注册、登录、Token 签发与刷新、登出、用户查询
 *       支持 Refresh Token Rotation 安全机制
 */
type AuthService struct {
	userRepo       *repository.UserRepository
	loginLogRepo   *repository.LoginLogRepository
	oauthRepo      *repository.OAuthRepository
	jwtManager     *jwt.Manager
	config         *config.Config
	tokenBlacklist *jwt.Blacklist
}

/*
 * NewAuthService 创建认证服务实例
 * @param userRepo     - 用户数据仓储
 * @param loginLogRepo - 登录日志仓储
 * @param jwtManager   - JWT 管理器
 * @param cfg          - 系统配置
 */
func NewAuthService(userRepo *repository.UserRepository, loginLogRepo *repository.LoginLogRepository, jwtManager *jwt.Manager, cfg *config.Config) *AuthService {
	return &AuthService{
		userRepo:     userRepo,
		loginLogRepo: loginLogRepo,
		jwtManager:   jwtManager,
		config:       cfg,
	}
}

/* SetOAuthRepo 注入 OAuthRepository（启用 Refresh Token Rotation） */
func (s *AuthService) SetOAuthRepo(repo *repository.OAuthRepository) {
	s.oauthRepo = repo
}

/* SetTokenBlacklist 注入 JWT 黑名单（启用 access token 即时吊销） */
func (s *AuthService) SetTokenBlacklist(bl *jwt.Blacklist) {
	s.tokenBlacklist = bl
}

/* GetJWTManager 返回 JWT 管理器（用于 Logout 等场景解析 token） */
func (s *AuthService) GetJWTManager() *jwt.Manager {
	return s.jwtManager
}

/* RegisterInput 用户注册输入参数 */
type RegisterInput struct {
	Email    string
	Username string
	Password string
}

/* LoginInput 用户登录输入参数 */
type LoginInput struct {
	Email     string
	Password  string
	IPAddress string
	UserAgent string
}

/* AuthTokens 认证令牌对（access_token + refresh_token） */
type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

/*
 * Register 创建新用户账号
 * 功能：校验邮箱/用户名唯一性，哈希密码，第一个用户自动成为管理员
 * @param input - 注册参数
 * @return *model.User - 创建后的用户实体
 */
func (s *AuthService) Register(input *RegisterInput) (*model.User, error) {
	/* 校验密码强度（长度、bcrypt 72 字节限制） */
	if err := password.ValidateStrength(input.Password); err != nil {
		return nil, ErrPasswordTooWeak
	}

	// Check if email exists
	exists, err := s.userRepo.ExistsByEmail(input.Email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrEmailExists
	}

	// Check if username exists
	exists, err = s.userRepo.ExistsByUsername(input.Username)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrUsernameExists
	}

	// Hash password
	hashedPassword, err := password.Hash(input.Password)
	if err != nil {
		return nil, err
	}

	// Check if this is the first user (make them admin)
	userCount, err := s.userRepo.Count()
	if err != nil {
		return nil, err
	}

	role := model.RoleUser
	if userCount == 0 {
		role = model.RoleAdmin
	}

	// Create user
	user := &model.User{
		Email:        input.Email,
		Username:     input.Username,
		PasswordHash: hashedPassword,
		Role:         role,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}

	return user, nil
}

/*
 * Login 用户登录认证
 * 功能：校验邮箱密码，记录登录日志，签发 JWT 令牌对
 * @param input - 登录参数（邮箱、密码、IP、UA）
 * @return *model.User   - 用户实体
 * @return *AuthTokens   - JWT 令牌对
 */
/*
 * 账户锁定策略常量
 * MaxFailedLogins: 连续失败次数阈值
 * LockDuration:    锁定持续时间
 */
const (
	MaxFailedLogins = 5
	LockDuration    = 15 * time.Minute
)

func (s *AuthService) Login(input *LoginInput) (*model.User, *AuthTokens, error) {
	// Find user by email
	user, err := s.userRepo.FindByEmail(input.Email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			// Log failed login attempt (user not found)
			if s.loginLogRepo != nil {
				s.loginLogRepo.CreateLoginLog(nil, nil, model.LoginTypeDirect, input.IPAddress, input.UserAgent, input.Email, false, "user not found")
			}
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, err
	}

	/* 用户状态检查：suspended/disabled 用户拒绝登录 */
	if user.Status != "" && user.Status != "active" {
		if s.loginLogRepo != nil {
			s.loginLogRepo.CreateLoginLog(&user.ID, nil, model.LoginTypeDirect, input.IPAddress, input.UserAgent, input.Email, false, "user "+user.Status)
		}
		return nil, nil, ErrInvalidCredentials
	}

	/* 账户锁定检查：连续失败超过阈值后临时锁定 */
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		if s.loginLogRepo != nil {
			s.loginLogRepo.CreateLoginLog(&user.ID, nil, model.LoginTypeDirect, input.IPAddress, input.UserAgent, input.Email, false, "account locked")
		}
		return nil, nil, ErrAccountLocked
	}

	// Verify password
	if !password.Verify(input.Password, user.PasswordHash) {
		/* 递增失败计数，达到阈值时锁定账户 */
		user.FailedLogins++
		if user.FailedLogins >= MaxFailedLogins {
			lockUntil := time.Now().Add(LockDuration)
			user.LockedUntil = &lockUntil
		}
		s.userRepo.Update(user)

		// Log failed login attempt (wrong password)
		if s.loginLogRepo != nil {
			s.loginLogRepo.CreateLoginLog(&user.ID, nil, model.LoginTypeDirect, input.IPAddress, input.UserAgent, input.Email, false, "invalid password")
		}
		return nil, nil, ErrInvalidCredentials
	}

	/* 登录成功：重置失败计数和锁定状态 */
	needsUpdate := user.FailedLogins > 0 || user.LockedUntil != nil
	if user.FailedLogins > 0 || user.LockedUntil != nil {
		user.FailedLogins = 0
		user.LockedUntil = nil
		needsUpdate = true
	}

	/* bcrypt cost 自适应升级：旧哈希使用较低 cost 时透明重哈希 */
	if password.NeedsRehash(user.PasswordHash) {
		if newHash, hashErr := password.Hash(input.Password); hashErr == nil {
			user.PasswordHash = newHash
			needsUpdate = true
			logger.Info("Password rehashed with updated cost", "user_id", user.ID)
		}
	}

	if needsUpdate {
		s.userRepo.Update(user)
	}

	// Log successful login
	if s.loginLogRepo != nil {
		s.loginLogRepo.CreateLoginLog(&user.ID, nil, model.LoginTypeDirect, input.IPAddress, input.UserAgent, input.Email, true, "")
	}

	// Generate tokens
	tokens, err := s.generateTokens(user)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

/*
 * RefreshTokens 使用 refresh token 生成新的 token 对
 * 实现 Token Rotation：每个 refresh token 只能使用一次，
 * 使用后立即失效并颁发新的 refresh token
 */
func (s *AuthService) RefreshTokens(refreshToken string) (*AuthTokens, error) {
	/* 验证 refresh token 且确保类型正确 */
	claims, err := s.jwtManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	/* Token Rotation: 检查 DB 中该 token 是否已被使用/撤销 */
	if s.oauthRepo != nil {
		record, findErr := s.oauthRepo.FindAuthRefreshToken(claims.ID)
		if findErr != nil {
			/* token 不在 DB 中（可能是旧 token 或伪造的） */
			return nil, errors.New("refresh token not recognized")
		}
		if record.Revoked {
			/*
			 * 宽限期机制：Token Rotation 存在竞态条件
			 * 前端可能因 Cookie 更新延迟 / 多标签页并发等原因，在短时间内重复使用同一个旧 token
			 * 如果在 30 秒宽限期内，不触发"撤销全部 token"的核弹操作，只拒绝本次请求
			 * 超过宽限期则视为真正的重放攻击，撤销该用户全部 refresh token
			 */
			const rotationGracePeriod = 30 * time.Second
			if record.RevokedAt != nil && time.Since(*record.RevokedAt) < rotationGracePeriod {
				return nil, errors.New("refresh token already used (grace period)")
			}
			/* 超过宽限期：检测到重放攻击，撤销该用户所有 refresh token */
			if record.UserID != nil {
				_ = s.oauthRepo.RevokeUserAuthRefreshTokens(*record.UserID)
			}
			return nil, errors.New("refresh token already used")
		}
		/* 标记旧 token 已使用 */
		_ = s.oauthRepo.RevokeAuthRefreshToken(claims.ID)
	}

	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		return nil, err
	}

	return s.generateTokens(user)
}

/*
 * LogoutUser 用户登出时撤销该用户所有 Auth Refresh Token
 * 功能：确保服务端彻底失效，即使 Cookie 被截获也无法再刷新
 * @param userID - 用户 UUID
 */
func (s *AuthService) LogoutUser(userID uuid.UUID) {
	if s.oauthRepo != nil {
		_ = s.oauthRepo.RevokeUserAuthRefreshTokens(userID)
	}
	/* 吊销该用户所有已签发的 access token（基于用户级别时间戳） */
	if s.tokenBlacklist != nil {
		_ = s.tokenBlacklist.RevokeAllForUser(userID.String(), s.config.JWT.AccessTokenTTL)
	}
}

/*
 * GetUserByID 根据 UUID 获取用户
 * @param id - 用户 UUID
 * @return *model.User - 用户实体
 */
func (s *AuthService) GetUserByID(id uuid.UUID) (*model.User, error) {
	return s.userRepo.FindByID(id)
}

/*
 * generateTokens 为用户生成 JWT 令牌对（access + refresh）
 * 功能：签发 access_token 和 refresh_token，并将 refresh_token 的 JTI 存入 DB 用于 Rotation 追踪
 * @param user - 用户实体
 * @return *AuthTokens - 令牌对
 */
func (s *AuthService) generateTokens(user *model.User) (*AuthTokens, error) {
	accessToken, err := s.jwtManager.GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeAccess,
		s.config.JWT.AccessTokenTTL,
	)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.jwtManager.GenerateToken(
		user.ID,
		user.Email,
		user.Username,
		string(user.Role),
		jwt.TokenTypeRefresh,
		s.config.JWT.RefreshTokenTTL,
	)
	if err != nil {
		return nil, err
	}

	/* 将 refresh token 的 JTI 存入 DB，用于 Token Rotation 追踪 */
	if s.oauthRepo != nil {
		if refreshClaims, parseErr := s.jwtManager.ValidateRefreshToken(refreshToken); parseErr == nil {
			if storeErr := s.oauthRepo.StoreAuthRefreshToken(
				refreshClaims.ID,
				user.ID,
				refreshClaims.ExpiresAt.Time,
			); storeErr != nil {
				logger.Error("Failed to store auth refresh token",
					"user_id", user.ID,
					"error", storeErr,
				)
				/* 存储失败会导致下次刷新时 token “不被识别”，必须返回错误 */
				return nil, fmt.Errorf("failed to persist refresh token: %w", storeErr)
			}
		}
	}

	return &AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
	}, nil
}

/*
 * GetUserByEmail 根据邮箱获取用户
 * @param email - 用户邮箱
 */
func (s *AuthService) GetUserByEmail(email string) (*model.User, error) {
	return s.userRepo.FindByEmail(email)
}

/*
 * CreateUser 创建新用户（无密码校验，用于社交登录等场景）
 * 功能：校验邮箱/用户名唯一性后直接创建
 * @param user - 用户实体
 */
func (s *AuthService) CreateUser(user *model.User) error {
	// Check if email exists
	exists, err := s.userRepo.ExistsByEmail(user.Email)
	if err != nil {
		return err
	}
	if exists {
		return ErrEmailExists
	}

	// Check if username exists
	exists, err = s.userRepo.ExistsByUsername(user.Username)
	if err != nil {
		return err
	}
	if exists {
		return ErrUsernameExists
	}

	return s.userRepo.Create(user)
}

/*
 * ChangePassword 修改用户密码
 * 功能：验证旧密码后设置新密码（社交登录用户无旧密码时允许直接设置）
 * @param userID      - 用户 UUID
 * @param oldPassword - 旧密码
 * @param newPassword - 新密码
 */
func (s *AuthService) ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	/* 验证旧密码是否正确（社交登录用户可能没有密码，允许直接设置） */
	if user.PasswordHash != "" {
		if !password.Verify(oldPassword, user.PasswordHash) {
			return ErrInvalidCredentials
		}
	}

	/* 校验新密码强度 */
	if err := password.ValidateStrength(newPassword); err != nil {
		return ErrPasswordTooWeak
	}

	/* 生成新密码哈希 */
	hashedPassword, err := password.Hash(newPassword)
	if err != nil {
		return err
	}

	user.PasswordHash = hashedPassword
	if err := s.userRepo.Update(user); err != nil {
		return err
	}

	/* 密码修改后撤销该用户所有 auth refresh token，强制其他会话重新登录 */
	if s.oauthRepo != nil {
		_ = s.oauthRepo.RevokeUserAuthRefreshTokens(userID)
	}
	/* 同时吊销所有已签发的 access token（基于用户级别时间戳） */
	if s.tokenBlacklist != nil {
		_ = s.tokenBlacklist.RevokeAllForUser(userID.String(), s.config.JWT.AccessTokenTTL)
	}
	return nil
}

/*
 * DeleteAccount 用户自助删除账号 (GDPR 合规)
 * 功能：验证密码后永久删除用户数据，撤销所有 token 和授权
 * @param userID   - 用户 UUID
 * @param password - 当前密码（社交登录用户可为空）
 */
func (s *AuthService) DeleteAccount(userID uuid.UUID, pwd string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	/* 密码校验：有密码的用户必须验证（社交登录用户无密码可跳过） */
	if user.PasswordHash != "" {
		if pwd == "" {
			return ErrInvalidCredentials
		}
		if !password.Verify(pwd, user.PasswordHash) {
			return ErrInvalidCredentials
		}
	}

	/* 撤销所有 refresh token */
	if s.oauthRepo != nil {
		_ = s.oauthRepo.RevokeUserAuthRefreshTokens(userID)
	}

	/* 吊销所有 access token（JWT 黑名单） */
	if s.tokenBlacklist != nil {
		_ = s.tokenBlacklist.RevokeAllForUser(userID.String(), s.config.JWT.AccessTokenTTL)
	}

	/* 永久删除用户记录 */
	return s.userRepo.Delete(userID)
}

/*
 * UpdateUser 更新用户信息
 * @param user - 包含更新字段的用户实体
 */
func (s *AuthService) UpdateUser(user *model.User) error {
	return s.userRepo.Update(user)
}
