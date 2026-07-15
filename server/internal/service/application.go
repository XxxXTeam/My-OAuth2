/*
 * Package service 业务逻辑层
 * 功能：封装所有业务规则和流程编排，调用 repository 层完成数据操作
 */
package service

import (
	"errors"

	"server/internal/model"
	"server/internal/repository"

	"github.com/google/uuid"
)

/* 应用服务层错误定义 */
var (
	ErrAppNotFound   = errors.New("application not found")
	ErrNotAppOwner   = errors.New("not the application owner")
	ErrAppNameExists = errors.New("application name already exists")
)

/*
 * ApplicationService 应用管理服务
 * 功能：OAuth2 应用的创建、更新、删除、密钥重置和统计查询
 */
type ApplicationService struct {
	appRepo      *repository.ApplicationRepository
	oauthRepo    *repository.OAuthRepository
	webhookRepo  *repository.WebhookRepository
	userAuthRepo *repository.UserAuthorizationRepository
}

/*
 * NewApplicationService 创建应用管理服务实例
 * @param appRepo - 应用数据仓储
 */
func NewApplicationService(appRepo *repository.ApplicationRepository) *ApplicationService {
	return &ApplicationService{appRepo: appRepo}
}

/* SetCleanupRepos 注入应用删除所需的级联清理仓储 */
func (s *ApplicationService) SetCleanupRepos(oauthRepo *repository.OAuthRepository, webhookRepo *repository.WebhookRepository, userAuthRepo *repository.UserAuthorizationRepository) {
	s.oauthRepo = oauthRepo
	s.webhookRepo = webhookRepo
	s.userAuthRepo = userAuthRepo
}

/* CreateAppInput 创建应用的输入参数 */
type CreateAppInput struct {
	Name                    string
	Description             string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	Scopes                  []string
	AllowedScopes           []string
	GrantTypes              []string
	AppType                 string
	TokenEndpointAuthMethod string
	UserID                  uuid.UUID
}

/*
 * CreateApp 创建新的 OAuth2 应用
 * 功能：自动生成 client_id/secret，默认 grant_type 为 authorization_code + refresh_token
 * @param input - 创建参数
 * @return *model.Application - 创建后的应用实体
 */
func (s *ApplicationService) CreateApp(input *CreateAppInput) (*model.Application, error) {
	app := &model.Application{
		Name:                    input.Name,
		Description:             input.Description,
		UserID:                  input.UserID,
		AppType:                 model.AppTypeConfidential,
		TokenEndpointAuthMethod: model.AuthMethodClientSecretBasic,
	}
	if input.AppType != "" {
		app.AppType = model.ApplicationType(input.AppType)
	}
	if input.TokenEndpointAuthMethod != "" {
		app.TokenEndpointAuthMethod = model.TokenEndpointAuthMethod(input.TokenEndpointAuthMethod)
	}
	app.SetRedirectURIs(input.RedirectURIs)
	if len(input.PostLogoutRedirectURIs) > 0 {
		app.SetPostLogoutRedirectURIs(input.PostLogoutRedirectURIs)
	}
	scopes := input.Scopes
	if len(scopes) == 0 {
		scopes = model.DefaultUserAuthorizationScopes()
	}
	app.SetScopes(scopes)

	// Set grant types (default to authorization_code and refresh_token if not specified)
	if len(input.GrantTypes) > 0 {
		app.SetGrantTypes(input.GrantTypes)
	} else {
		app.SetGrantTypes([]string{"authorization_code", "refresh_token"})
	}
	if len(input.AllowedScopes) > 0 {
		app.SetAllowedScopes(input.AllowedScopes)
	} else {
		for _, gt := range app.GetGrantTypes() {
			if gt == "client_credentials" {
				app.SetAllowedScopes(model.DefaultMachineScopes())
				break
			}
		}
	}

	if err := s.appRepo.Create(app); err != nil {
		return nil, err
	}

	return app, nil
}

/*
 * GetApp 根据 UUID 获取应用
 * @param id - 应用 UUID
 */
func (s *ApplicationService) GetApp(id uuid.UUID) (*model.Application, error) {
	return s.appRepo.FindByID(id)
}

/*
 * GetAppByClientID 根据 client_id 获取应用
 * @param clientID - OAuth2 客户端 ID
 */
func (s *ApplicationService) GetAppByClientID(clientID string) (*model.Application, error) {
	return s.appRepo.FindByClientID(clientID)
}

/*
 * GetUserApps 获取用户拥有的所有应用
 * @param userID - 用户 UUID
 */
func (s *ApplicationService) GetUserApps(userID uuid.UUID) ([]model.Application, error) {
	return s.appRepo.FindByUserID(userID)
}

/* UpdateAppInput 更新应用的输入参数 */
type UpdateAppInput struct {
	ID                      uuid.UUID
	Name                    string
	Description             string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	Scopes                  []string
	AllowedScopes           []string
	GrantTypes              []string
	AppType                 string
	TokenEndpointAuthMethod string
	UserID                  uuid.UUID // For ownership verification
}

/*
 * UpdateApp 更新应用信息
 * 功能：校验所有权后更新应用名称、描述、回调地址、scope 和 grant_type
 * @param input - 更新参数（包含 UserID 用于所有权校验）
 * @return *model.Application - 更新后的应用实体
 */
func (s *ApplicationService) UpdateApp(input *UpdateAppInput) (*model.Application, error) {
	app, err := s.appRepo.FindByID(input.ID)
	if err != nil {
		return nil, ErrAppNotFound
	}

	// Verify ownership
	if app.UserID != input.UserID {
		return nil, ErrNotAppOwner
	}

	// Update fields
	if input.Name != "" {
		app.Name = input.Name
	}
	if input.Description != "" {
		app.Description = input.Description
	}
	if len(input.RedirectURIs) > 0 {
		app.SetRedirectURIs(input.RedirectURIs)
	}
	if input.PostLogoutRedirectURIs != nil {
		app.SetPostLogoutRedirectURIs(input.PostLogoutRedirectURIs)
	}
	if len(input.Scopes) > 0 {
		app.SetScopes(input.Scopes)
	}
	if len(input.AllowedScopes) > 0 {
		app.SetAllowedScopes(input.AllowedScopes)
	}
	if len(input.GrantTypes) > 0 {
		app.SetGrantTypes(input.GrantTypes)
		for _, gt := range input.GrantTypes {
			if gt == "client_credentials" && len(app.GetAllowedScopes()) == 0 {
				app.SetAllowedScopes(model.DefaultMachineScopes())
				break
			}
		}
	}
	if input.AppType != "" {
		app.AppType = model.ApplicationType(input.AppType)
	}
	if input.TokenEndpointAuthMethod != "" {
		app.TokenEndpointAuthMethod = model.TokenEndpointAuthMethod(input.TokenEndpointAuthMethod)
	}

	if err := s.appRepo.Update(app); err != nil {
		return nil, err
	}

	return app, nil
}

/*
 * DeleteApp 删除应用
 * 功能：校验所有权后删除应用，并级联清理授权记录、OAuth 凭证和 Webhook
 * @param id     - 应用 UUID
 * @param userID - 当前用户 UUID（用于所有权校验）
 */
func (s *ApplicationService) DeleteApp(id, userID uuid.UUID) error {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return ErrAppNotFound
	}

	// Verify ownership
	if app.UserID != userID {
		return ErrNotAppOwner
	}

	if s.userAuthRepo != nil {
		if _, err := s.userAuthRepo.DeleteByApp(app.ID); err != nil {
			return err
		}
	}
	if s.webhookRepo != nil {
		if err := s.webhookRepo.DeleteByAppID(app.ID); err != nil {
			return err
		}
	}
	if s.oauthRepo != nil {
		if err := s.oauthRepo.DeleteTokensByClientID(app.ClientID); err != nil {
			return err
		}
	}

	return s.appRepo.Delete(id)
}

/*
 * ResetSecret 重置应用的客户端密钥
 * 功能：校验所有权后生成新的 client_secret
 * @param id     - 应用 UUID
 * @param userID - 当前用户 UUID
 * @return string - 新生成的客户端密钥
 */
func (s *ApplicationService) ResetSecret(id, userID uuid.UUID) (*model.Application, string, error) {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return nil, "", ErrAppNotFound
	}

	// Verify ownership
	if app.UserID != userID {
		return nil, "", ErrNotAppOwner
	}

	// Generate new secret using repository method
	newSecret, err := s.appRepo.ResetSecret(id)
	if err != nil {
		return nil, "", err
	}

	return app, newSecret, nil
}

/* AppStats 应用统计数据结构 */
type AppStats struct {
	TotalAuthorizations int64 `json:"total_authorizations"`
	ActiveTokens        int64 `json:"active_tokens"`
	TotalUsers          int64 `json:"total_users"`
	Last24hTokens       int64 `json:"last_24h_tokens"`
}

/*
 * GetAppStats 获取应用统计数据
 * 功能：校验所有权后返回授权码总数、活跃令牌数、独立用户数和近 24h 令牌签发数
 * @param id     - 应用 UUID
 * @param userID - 当前用户 UUID
 * @return *AppStats - 统计数据
 */
func (s *ApplicationService) GetAppStats(id, userID uuid.UUID) (*AppStats, error) {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return nil, ErrAppNotFound
	}

	// Verify ownership
	if app.UserID != userID {
		return nil, ErrNotAppOwner
	}

	stats, err := s.appRepo.GetStats(id)
	if err != nil {
		return nil, err
	}

	return &AppStats{
		TotalAuthorizations: stats.TotalAuthorizations,
		ActiveTokens:        stats.ActiveTokens,
		TotalUsers:          stats.TotalUsers,
		Last24hTokens:       stats.Last24hTokens,
	}, nil
}

/*
 * ListAuthorizedUsers 分页查询应用的授权用户（含用户资料预加载）
 */
func (s *ApplicationService) ListAuthorizedUsers(id, ownerID uuid.UUID, page, limit int) ([]model.UserAuthorization, int64, error) {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return nil, 0, ErrAppNotFound
	}
	if app.UserID != ownerID {
		return nil, 0, ErrNotAppOwner
	}
	if s.userAuthRepo == nil {
		return []model.UserAuthorization{}, 0, nil
	}
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit
	return s.userAuthRepo.FindByApp(id, offset, limit)
}
