package repository

import (
	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * FederationRepository 联邦认证数据仓储
 * 功能：封装联邦提供者、联邦身份关联和受信任应用的全部 CRUD 操作
 */
type FederationRepository struct {
	db *gorm.DB
}

/*
 * NewFederationRepository 创建联邦仓储实例
 * @param db - GORM 数据库连接
 */
func NewFederationRepository(db *gorm.DB) *FederationRepository {
	return &FederationRepository{db: db}
}

/* ========== Provider 提供者操作 ========== */

/* FindAll 查找所有联邦提供者（按名称升序） */
func (r *FederationRepository) FindAll() ([]model.FederatedProvider, error) {
	var providers []model.FederatedProvider
	err := r.db.Order("name ASC").Find(&providers).Error
	return providers, err
}

/* FindAllEnabled 查找所有已启用的联邦提供者 */
func (r *FederationRepository) FindAllEnabled() ([]model.FederatedProvider, error) {
	var providers []model.FederatedProvider
	err := r.db.Where("enabled = ?", true).Order("name ASC").Find(&providers).Error
	return providers, err
}

/* FindByID 根据 UUID 查找提供者 */
func (r *FederationRepository) FindByID(id uuid.UUID) (*model.FederatedProvider, error) {
	var provider model.FederatedProvider
	err := r.db.First(&provider, "id = ?", id).Error
	return &provider, err
}

/* FindBySlug 根据唯一标识 slug 查找提供者 */
func (r *FederationRepository) FindBySlug(slug string) (*model.FederatedProvider, error) {
	var provider model.FederatedProvider
	err := r.db.First(&provider, "slug = ?", slug).Error
	return &provider, err
}

/* CreateProvider 创建新的联邦提供者 */
func (r *FederationRepository) CreateProvider(provider *model.FederatedProvider) error {
	return r.db.Create(provider).Error
}

/* UpdateProvider 更新联邦提供者 */
func (r *FederationRepository) UpdateProvider(provider *model.FederatedProvider) error {
	return r.db.Save(provider).Error
}

/* DeleteProvider 删除联邦提供者 */
func (r *FederationRepository) DeleteProvider(id uuid.UUID) error {
	return r.db.Delete(&model.FederatedProvider{}, "id = ?", id).Error
}

/* ========== Identity 身份关联操作 ========== */

/*
 * FindIdentityByExternalID 根据提供者 ID 和外部用户 ID 查找身份关联
 * @param providerID - 提供者 UUID
 * @param externalID - 外部系统的用户 ID (sub)
 */
func (r *FederationRepository) FindIdentityByExternalID(providerID uuid.UUID, externalID string) (*model.FederatedIdentity, error) {
	var identity model.FederatedIdentity
	err := r.db.First(&identity, "provider_id = ? AND external_id = ?", providerID, externalID).Error
	return &identity, err
}

/*
 * FindIdentitiesByUserID 查找用户的所有联邦身份关联（预加载提供者）
 * @param userID - 用户 UUID
 */
func (r *FederationRepository) FindIdentitiesByUserID(userID uuid.UUID) ([]model.FederatedIdentity, error) {
	var identities []model.FederatedIdentity
	err := r.db.Preload("Provider").Where("user_id = ?", userID).Find(&identities).Error
	return identities, err
}

/* CreateIdentity 创建新的身份关联 */
func (r *FederationRepository) CreateIdentity(identity *model.FederatedIdentity) error {
	return r.db.Create(identity).Error
}

/* UpdateIdentity 更新身份关联 */
func (r *FederationRepository) UpdateIdentity(identity *model.FederatedIdentity) error {
	return r.db.Save(identity).Error
}

/* DeleteIdentity 删除身份关联 */
func (r *FederationRepository) DeleteIdentity(id uuid.UUID) error {
	return r.db.Delete(&model.FederatedIdentity{}, "id = ?", id).Error
}

/* ========== TrustedApp 受信任应用操作 ========== */

/*
 * FindTrustedAppByAPIKey 根据 API Key 查找受信任应用
 * @param apiKey - API 密钥
 */
func (r *FederationRepository) FindTrustedAppByAPIKey(apiKey string) (*model.TrustedApp, error) {
	var app model.TrustedApp
	err := r.db.First(&app, "api_key = ?", apiKey).Error
	return &app, err
}

/* FindAllTrustedApps 查找所有受信任应用（预加载提供者） */
func (r *FederationRepository) FindAllTrustedApps() ([]model.TrustedApp, error) {
	var apps []model.TrustedApp
	err := r.db.Preload("Provider").Order("name ASC").Find(&apps).Error
	return apps, err
}

/* CreateTrustedApp 创建受信任应用 */
func (r *FederationRepository) CreateTrustedApp(app *model.TrustedApp) error {
	return r.db.Create(app).Error
}

/* UpdateTrustedApp 更新受信任应用 */
func (r *FederationRepository) UpdateTrustedApp(app *model.TrustedApp) error {
	return r.db.Save(app).Error
}

/* DeleteTrustedApp 删除受信任应用 */
func (r *FederationRepository) DeleteTrustedApp(id uuid.UUID) error {
	return r.db.Delete(&model.TrustedApp{}, "id = ?", id).Error
}
