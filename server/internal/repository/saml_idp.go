package repository

import (
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"server/internal/model"
)

var ErrSAMLIdPServiceProviderNotFound = errors.New("saml idp service provider not found")

type SAMLIdPServiceProviderRepository struct {
	db *gorm.DB
}

func NewSAMLIdPServiceProviderRepository(db *gorm.DB) *SAMLIdPServiceProviderRepository {
	return &SAMLIdPServiceProviderRepository{db: db}
}

func (r *SAMLIdPServiceProviderRepository) FindByID(id uuid.UUID) (*model.SAMLIdPServiceProvider, error) {
	var sp model.SAMLIdPServiceProvider
	result := r.db.First(&sp, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrSAMLIdPServiceProviderNotFound
		}
		return nil, result.Error
	}
	return &sp, nil
}

func (r *SAMLIdPServiceProviderRepository) FindByAppID(appID uuid.UUID) (*model.SAMLIdPServiceProvider, error) {
	var sp model.SAMLIdPServiceProvider
	result := r.db.First(&sp, "app_id = ?", appID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrSAMLIdPServiceProviderNotFound
		}
		return nil, result.Error
	}
	return &sp, nil
}

func (r *SAMLIdPServiceProviderRepository) FindEnabledByEntityID(entityID string) (*model.SAMLIdPServiceProvider, error) {
	var sp model.SAMLIdPServiceProvider
	result := r.db.First(&sp, "entity_id = ? AND enabled = ?", entityID, true)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrSAMLIdPServiceProviderNotFound
		}
		return nil, result.Error
	}
	return &sp, nil
}

func (r *SAMLIdPServiceProviderRepository) Create(sp *model.SAMLIdPServiceProvider) error {
	return r.db.Create(sp).Error
}

func (r *SAMLIdPServiceProviderRepository) Update(sp *model.SAMLIdPServiceProvider) error {
	return r.db.Save(sp).Error
}

func (r *SAMLIdPServiceProviderRepository) DeleteByAppID(appID uuid.UUID) error {
	return r.db.Where("app_id = ?", appID).Delete(&model.SAMLIdPServiceProvider{}).Error
}
