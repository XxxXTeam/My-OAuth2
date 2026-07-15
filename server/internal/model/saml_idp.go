package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	SAMLNameIDFormatUnspecified  = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	SAMLNameIDFormatEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	SAMLNameIDFormatTransient    = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	SAMLNameIDFormatPersistent   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

type SAMLIdPServiceProvider struct {
	ID                uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	AppID             uuid.UUID `gorm:"type:uuid;not null;uniqueIndex" json:"app_id"`
	EntityID          string    `gorm:"size:500;not null;uniqueIndex" json:"sp_entity_id"`
	ACSURL            string    `gorm:"size:1000;not null" json:"acs_url"`
	SLOURL            string    `gorm:"size:1000" json:"slo_url"`
	CertificatePEM    string    `gorm:"type:text" json:"-"`
	NameIDFormat      string    `gorm:"size:255;not null" json:"name_id_format"`
	AttributeMappings string    `gorm:"type:text" json:"-"`
	Enabled           bool      `gorm:"default:true" json:"enabled"`
	CreatedAt         time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt         time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	App *Application `gorm:"foreignKey:AppID" json:"app,omitempty"`
}

func (sp *SAMLIdPServiceProvider) BeforeCreate(_ *gorm.DB) error {
	if sp.ID == uuid.Nil {
		sp.ID = uuid.New()
	}
	if sp.NameIDFormat == "" {
		sp.NameIDFormat = SAMLNameIDFormatPersistent
	}
	return nil
}

func (sp *SAMLIdPServiceProvider) TableName() string {
	return "saml_idp_service_providers"
}

func (sp *SAMLIdPServiceProvider) GetAttributeMappings() map[string]string {
	mappings := map[string]string{}
	if sp.AttributeMappings != "" {
		json.Unmarshal([]byte(sp.AttributeMappings), &mappings)
	}
	return mappings
}

func (sp *SAMLIdPServiceProvider) SetAttributeMappings(mappings map[string]string) {
	if mappings == nil {
		mappings = map[string]string{}
	}
	data, _ := json.Marshal(mappings)
	sp.AttributeMappings = string(data)
}

func IsSupportedSAMLNameIDFormat(format string) bool {
	switch format {
	case SAMLNameIDFormatUnspecified, SAMLNameIDFormatEmailAddress, SAMLNameIDFormatTransient, SAMLNameIDFormatPersistent:
		return true
	default:
		return false
	}
}
