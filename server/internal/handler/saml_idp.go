package handler

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"

	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
)

type SAMLIdPHandler struct {
	service *service.SAMLIdPService
	appRepo *repository.ApplicationRepository
}

type SAMLIdPConfigRequest struct {
	EntityID          string            `json:"sp_entity_id"`
	ACSURL            string            `json:"acs_url"`
	SLOURL            string            `json:"slo_url"`
	CertificatePEM    string            `json:"certificate_pem"`
	NameIDFormat      string            `json:"name_id_format"`
	AttributeMappings map[string]string `json:"attribute_mappings"`
	Enabled           bool              `json:"enabled"`
}

type SAMLIdPConfigResponse struct {
	ID                    string            `json:"id"`
	AppID                 string            `json:"app_id"`
	EntityID              string            `json:"sp_entity_id"`
	ACSURL                string            `json:"acs_url"`
	SLOURL                string            `json:"slo_url"`
	CertificateConfigured bool              `json:"certificate_configured"`
	NameIDFormat          string            `json:"name_id_format"`
	AttributeMappings     map[string]string `json:"attribute_mappings"`
	Enabled               bool              `json:"enabled"`
	IDPEntityID           string            `json:"idp_entity_id"`
	IDPMetadataURL        string            `json:"idp_metadata_url"`
	IDPSSOURL             string            `json:"idp_sso_url"`
	IDPSLOURL             string            `json:"idp_slo_url"`
}

func NewSAMLIdPHandler(svc *service.SAMLIdPService, appRepo *repository.ApplicationRepository) *SAMLIdPHandler {
	return &SAMLIdPHandler{service: svc, appRepo: appRepo}
}

func (h *SAMLIdPHandler) Metadata(c *gin.Context) {
	idp, err := h.identityProvider(c.Request)
	if err != nil {
		InternalError(c, "Failed to initialize SAML IdP")
		return
	}
	idp.ServeMetadata(c.Writer, c.Request)
}

func (h *SAMLIdPHandler) SSO(c *gin.Context) {
	idp, err := h.identityProvider(c.Request)
	if err != nil {
		InternalError(c, "Failed to initialize SAML IdP")
		return
	}
	idp.ServeSSO(c.Writer, c.Request)
}

/** SLO 处理 SAML Single Logout 请求 (HTTP-Redirect binding) */
func (h *SAMLIdPHandler) SLO(c *gin.Context) {
	samlRequest := c.Query("SAMLRequest")
	if samlRequest == "" {
		samlRequest = c.PostForm("SAMLRequest")
	}
	if samlRequest == "" {
		BadRequest(c, "SAMLRequest parameter required")
		return
	}
	relayState := c.Query("RelayState")
	if relayState == "" {
		relayState = c.PostForm("RelayState")
	}

	respXML, destination, relay, err := h.service.ProcessSLORequest(samlRequest, relayState)
	if err != nil {
		BadRequest(c, "Invalid LogoutRequest")
		return
	}

	encoded := base64.StdEncoding.EncodeToString(respXML)
	redirectURL := destination + "?SAMLResponse=" + url.QueryEscape(encoded)
	if relay != "" {
		redirectURL += "&RelayState=" + url.QueryEscape(relay)
	}
	c.Redirect(http.StatusFound, redirectURL)
}

func (h *SAMLIdPHandler) GetAppConfig(c *gin.Context) {
	appID, ok := parseAppID(c)
	if !ok {
		return
	}
	if _, err := h.appRepo.FindByID(appID); err != nil {
		NotFound(c, "Application not found")
		return
	}
	sp, err := h.service.GetServiceProviderByAppID(appID)
	if errors.Is(err, repository.ErrSAMLIdPServiceProviderNotFound) {
		Success(c, h.emptyResponse(appID))
		return
	}
	if err != nil {
		InternalError(c, "Failed to get SAML IdP config")
		return
	}
	Success(c, h.toResponse(sp))
}

func (h *SAMLIdPHandler) UpdateAppConfig(c *gin.Context) {
	appID, ok := parseAppID(c)
	if !ok {
		return
	}
	if _, err := h.appRepo.FindByID(appID); err != nil {
		NotFound(c, "Application not found")
		return
	}
	var req SAMLIdPConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "Invalid request body")
		return
	}
	sp, err := h.service.UpsertServiceProvider(appID, service.SAMLIdPConfigInput{
		EntityID:          req.EntityID,
		ACSURL:            req.ACSURL,
		SLOURL:            req.SLOURL,
		CertificatePEM:    req.CertificatePEM,
		NameIDFormat:      req.NameIDFormat,
		AttributeMappings: req.AttributeMappings,
		Enabled:           req.Enabled,
	})
	if errors.Is(err, service.ErrSAMLIdPConfigInvalid) {
		BadRequest(c, "Invalid SAML IdP service provider config")
		return
	}
	if err != nil {
		InternalError(c, "Failed to update SAML IdP config")
		return
	}
	Success(c, h.toResponse(sp))
}

func (h *SAMLIdPHandler) DeleteAppConfig(c *gin.Context) {
	appID, ok := parseAppID(c)
	if !ok {
		return
	}
	if err := h.service.DeleteServiceProviderByAppID(appID); err != nil {
		InternalError(c, "Failed to delete SAML IdP config")
		return
	}
	Success(c, gin.H{"deleted": true})
}

func (h *SAMLIdPHandler) identityProvider(r *http.Request) (*saml.IdentityProvider, error) {
	pair, err := h.service.EnsureCertificatePair()
	if err != nil {
		return nil, err
	}
	cert, key, err := service.ParseSAMLIdPCertificatePair(pair)
	if err != nil {
		return nil, err
	}
	metadataURL, err := url.Parse(h.service.MetadataURL())
	if err != nil {
		return nil, err
	}
	ssoURL, err := url.Parse(h.service.SSOURL())
	if err != nil {
		return nil, err
	}
	sloURL, err := url.Parse(h.service.SLOURL())
	if err != nil {
		return nil, err
	}
	return &saml.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		MetadataURL:             *metadataURL,
		SSOURL:                  *ssoURL,
		LogoutURL:               *sloURL,
		ServiceProviderProvider: h.service.ServiceProviderProvider(),
		SessionProvider:         h.service.SessionProvider(),
		SignatureMethod:         dsig.RSASHA256SignatureMethod,
	}, nil
}

func (h *SAMLIdPHandler) toResponse(sp *model.SAMLIdPServiceProvider) SAMLIdPConfigResponse {
	return SAMLIdPConfigResponse{
		ID:                    sp.ID.String(),
		AppID:                 sp.AppID.String(),
		EntityID:              sp.EntityID,
		ACSURL:                sp.ACSURL,
		SLOURL:                sp.SLOURL,
		CertificateConfigured: sp.CertificatePEM != "",
		NameIDFormat:          sp.NameIDFormat,
		AttributeMappings:     sp.GetAttributeMappings(),
		Enabled:               sp.Enabled,
		IDPEntityID:           h.service.MetadataURL(),
		IDPMetadataURL:        h.service.MetadataURL(),
		IDPSSOURL:             h.service.SSOURL(),
		IDPSLOURL:             h.service.SLOURL(),
	}
}

func (h *SAMLIdPHandler) emptyResponse(appID uuid.UUID) SAMLIdPConfigResponse {
	return SAMLIdPConfigResponse{
		AppID:             appID.String(),
		NameIDFormat:      model.SAMLNameIDFormatPersistent,
		AttributeMappings: map[string]string{},
		Enabled:           true,
		IDPEntityID:       h.service.MetadataURL(),
		IDPMetadataURL:    h.service.MetadataURL(),
		IDPSSOURL:         h.service.SSOURL(),
		IDPSLOURL:         h.service.SLOURL(),
	}
}

func parseAppID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		BadRequest(c, "Invalid application ID")
		return uuid.Nil, false
	}
	return id, true
}
