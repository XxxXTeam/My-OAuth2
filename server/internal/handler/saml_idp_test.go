package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"
)

type samlIDPHandlerFixture struct {
	router    *gin.Engine
	handler   *SAMLIdPHandler
	service   *service.SAMLIdPService
	spRepo    *repository.SAMLIdPServiceProviderRepository
	oauthRepo *repository.OAuthRepository
	manager   *jwt.Manager
	user      *model.User
	app       *model.Application
}

func setupSAMLIDPHandlerFixture(t *testing.T) samlIDPHandlerFixture {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.SystemConfig{}, &model.User{}, &model.Application{}, &model.AccessToken{}, &model.RefreshToken{}, &model.SAMLIdPServiceProvider{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	appRepo := repository.NewApplicationRepository(db)
	spRepo := repository.NewSAMLIdPServiceProviderRepository(db)
	configRepo := repository.NewConfigRepository(db)
	userRepo := repository.NewUserRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	manager := jwt.NewManager("saml-idp-test-secret-with-enough-length", "saml-idp-test")

	user := &model.User{
		Email:        "saml-idp-handler@example.com",
		Username:     "samlidphandler",
		PasswordHash: "hashed-password",
		Status:       "active",
		Role:         model.RoleUser,
		GivenName:    "SAML",
		FamilyName:   "User",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:     "saml-idp-client",
		ClientSecret: "saml-idp-secret",
		Name:         "SAML IdP Client",
		UserID:       user.ID,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	svc := service.NewSAMLIdPService(spRepo, configRepo, userRepo, oauthRepo, manager, nil, "http://localhost:8080", "http://localhost:3000")
	handler := NewSAMLIdPHandler(svc, appRepo)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/saml/idp/metadata", handler.Metadata)
	router.GET("/saml/idp/sso", handler.SSO)

	return samlIDPHandlerFixture{
		router:    router,
		handler:   handler,
		service:   svc,
		spRepo:    spRepo,
		oauthRepo: oauthRepo,
		manager:   manager,
		user:      user,
		app:       app,
	}
}

func createSAMLIDPServiceProvider(t *testing.T, f samlIDPHandlerFixture) *model.SAMLIdPServiceProvider {
	t.Helper()

	sp := &model.SAMLIdPServiceProvider{
		AppID:        f.app.ID,
		EntityID:     "https://sp.example.com/saml/metadata",
		ACSURL:       "https://sp.example.com/saml/acs",
		NameIDFormat: model.SAMLNameIDFormatEmailAddress,
		Enabled:      true,
	}
	sp.SetAttributeMappings(map[string]string{
		"email":       "mail",
		"displayName": "display_name",
	})
	if err := f.spRepo.Create(sp); err != nil {
		t.Fatalf("create saml idp sp: %v", err)
	}
	return sp
}

func TestSAMLIdPHandler_MetadataReturnsIdentityProviderMetadata(t *testing.T) {
	f := setupSAMLIDPHandlerFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/saml/idp/metadata", nil)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"EntityDescriptor",
		"http://localhost:8080/saml/idp/metadata",
		"http://localhost:8080/saml/idp/sso",
		"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metadata body missing %q: %s", want, body)
		}
	}
}

func TestSAMLIdPHandler_IdentityProviderUsesRSASHA256(t *testing.T) {
	f := setupSAMLIDPHandlerFixture(t)

	idp, err := f.handler.identityProvider(httptest.NewRequest(http.MethodGet, "/saml/idp/metadata", nil))
	if err != nil {
		t.Fatalf("identity provider: %v", err)
	}
	if idp.SignatureMethod != dsig.RSASHA256SignatureMethod {
		t.Fatalf("SignatureMethod=%q want %q", idp.SignatureMethod, dsig.RSASHA256SignatureMethod)
	}
}

func TestSAMLIdPServiceProviderProvider_ReturnsMetadataForConfiguredSP(t *testing.T) {
	f := setupSAMLIDPHandlerFixture(t)
	sp := createSAMLIDPServiceProvider(t, f)

	metadata, err := f.service.ServiceProviderProvider().GetServiceProvider(nil, sp.EntityID)
	if err != nil {
		t.Fatalf("get service provider: %v", err)
	}
	if metadata.EntityID != sp.EntityID {
		t.Fatalf("EntityID=%q want %q", metadata.EntityID, sp.EntityID)
	}
	if len(metadata.SPSSODescriptors) != 1 {
		t.Fatalf("SPSSODescriptors len=%d want 1", len(metadata.SPSSODescriptors))
	}
	acs := metadata.SPSSODescriptors[0].AssertionConsumerServices
	if len(acs) != 1 {
		t.Fatalf("AssertionConsumerServices len=%d want 1", len(acs))
	}
	if acs[0].Binding != saml.HTTPPostBinding || acs[0].Location != sp.ACSURL {
		t.Fatalf("ACS binding=%q location=%q want POST %q", acs[0].Binding, acs[0].Location, sp.ACSURL)
	}
}

func TestSAMLIdPServiceProviderProvider_RejectsUnknownSP(t *testing.T) {
	f := setupSAMLIDPHandlerFixture(t)

	_, err := f.service.ServiceProviderProvider().GetServiceProvider(nil, "https://unknown.example.com/saml/metadata")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err=%v want os.ErrNotExist", err)
	}
}

func TestSAMLIdPSessionProvider_RedirectsAnonymousUserToLogin(t *testing.T) {
	f := setupSAMLIDPHandlerFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/saml/idp/sso?SAMLRequest=test-request&RelayState=test-state", nil)
	rec := httptest.NewRecorder()
	session := f.service.SessionProvider().GetSession(rec, req, nil)

	if session != nil {
		t.Fatalf("session=%v want nil", session)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusFound)
	}
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location=%q: %v", location, err)
	}
	if parsed.Scheme != "http" || parsed.Host != "localhost:3000" || parsed.Path != "/login" {
		t.Fatalf("Location=%q want frontend login", location)
	}
	if got := parsed.Query().Get("return_to"); got != "/saml/idp/sso?SAMLRequest=test-request&RelayState=test-state" {
		t.Fatalf("return_to=%q want original request URI", got)
	}
}

func TestSAMLIdPSessionProvider_BuildsSessionFromAccessTokenCookie(t *testing.T) {
	f := setupSAMLIDPHandlerFixture(t)
	sp := createSAMLIDPServiceProvider(t, f)
	accessToken, err := f.manager.GenerateClientTokenWithScope(f.user.ID, f.user.Email, f.user.Username, string(f.user.Role), f.app.ClientID, "openid profile email", jwt.TokenTypeAccess, time.Hour)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	storedToken := &model.AccessToken{
		Token:     accessToken,
		ClientID:  f.app.ClientID,
		UserID:    &f.user.ID,
		Scope:     "openid profile email",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := f.oauthRepo.CreateAccessToken(storedToken); err != nil {
		t.Fatalf("create access token: %v", err)
	}

	metadata, err := f.service.ServiceProviderMetadata(sp)
	if err != nil {
		t.Fatalf("service provider metadata: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/saml/idp/sso", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	rec := httptest.NewRecorder()
	session := f.service.SessionProvider().GetSession(rec, req, &saml.IdpAuthnRequest{ServiceProviderMetadata: metadata})

	if session == nil {
		t.Fatal("session is nil")
	}
	if session.NameID != f.user.Email {
		t.Fatalf("NameID=%q want %q", session.NameID, f.user.Email)
	}
	if session.NameIDFormat != model.SAMLNameIDFormatEmailAddress {
		t.Fatalf("NameIDFormat=%q want %q", session.NameIDFormat, model.SAMLNameIDFormatEmailAddress)
	}
	if session.UserCommonName != "SAML User" {
		t.Fatalf("UserCommonName=%q want SAML User", session.UserCommonName)
	}
	if !samlIDPSessionHasAttribute(session.CustomAttributes, "mail", f.user.Email) {
		t.Fatalf("CustomAttributes missing mapped mail=%q: %#v", f.user.Email, session.CustomAttributes)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want default recorder status %d", rec.Code, http.StatusOK)
	}
}

func samlIDPSessionHasAttribute(attributes []saml.Attribute, name string, value string) bool {
	for _, attribute := range attributes {
		if attribute.Name != name {
			continue
		}
		for _, attributeValue := range attribute.Values {
			if attributeValue.Value == value {
				return true
			}
		}
	}
	return false
}

func TestSAMLIdPHandler_EmptyConfigResponseIncludesProviderEndpoints(t *testing.T) {
	f := setupSAMLIDPHandlerFixture(t)

	response := f.handler.emptyResponse(uuid.New())
	if response.IDPEntityID != "http://localhost:8080/saml/idp/metadata" {
		t.Fatalf("IDPEntityID=%q want metadata URL", response.IDPEntityID)
	}
	if response.IDPMetadataURL != "http://localhost:8080/saml/idp/metadata" {
		t.Fatalf("IDPMetadataURL=%q want metadata URL", response.IDPMetadataURL)
	}
	if response.IDPSSOURL != "http://localhost:8080/saml/idp/sso" {
		t.Fatalf("IDPSSOURL=%q want SSO URL", response.IDPSSOURL)
	}
}
