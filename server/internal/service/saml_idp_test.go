package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"
)

type samlIDPServiceFixture struct {
	service    *SAMLIdPService
	spRepo     *repository.SAMLIdPServiceProviderRepository
	configRepo *repository.ConfigRepository
	userRepo   *repository.UserRepository
	oauthRepo  *repository.OAuthRepository
	manager    *jwt.Manager
	user       *model.User
	app        *model.Application
}

func setupSAMLIdPServiceFixture(t *testing.T) samlIDPServiceFixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(
		&model.SystemConfig{},
		&model.User{},
		&model.Application{},
		&model.AccessToken{},
		&model.RefreshToken{},
		&model.SAMLIdPServiceProvider{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	spRepo := repository.NewSAMLIdPServiceProviderRepository(db)
	configRepo := repository.NewConfigRepository(db)
	userRepo := repository.NewUserRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	manager := jwt.NewManager("saml-idp-test-secret-32chars-ok!", "test-issuer")
	blacklist := jwt.NewBlacklist(nil)

	user := &model.User{
		Email:        "saml-svc-test@example.com",
		Username:     "samlsvctest",
		PasswordHash: "hashed",
		Status:       "active",
		Role:         model.RoleUser,
		GivenName:    "Test",
		FamilyName:   "User",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:     "saml-svc-client",
		ClientSecret: "saml-svc-secret",
		Name:         "SAML SVC App",
		UserID:       user.ID,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	svc := NewSAMLIdPService(spRepo, configRepo, userRepo, oauthRepo, manager, blacklist, "http://localhost:8080", "http://localhost:3000")

	return samlIDPServiceFixture{
		service:    svc,
		spRepo:     spRepo,
		configRepo: configRepo,
		userRepo:   userRepo,
		oauthRepo:  oauthRepo,
		manager:    manager,
		user:       user,
		app:        app,
	}
}

func TestUpsertServiceProvider_RejectsEmptyEntityID(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)
	_, err := f.service.UpsertServiceProvider(f.app.ID, SAMLIdPConfigInput{
		EntityID: "",
		ACSURL:   "https://sp.example.com/acs",
		Enabled:  true,
	})
	if err != ErrSAMLIdPConfigInvalid {
		t.Fatalf("err=%v want ErrSAMLIdPConfigInvalid", err)
	}
}

func TestUpsertServiceProvider_RejectsEmptyACSURL(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)
	_, err := f.service.UpsertServiceProvider(f.app.ID, SAMLIdPConfigInput{
		EntityID: "https://sp.example.com/metadata",
		ACSURL:   "",
		Enabled:  true,
	})
	if err != ErrSAMLIdPConfigInvalid {
		t.Fatalf("err=%v want ErrSAMLIdPConfigInvalid", err)
	}
}

func TestUpsertServiceProvider_RejectsInvalidACSURL(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)
	cases := []struct {
		name   string
		acsURL string
	}{
		{"not a url", "not-a-url"},
		{"ftp scheme", "ftp://sp.example.com/acs"},
		{"no scheme", "sp.example.com/acs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.service.UpsertServiceProvider(f.app.ID, SAMLIdPConfigInput{
				EntityID: "https://sp.example.com/metadata",
				ACSURL:   tc.acsURL,
				Enabled:  true,
			})
			if err != ErrSAMLIdPConfigInvalid {
				t.Fatalf("ACSURL=%q err=%v want ErrSAMLIdPConfigInvalid", tc.acsURL, err)
			}
		})
	}
}

func TestUpsertServiceProvider_RejectsUnsupportedNameIDFormat(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)
	_, err := f.service.UpsertServiceProvider(f.app.ID, SAMLIdPConfigInput{
		EntityID:    "https://sp.example.com/metadata",
		ACSURL:      "https://sp.example.com/acs",
		NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:INVALID",
		Enabled:     true,
	})
	if err != ErrSAMLIdPConfigInvalid {
		t.Fatalf("err=%v want ErrSAMLIdPConfigInvalid", err)
	}
}

func TestUpsertServiceProvider_CreateThenUpdate(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)
	input := SAMLIdPConfigInput{
		EntityID:    "https://sp.example.com/metadata",
		ACSURL:      "https://sp.example.com/acs",
		NameIDFormat: model.SAMLNameIDFormatEmailAddress,
		Enabled:     true,
	}
	sp1, err := f.service.UpsertServiceProvider(f.app.ID, input)
	if err != nil {
		t.Fatalf("create err=%v", err)
	}
	if sp1.ID == uuid.Nil {
		t.Fatal("created sp should have non-nil ID")
	}

	input.ACSURL = "https://sp.example.com/acs-v2"
	sp2, err := f.service.UpsertServiceProvider(f.app.ID, input)
	if err != nil {
		t.Fatalf("update err=%v", err)
	}
	if sp2.ID != sp1.ID {
		t.Fatalf("update should reuse same record: got %v want %v", sp2.ID, sp1.ID)
	}
	if sp2.ACSURL != "https://sp.example.com/acs-v2" {
		t.Fatalf("ACSURL not updated: got %q", sp2.ACSURL)
	}
}

func TestUpsertServiceProvider_DefaultsToPeristentNameIDFormat(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)
	sp, err := f.service.UpsertServiceProvider(f.app.ID, SAMLIdPConfigInput{
		EntityID: "https://sp.example.com/metadata",
		ACSURL:   "https://sp.example.com/acs",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if sp.NameIDFormat != model.SAMLNameIDFormatPersistent {
		t.Fatalf("NameIDFormat=%q want %q", sp.NameIDFormat, model.SAMLNameIDFormatPersistent)
	}
}

func TestEnsureCertificatePair_Idempotent(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)
	pair1, err := f.service.EnsureCertificatePair()
	if err != nil {
		t.Fatalf("first call err=%v", err)
	}
	if pair1.CertificatePEM == "" || pair1.PrivateKeyPEM == "" {
		t.Fatal("first call should generate cert+key")
	}

	pair2, err := f.service.EnsureCertificatePair()
	if err != nil {
		t.Fatalf("second call err=%v", err)
	}
	if pair2.CertificatePEM != pair1.CertificatePEM {
		t.Fatal("second call should return same certificate")
	}
	if pair2.PrivateKeyPEM != pair1.PrivateKeyPEM {
		t.Fatal("second call should return same private key")
	}
}

func TestUserFromRequest_RejectsMissingCookie(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/saml/idp/sso", nil)
	_, _, ok := f.service.userFromRequest(req)
	if ok {
		t.Fatal("should reject request without cookie")
	}
}

func TestUserFromRequest_RejectsInvalidJWT(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/saml/idp/sso", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "invalid-jwt-token"})
	_, _, ok := f.service.userFromRequest(req)
	if ok {
		t.Fatal("should reject invalid JWT")
	}
}

func TestUserFromRequest_RejectsInactiveUser(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)

	f.user.Status = "suspended"
	f.userRepo.Update(f.user)

	token, _ := f.manager.GenerateClientTokenWithScope(
		f.user.ID, f.user.Email, f.user.Username, string(f.user.Role),
		f.app.ClientID, "openid", jwt.TokenTypeAccess, time.Hour,
	)
	storedToken := &model.AccessToken{
		Token:     token,
		ClientID:  f.app.ClientID,
		UserID:    &f.user.ID,
		Scope:     "openid",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	f.oauthRepo.CreateAccessToken(storedToken)

	req := httptest.NewRequest(http.MethodGet, "/saml/idp/sso", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	_, _, ok := f.service.userFromRequest(req)
	if ok {
		t.Fatal("should reject inactive user")
	}
}

func TestUserFromRequest_RejectsMismatchedTokenBinding(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)

	token, _ := f.manager.GenerateClientTokenWithScope(
		f.user.ID, f.user.Email, f.user.Username, string(f.user.Role),
		f.app.ClientID, "openid", jwt.TokenTypeAccess, time.Hour,
	)
	otherUserID := uuid.New()
	storedToken := &model.AccessToken{
		Token:     token,
		ClientID:  f.app.ClientID,
		UserID:    &otherUserID,
		Scope:     "openid",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	f.oauthRepo.CreateAccessToken(storedToken)

	req := httptest.NewRequest(http.MethodGet, "/saml/idp/sso", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	_, _, ok := f.service.userFromRequest(req)
	if ok {
		t.Fatal("should reject token with mismatched userID binding")
	}
}

func TestUserFromRequest_AcceptsValidToken(t *testing.T) {
	f := setupSAMLIdPServiceFixture(t)

	token, _ := f.manager.GenerateClientTokenWithScope(
		f.user.ID, f.user.Email, f.user.Username, string(f.user.Role),
		f.app.ClientID, "openid", jwt.TokenTypeAccess, time.Hour,
	)
	storedToken := &model.AccessToken{
		Token:     token,
		ClientID:  f.app.ClientID,
		UserID:    &f.user.ID,
		Scope:     "openid",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	f.oauthRepo.CreateAccessToken(storedToken)

	req := httptest.NewRequest(http.MethodGet, "/saml/idp/sso", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	user, claims, ok := f.service.userFromRequest(req)
	if !ok {
		t.Fatal("should accept valid token")
	}
	if user.ID != f.user.ID {
		t.Fatalf("user.ID=%v want %v", user.ID, f.user.ID)
	}
	if claims.UserID != f.user.ID {
		t.Fatalf("claims.UserID=%v want %v", claims.UserID, f.user.ID)
	}
}

func TestSamlNameIDValue_AllFormats(t *testing.T) {
	user := &model.User{
		Email:    "test@example.com",
		Username: "testuser",
	}
	user.ID = uuid.MustParse("11111111-1111-1111-1111-111111111111")

	cases := []struct {
		format string
		want   string
	}{
		{model.SAMLNameIDFormatEmailAddress, "test@example.com"},
		{model.SAMLNameIDFormatUnspecified, "testuser"},
		{model.SAMLNameIDFormatPersistent, "11111111-1111-1111-1111-111111111111"},
		{model.SAMLNameIDFormatTransient, "11111111-1111-1111-1111-111111111111"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			got := samlNameIDValue(user, tc.format)
			if got != tc.want {
				t.Fatalf("samlNameIDValue(%q)=%q want %q", tc.format, got, tc.want)
			}
		})
	}
}

func TestUserSAMLAttributes_DefaultMappings(t *testing.T) {
	user := &model.User{
		Email:    "attr@example.com",
		Username: "attruser",
		GivenName: "Attr",
		FamilyName: "User",
	}
	attrs := userSAMLAttributes(user, nil)
	found := map[string]string{}
	for _, a := range attrs {
		if len(a.Values) > 0 {
			found[a.Name] = a.Values[0].Value
		}
	}
	if found["email"] != "attr@example.com" {
		t.Fatalf("email=%q want attr@example.com", found["email"])
	}
	if found["username"] != "attruser" {
		t.Fatalf("username=%q want attruser", found["username"])
	}
	if found["displayName"] != "Attr User" {
		t.Fatalf("displayName=%q want 'Attr User'", found["displayName"])
	}
}

func TestUserSAMLAttributes_CustomMappingOverride(t *testing.T) {
	user := &model.User{
		Email:    "custom@example.com",
		Username: "customuser",
		GivenName: "Custom",
	}
	mappings := map[string]string{
		"email":     "mail",
		"givenName": "first_name",
	}
	attrs := userSAMLAttributes(user, mappings)
	found := map[string]string{}
	for _, a := range attrs {
		if len(a.Values) > 0 {
			found[a.Name] = a.Values[0].Value
		}
	}
	if found["mail"] != "custom@example.com" {
		t.Fatalf("mapped email attr name should be 'mail', got attrs: %v", found)
	}
	if found["first_name"] != "Custom" {
		t.Fatalf("mapped givenName attr name should be 'first_name', got attrs: %v", found)
	}
	if _, exists := found["email"]; exists {
		t.Fatal("original 'email' name should be overridden by mapping")
	}
}

func TestDisplayName_Fallbacks(t *testing.T) {
	cases := []struct {
		name     string
		user     *model.User
		expected string
	}{
		{"given+family", &model.User{GivenName: "John", FamilyName: "Doe", Username: "jdoe"}, "John Doe"},
		{"nickname only", &model.User{Nickname: "JD", Username: "jdoe"}, "JD"},
		{"username fallback", &model.User{Username: "jdoe"}, "jdoe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := displayName(tc.user)
			if got != tc.expected {
				t.Fatalf("displayName=%q want %q", got, tc.expected)
			}
		})
	}
}
