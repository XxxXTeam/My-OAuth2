package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type oidcLogoutHandlerFixture struct {
	router  *gin.Engine
	manager *jwt.Manager
	user    *model.User
	app     *model.Application
}

func setupOIDCLogoutHandlerFixture(t *testing.T) oidcLogoutHandlerFixture {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Application{}, &model.AccessToken{}, &model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	appRepo := repository.NewApplicationRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)

	user := &model.User{
		Email:        "oidc-logout@example.com",
		Username:     "oidclogout",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:               "oidc-logout-client",
		ClientSecret:           "oidc-logout-secret",
		Name:                   "OIDC Logout Client",
		UserID:                 user.ID,
		RedirectURIs:           `["http://localhost/callback"]`,
		PostLogoutRedirectURIs: `["http://localhost/logout-callback","http://localhost/logout-callback?from=rp"]`,
		GrantTypes:             `["authorization_code"]`,
		Scopes:                 `["openid","profile"]`,
		AllowedScopes:          `["openid","profile"]`,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	manager := jwt.NewManager("test-secret-with-enough-length", "test-issuer")
	oidcHandler := NewOIDCHandler("test-issuer", manager)
	oidcHandler.SetOAuthRepo(oauthRepo)
	oidcHandler.SetApplicationRepo(appRepo)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/oauth/logout", oidcHandler.Logout)

	return oidcLogoutHandlerFixture{
		router:  router,
		manager: manager,
		user:    user,
		app:     app,
	}
}

func makeLogoutIDToken(t *testing.T, f oidcLogoutHandlerFixture) string {
	t.Helper()

	idToken, err := f.manager.GenerateClientIDTokenWithNonceAndAuthTime(
		f.user.ID, f.user.Email, f.user.Username, string(f.user.Role),
		f.app.ClientID, f.app.ClientSecret, "openid profile", "", time.Now().Unix(), time.Hour,
	)
	if err != nil {
		t.Fatalf("generate id token: %v", err)
	}
	return idToken
}

func TestOIDCHandler_LogoutRejectsUnregisteredPostLogoutRedirectURI(t *testing.T) {
	f := setupOIDCLogoutHandlerFixture(t)
	idToken := makeLogoutIDToken(t, f)

	u := "/oauth/logout?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape("https://evil.example/logout") +
		"&state=" + url.QueryEscape("logout-state")
	req := httptest.NewRequest(http.MethodGet, u, nil)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d location=%s body=%s", rec.Code, http.StatusOK, rec.Header().Get("Location"), rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("Location=%q want empty", rec.Header().Get("Location"))
	}
}

func TestOIDCHandler_LogoutRejectsAccessTokenHintForPostLogoutRedirectURI(t *testing.T) {
	f := setupOIDCLogoutHandlerFixture(t)
	accessToken, err := f.manager.GenerateClientToken(f.user.ID, f.user.Email, f.user.Username, string(f.user.Role), f.app.ClientID, jwt.TokenTypeAccess, time.Hour)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}

	u := "/oauth/logout?id_token_hint=" + url.QueryEscape(accessToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape("http://localhost/logout-callback") +
		"&state=" + url.QueryEscape("logout-state")
	req := httptest.NewRequest(http.MethodGet, u, nil)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d location=%s body=%s", rec.Code, http.StatusOK, rec.Header().Get("Location"), rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("Location=%q want empty", rec.Header().Get("Location"))
	}
}

func TestOIDCHandler_LogoutAllowsRegisteredPostLogoutRedirectURI(t *testing.T) {
	f := setupOIDCLogoutHandlerFixture(t)
	idToken := makeLogoutIDToken(t, f)

	u := "/oauth/logout?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape("http://localhost/logout-callback") +
		"&state=" + url.QueryEscape("logout-state")
	req := httptest.NewRequest(http.MethodGet, u, nil)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "http://localhost/logout-callback?state=logout-state" {
		t.Fatalf("Location=%q want registered post logout redirect with state", got)
	}
}

func TestOIDCHandler_LogoutEncodesStateInRegisteredPostLogoutRedirectURI(t *testing.T) {
	f := setupOIDCLogoutHandlerFixture(t)
	idToken := makeLogoutIDToken(t, f)

	u := "/oauth/logout?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape("http://localhost/logout-callback?from=rp") +
		"&state=" + url.QueryEscape("state value&next=/profile")
	req := httptest.NewRequest(http.MethodGet, u, nil)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location=%q: %v", location, err)
	}
	if parsed.Scheme != "http" || parsed.Host != "localhost" || parsed.Path != "/logout-callback" {
		t.Fatalf("Location=%q want localhost logout callback", location)
	}
	if got := parsed.Query().Get("from"); got != "rp" {
		t.Fatalf("from=%q want rp Location=%q", got, location)
	}
	if got := parsed.Query().Get("state"); got != "state value&next=/profile" {
		t.Fatalf("state=%q want original state Location=%q", got, location)
	}
}
