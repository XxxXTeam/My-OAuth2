package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/jwt"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type oauthUserInfoHandlerFixture struct {
	router    *gin.Engine
	oauthRepo *repository.OAuthRepository
	user      *model.User
	app       *model.Application
}

func setupOAuthUserInfoHandlerFixture(t *testing.T) oauthUserInfoHandlerFixture {
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
	userRepo := repository.NewUserRepository(db)

	cfg := &config.Config{
		OAuth: config.OAuthConfig{
			AccessTokenTTL:  time.Hour,
			RefreshTokenTTL: 24 * time.Hour,
			IDTokenTTL:      time.Hour,
		},
		JWT: config.JWTConfig{
			Secret: "test-secret-with-enough-length",
			Issuer: "test",
		},
	}
	oauthService := service.NewOAuthService(appRepo, oauthRepo, userRepo, nil, cfg)
	oauthService.SetJWTManager(jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer))

	user := &model.User{
		Email:        "oauth-userinfo-handler@example.com",
		Username:     "oauthuserinfohandler",
		PasswordHash: "hashed-password",
		Status:       "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	app := &model.Application{
		ClientID:      "oauth-userinfo-handler-client",
		ClientSecret:  "oauth-userinfo-handler-secret",
		Name:          "OAuth UserInfo Handler Client",
		UserID:        user.ID,
		Scopes:        `["openid","profile","email"]`,
		AllowedScopes: `["openid","profile","email"]`,
	}
	if err := appRepo.Create(app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	oauthHandler := NewOAuthHandler(oauthService, nil, "", "")
	router.GET("/oauth/userinfo", oauthHandler.UserInfo)
	router.POST("/oauth/userinfo", oauthHandler.UserInfo)

	return oauthUserInfoHandlerFixture{
		router:    router,
		oauthRepo: oauthRepo,
		user:      user,
		app:       app,
	}
}

func createUserInfoAccessToken(t *testing.T, f oauthUserInfoHandlerFixture, token, scope string) *model.AccessToken {
	t.Helper()

	accessToken := &model.AccessToken{
		Token:     token,
		ClientID:  f.app.ClientID,
		UserID:    &f.user.ID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := f.oauthRepo.CreateAccessToken(accessToken); err != nil {
		t.Fatalf("create access token: %v", err)
	}
	return accessToken
}

func getUserInfo(t *testing.T, router *gin.Engine, token string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func getUserInfoWithAuthorization(t *testing.T, router *gin.Engine, authorization string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", authorization)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func requireBearerChallenge(t *testing.T, rec *httptest.ResponseRecorder, expectedError string) {
	t.Helper()

	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, "Bearer") {
		t.Fatalf("WWW-Authenticate=%q should contain Bearer", challenge)
	}
	if !strings.Contains(challenge, `error="`+expectedError+`"`) {
		t.Fatalf("WWW-Authenticate=%q should contain error=%q", challenge, expectedError)
	}
}

func TestOAuthHandler_UserInfoRejectsAccessTokenWithoutOpenIDScope(t *testing.T) {
	f := setupOAuthUserInfoHandlerFixture(t)
	accessToken := createUserInfoAccessToken(t, f, "userinfo-handler-no-openid-token", "profile email")

	rec := getUserInfo(t, f.router, accessToken.Token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	requireBearerChallenge(t, rec, "insufficient_scope")

	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.Error != "insufficient_scope" {
		t.Fatalf("error=%q want insufficient_scope", body.Error)
	}
}

func TestOAuthHandler_UserInfoAllowsAccessTokenWithOpenIDScope(t *testing.T) {
	f := setupOAuthUserInfoHandlerFixture(t)
	accessToken := createUserInfoAccessToken(t, f, "userinfo-handler-openid-token", "openid profile email")

	rec := getUserInfo(t, f.router, accessToken.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.Sub != f.user.ID.String() {
		t.Fatalf("sub=%q want %s", body.Sub, f.user.ID.String())
	}
	if body.PreferredUsername != f.user.Username {
		t.Fatalf("preferred_username=%q want %s", body.PreferredUsername, f.user.Username)
	}
	if body.Email != f.user.Email {
		t.Fatalf("email=%q want %s", body.Email, f.user.Email)
	}
}

func TestOAuthHandler_UserInfoAllowsPost(t *testing.T) {
	f := setupOAuthUserInfoHandlerFixture(t)
	accessToken := createUserInfoAccessToken(t, f, "userinfo-handler-post-token", "openid email")

	req := httptest.NewRequest(http.MethodPost, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken.Token)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.Sub != f.user.ID.String() || body.Email != f.user.Email {
		t.Fatalf("body=%+v", body)
	}
}

func TestOAuthHandler_UserInfoOpenIDOnlyReturnsOnlySubject(t *testing.T) {
	f := setupOAuthUserInfoHandlerFixture(t)
	accessToken := createUserInfoAccessToken(t, f, "userinfo-handler-openid-only-token", "openid")

	rec := getUserInfo(t, f.router, accessToken.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body["sub"] != f.user.ID.String() {
		t.Fatalf("sub=%v want %s", body["sub"], f.user.ID.String())
	}
	for _, key := range []string{
		"name",
		"preferred_username",
		"email",
		"email_verified",
		"phone_number",
		"phone_number_verified",
		"address",
	} {
		if _, ok := body[key]; ok {
			t.Fatalf("claim %q should not be returned for openid-only scope body=%s", key, rec.Body.String())
		}
	}
}

func TestOAuthHandler_UserInfoRejectsNonBearerAuthorizationScheme(t *testing.T) {
	f := setupOAuthUserInfoHandlerFixture(t)
	accessToken := createUserInfoAccessToken(t, f, "userinfo-handler-non-bearer-token", "openid profile")

	rec := getUserInfoWithAuthorization(t, f.router, "Basic "+accessToken.Token)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	requireBearerChallenge(t, rec, "invalid_token")

	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if body.Error != "invalid_token" {
		t.Fatalf("error=%q want invalid_token", body.Error)
	}
}
