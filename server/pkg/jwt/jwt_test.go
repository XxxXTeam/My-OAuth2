package jwt

import (
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func newTestManager() *Manager {
	return NewManager("test-secret-key-32bytes-long!!", "test-issuer")
}

/* ========== GenerateToken & ValidateToken ========== */

func TestGenerateAndValidate_AccessToken(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()

	token, err := m.GenerateToken(uid, "test@example.com", "testuser", "user", TokenTypeAccess, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateToken() returned empty string")
	}

	claims, err := m.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error: %v", err)
	}
	if claims.UserID != uid {
		t.Errorf("UserID = %v, want %v", claims.UserID, uid)
	}
	if claims.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "test@example.com")
	}
	if claims.Username != "testuser" {
		t.Errorf("Username = %q, want %q", claims.Username, "testuser")
	}
	if claims.Role != "user" {
		t.Errorf("Role = %q, want %q", claims.Role, "user")
	}
	if claims.TokenType != TokenTypeAccess {
		t.Errorf("TokenType = %q, want %q", claims.TokenType, TokenTypeAccess)
	}
	if claims.Issuer != "test-issuer" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "test-issuer")
	}
}

/* ========== ValidateAccessToken ========== */

func TestValidateAccessToken_RejectRefresh(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()

	refreshToken, _ := m.GenerateToken(uid, "a@b.com", "user", "user", TokenTypeRefresh, 5*time.Minute)
	_, err := m.ValidateAccessToken(refreshToken)
	if err != ErrTokenTypeMismatch {
		t.Errorf("ValidateAccessToken(refresh) = %v, want ErrTokenTypeMismatch", err)
	}
}

func TestValidateAccessToken_RejectIDToken(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()

	idToken, err := m.GenerateIDToken(uid, "a@b.com", "user", "user", "client-1", "openid profile", 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateIDToken() error: %v", err)
	}
	_, err = m.ValidateAccessToken(idToken)
	if err != ErrTokenTypeMismatch {
		t.Errorf("ValidateAccessToken(id_token) = %v, want ErrTokenTypeMismatch", err)
	}
}

func TestGenerateIDTokenWithNonceStoresNonceClaim(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()

	idToken, err := m.GenerateIDTokenWithNonce(uid, "a@b.com", "user", "user", "client-1", "openid profile", "nonce-123", 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateIDTokenWithNonce() error: %v", err)
	}
	claims, err := m.ValidateToken(idToken)
	if err != nil {
		t.Fatalf("ValidateToken() error: %v", err)
	}
	if claims.Nonce != "nonce-123" {
		t.Fatalf("Nonce=%q want nonce-123", claims.Nonce)
	}
	if claims.TokenType != TokenTypeIDToken {
		t.Fatalf("TokenType=%q want %q", claims.TokenType, TokenTypeIDToken)
	}
}

func TestGenerateTokenWithAuthTimeStoresAuthTimeClaim(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()
	authTime := time.Now().Add(-5 * time.Minute).Unix()

	token, err := m.GenerateTokenWithAuthTime(uid, "a@b.com", "user", "user", TokenTypeAccess, authTime, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateTokenWithAuthTime() error: %v", err)
	}
	claims, err := m.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error: %v", err)
	}
	if claims.AuthTime != authTime {
		t.Fatalf("AuthTime=%d want %d", claims.AuthTime, authTime)
	}
}

func TestGenerateIDTokenWithNonceAndAuthTimeStoresClaims(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()
	authTime := time.Now().Add(-5 * time.Minute).Unix()
	atHash := AccessTokenHash("access-token")

	idToken, err := m.GenerateIDTokenWithNonceAndAuthTimeAndAMRAndATHash(uid, "a@b.com", "user", "user", "client-1", "openid profile", "nonce-123", authTime, []string{AuthenticationMethodPassword}, atHash, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateIDTokenWithNonceAndAuthTimeAndAMRAndATHash() error: %v", err)
	}
	claims, err := m.ValidateToken(idToken)
	if err != nil {
		t.Fatalf("ValidateToken() error: %v", err)
	}
	if claims.Nonce != "nonce-123" {
		t.Fatalf("Nonce=%q want nonce-123", claims.Nonce)
	}
	if claims.AuthTime != authTime {
		t.Fatalf("AuthTime=%d want %d", claims.AuthTime, authTime)
	}
	if len(claims.AMR) != 1 || claims.AMR[0] != AuthenticationMethodPassword {
		t.Fatalf("AMR=%#v want [%q]", claims.AMR, AuthenticationMethodPassword)
	}
	if claims.ATHash != atHash {
		t.Fatalf("ATHash=%q want %q", claims.ATHash, atHash)
	}
	if claims.TokenType != TokenTypeIDToken {
		t.Fatalf("TokenType=%q want %q", claims.TokenType, TokenTypeIDToken)
	}
}

func TestGenerateIDTokenWithoutNonceLeavesNonceClaimEmpty(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()

	idToken, err := m.GenerateIDToken(uid, "a@b.com", "user", "user", "client-1", "openid profile", 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateIDToken() error: %v", err)
	}
	claims, err := m.ValidateToken(idToken)
	if err != nil {
		t.Fatalf("ValidateToken() error: %v", err)
	}
	if claims.Nonce != "" {
		t.Fatalf("Nonce=%q want empty", claims.Nonce)
	}
}

func TestGenerateClientIDTokenWithNonceAndAuthTimeUsesClientSecretJWS(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()
	authTime := time.Now().Add(-5 * time.Minute).Unix()
	atHash := AccessTokenHash("access-token")

	idToken, err := m.GenerateClientIDTokenWithNonceAndAuthTimeAndAMRAndATHash(uid, "a@b.com", "user", "user", "client-1", "client-secret", "openid profile", "nonce-123", authTime, []string{AuthenticationMethodPassword}, atHash, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateClientIDTokenWithNonceAndAuthTimeAndAMRAndATHash() error: %v", err)
	}
	if IsEncryptedToken(idToken) {
		t.Fatalf("client id_token should be a plain JWS, got encrypted token")
	}
	if strings.Count(idToken, ".") != 2 {
		t.Fatalf("client id_token should be compact JWS, got %q", idToken)
	}

	claims, err := m.ValidateClientIDToken(idToken, "client-1", "")
	if err != nil {
		t.Fatalf("ValidateClientIDToken() error: %v", err)
	}
	if claims.TokenType != TokenTypeIDToken {
		t.Fatalf("TokenType=%q want %q", claims.TokenType, TokenTypeIDToken)
	}
	if claims.ClientID != "client-1" {
		t.Fatalf("ClientID=%q want client-1", claims.ClientID)
	}
	if claims.AuthorizedParty != "client-1" {
		t.Fatalf("AuthorizedParty=%q want client-1", claims.AuthorizedParty)
	}
	if claims.Nonce != "nonce-123" {
		t.Fatalf("Nonce=%q want nonce-123", claims.Nonce)
	}
	if claims.AuthTime != authTime {
		t.Fatalf("AuthTime=%d want %d", claims.AuthTime, authTime)
	}
	if len(claims.AMR) != 1 || claims.AMR[0] != AuthenticationMethodPassword {
		t.Fatalf("AMR=%#v want [%q]", claims.AMR, AuthenticationMethodPassword)
	}
	if claims.ATHash != atHash {
		t.Fatalf("ATHash=%q want %q", claims.ATHash, atHash)
	}

	// 使用不同 RSA 密钥的 Manager 验证应失败
	m2 := NewManager("other-secret-key-with-enough-len", "test-issuer")
	if _, err := m2.ValidateClientIDToken(idToken, "client-1", ""); err != ErrInvalidToken {
		t.Fatalf("ValidateClientIDToken(different RSA key)=%v want ErrInvalidToken", err)
	}
}

func TestValidateClientIDTokenRejectsAuthorizedPartyMismatch(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()
	now := time.Now()
	token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, &Claims{
		UserID:          uid,
		Email:           "a@b.com",
		Username:        "user",
		Role:            "user",
		TokenType:       TokenTypeIDToken,
		ClientID:        "client-1",
		AuthorizedParty: "other-client",
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   uid.String(),
			Audience:  gojwt.ClaimStrings{"client-1"},
			IssuedAt:  gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: gojwt.NewNumericDate(now.Add(-time.Minute)),
		},
	})
	token.Header["kid"] = m.KeyID()
	idToken, err := token.SignedString(m.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}

	if _, err := m.ValidateClientIDToken(idToken, "client-1", ""); err != ErrInvalidToken {
		t.Fatalf("ValidateClientIDToken(azp mismatch)=%v want ErrInvalidToken", err)
	}
}

func TestAccessTokenHashUsesOIDCHS256LeftHalf(t *testing.T) {
	if got := AccessTokenHash("access-token"); got != "Pxa-1wifRlPl7yG_0oJNfw" {
		t.Fatalf("AccessTokenHash=%q want Pxa-1wifRlPl7yG_0oJNfw", got)
	}
	if got := AccessTokenHash(""); got != "" {
		t.Fatalf("AccessTokenHash(empty)=%q want empty", got)
	}
}

func TestGenerateClientIDTokenWithIssuerUsesRequestedIssuer(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()

	idToken, err := m.GenerateClientIDTokenWithIssuerAndNonceAndAuthTime(
		uid,
		"a@b.com",
		"user",
		"user",
		"client-1",
		"client-secret",
		"https://oauth.example.test",
		"openid profile",
		"",
		time.Now().Unix(),
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("GenerateClientIDTokenWithIssuerAndNonceAndAuthTime() error: %v", err)
	}

	claims, err := m.ValidateClientIDTokenWithIssuer(idToken, "client-1", "client-secret", "https://oauth.example.test")
	if err != nil {
		t.Fatalf("ValidateClientIDTokenWithIssuer() error: %v", err)
	}
	if claims.Issuer != "https://oauth.example.test" {
		t.Fatalf("Issuer=%q want https://oauth.example.test", claims.Issuer)
	}
	if _, err := m.ValidateClientIDToken(idToken, "client-1", "client-secret"); err != ErrInvalidToken {
		t.Fatalf("ValidateClientIDToken(default issuer)=%v want ErrInvalidToken", err)
	}
}

func TestValidateAccessToken_AcceptAccess(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()

	accessToken, _ := m.GenerateToken(uid, "a@b.com", "user", "user", TokenTypeAccess, 5*time.Minute)
	claims, err := m.ValidateAccessToken(accessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error: %v", err)
	}
	if claims.TokenType != TokenTypeAccess {
		t.Errorf("TokenType = %q, want %q", claims.TokenType, TokenTypeAccess)
	}
}

/* ========== ValidateRefreshToken ========== */

func TestValidateRefreshToken_RejectAccess(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()

	accessToken, _ := m.GenerateToken(uid, "a@b.com", "user", "user", TokenTypeAccess, 5*time.Minute)
	_, err := m.ValidateRefreshToken(accessToken)
	if err != ErrTokenTypeMismatch {
		t.Errorf("ValidateRefreshToken(access) = %v, want ErrTokenTypeMismatch", err)
	}
}

/* ========== Expired Token ========== */

func TestValidateToken_Expired(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()

	/* 生成一个已过期的 token（TTL = -1s） */
	token, _ := m.GenerateToken(uid, "a@b.com", "user", "user", TokenTypeAccess, -1*time.Second)
	_, err := m.ValidateToken(token)
	if err != ErrExpiredToken {
		t.Errorf("ValidateToken(expired) = %v, want ErrExpiredToken", err)
	}
}

/* ========== Invalid Token ========== */

func TestValidateToken_InvalidString(t *testing.T) {
	m := newTestManager()
	_, err := m.ValidateToken("not-a-jwt")
	if err != ErrInvalidToken {
		t.Errorf("ValidateToken(invalid) = %v, want ErrInvalidToken", err)
	}
}

/* ========== Wrong Secret ========== */

func TestValidateToken_WrongSecret(t *testing.T) {
	m1 := NewManager("secret-one-xxxxxxxxxxxxxxxxxxxxxx", "issuer")
	m2 := NewManager("secret-two-xxxxxxxxxxxxxxxxxxxxxx", "issuer")
	uid := uuid.New()

	token, _ := m1.GenerateToken(uid, "a@b.com", "user", "user", TokenTypeAccess, 5*time.Minute)
	_, err := m2.ValidateToken(token)
	if err != ErrInvalidToken {
		t.Errorf("ValidateToken(wrong secret) = %v, want ErrInvalidToken", err)
	}
}

/* ========== Wrong Issuer ========== */

func TestValidateToken_WrongIssuer(t *testing.T) {
	m1 := NewManager("same-secret-key-xxxxxxxxxxxx", "issuer-a")
	m2 := NewManager("same-secret-key-xxxxxxxxxxxx", "issuer-b")
	uid := uuid.New()

	token, _ := m1.GenerateToken(uid, "a@b.com", "user", "user", TokenTypeAccess, 5*time.Minute)
	_, err := m2.ValidateToken(token)
	if err != ErrInvalidToken {
		t.Errorf("ValidateToken(wrong issuer) = %v, want ErrInvalidToken", err)
	}
}

/* ========== JTI Uniqueness ========== */

func TestGenerateSecureJTI_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		jti := generateSecureJTI()
		if seen[jti] {
			t.Fatalf("generateSecureJTI() produced duplicate: %s", jti)
		}
		seen[jti] = true
	}
}
