package jwt

import (
	"testing"
	"time"

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
