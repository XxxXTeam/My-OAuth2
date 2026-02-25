package oauth2

import (
	"strings"
	"testing"
)

/* ========== Config.Validate ========== */

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := DefaultConfig("client-id", "secret", "http://localhost:9000/callback")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestConfig_Validate_MissingClientID(t *testing.T) {
	cfg := DefaultConfig("", "secret", "http://localhost:9000/callback")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "client_id") {
		t.Errorf("Validate() should require client_id, got: %v", err)
	}
}

func TestConfig_Validate_MissingAuthURL(t *testing.T) {
	cfg := DefaultConfig("cid", "secret", "http://localhost:9000/callback")
	cfg.AuthURL = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "auth_url") {
		t.Errorf("Validate() should require auth_url, got: %v", err)
	}
}

func TestConfig_Validate_MissingTokenURL(t *testing.T) {
	cfg := DefaultConfig("cid", "secret", "http://localhost:9000/callback")
	cfg.TokenURL = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "token_url") {
		t.Errorf("Validate() should require token_url, got: %v", err)
	}
}

func TestConfig_Validate_MissingRedirectURL(t *testing.T) {
	cfg := DefaultConfig("cid", "secret", "")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "redirect_url") {
		t.Errorf("Validate() should require redirect_url, got: %v", err)
	}
}

func TestConfig_Validate_InvalidScheme(t *testing.T) {
	cfg := DefaultConfig("cid", "secret", "ftp://localhost/callback")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "http") {
		t.Errorf("Validate() should reject non-http scheme, got: %v", err)
	}
}

/* ========== DefaultConfig ========== */

func TestDefaultConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig("my-id", "my-secret", "http://localhost:9000/cb")
	if cfg.ClientID != "my-id" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "my-id")
	}
	if !cfg.UsePKCE {
		t.Error("UsePKCE should default to true")
	}
	if len(cfg.Scopes) == 0 {
		t.Error("Scopes should have defaults")
	}
}

/* ========== MemoryTokenStore ========== */

func TestMemoryTokenStore_SetGetDelete(t *testing.T) {
	store := NewMemoryTokenStore()

	/* 初始状态无 token */
	token, err := store.GetToken()
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}
	if token != nil {
		t.Error("initial GetToken() should return nil")
	}

	/* 存储 token */
	tk := &Token{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		TokenType:    "Bearer",
	}
	if err := store.SetToken(tk); err != nil {
		t.Fatalf("SetToken() error: %v", err)
	}

	/* 读取 token */
	got, err := store.GetToken()
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}
	if got == nil || got.AccessToken != "access-123" {
		t.Errorf("GetToken().AccessToken = %v, want %q", got, "access-123")
	}

	/* 删除 token */
	if err := store.DeleteToken(); err != nil {
		t.Fatalf("DeleteToken() error: %v", err)
	}
	got2, _ := store.GetToken()
	if got2 != nil {
		t.Error("GetToken() after DeleteToken() should return nil")
	}
}
