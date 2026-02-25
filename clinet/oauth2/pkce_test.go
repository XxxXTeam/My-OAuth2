package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestGeneratePKCE_ValidOutput(t *testing.T) {
	pkce, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error: %v", err)
	}
	if pkce.Method != "S256" {
		t.Errorf("Method = %q, want %q", pkce.Method, "S256")
	}
	/* RFC 7636: verifier 长度 43-128 */
	if len(pkce.CodeVerifier) < 43 || len(pkce.CodeVerifier) > 128 {
		t.Errorf("CodeVerifier length = %d, want 43-128", len(pkce.CodeVerifier))
	}
	if pkce.CodeChallenge == "" {
		t.Error("CodeChallenge should not be empty")
	}
}

func TestGeneratePKCE_ChallengeMatchesVerifier(t *testing.T) {
	pkce, _ := GeneratePKCE()
	/* 手动计算 S256 challenge 验证一致性 */
	hash := sha256.Sum256([]byte(pkce.CodeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	if pkce.CodeChallenge != expected {
		t.Errorf("CodeChallenge mismatch:\n  got  %q\n  want %q", pkce.CodeChallenge, expected)
	}
}

func TestGeneratePKCE_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pkce, _ := GeneratePKCE()
		if seen[pkce.CodeVerifier] {
			t.Fatal("GeneratePKCE() produced duplicate verifier")
		}
		seen[pkce.CodeVerifier] = true
	}
}
