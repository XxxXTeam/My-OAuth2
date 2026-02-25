package password

import (
	"testing"
)

/* ========== Hash & Verify ========== */

func TestHash_And_Verify(t *testing.T) {
	pwd := "SecureP@ss1"
	hash, err := Hash(pwd)
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	if hash == "" {
		t.Fatal("Hash() returned empty string")
	}
	if !Verify(pwd, hash) {
		t.Error("Verify() should return true for correct password")
	}
	if Verify("WrongPassword1!", hash) {
		t.Error("Verify() should return false for wrong password")
	}
}

func TestHash_TooLong(t *testing.T) {
	longPwd := make([]byte, maxPasswordLength+1)
	for i := range longPwd {
		longPwd[i] = 'a'
	}
	_, err := Hash(string(longPwd))
	if err != ErrPasswordTooLong {
		t.Errorf("Hash() expected ErrPasswordTooLong, got %v", err)
	}
}

func TestVerify_TooLong_ReturnsFalse(t *testing.T) {
	longPwd := make([]byte, maxPasswordLength+1)
	for i := range longPwd {
		longPwd[i] = 'a'
	}
	if Verify(string(longPwd), "$2a$12$fakehash") {
		t.Error("Verify() should return false for password exceeding max length")
	}
}

/* ========== ValidateStrength ========== */

func TestValidateStrength(t *testing.T) {
	tests := []struct {
		name    string
		pwd     string
		wantErr error
	}{
		{"正常密码", "MyP@ssw0rd", nil},
		{"太短", "Ab1!", ErrPasswordTooShort},
		{"超长", string(make([]byte, 73)), ErrPasswordTooLong},
		{"常见弱密码", "password", ErrPasswordCommon},
		{"常见弱密码2", "admin123", ErrPasswordCommon},
		{"8位刚好通过", "abcdefgh", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStrength(tt.pwd)
			if err != tt.wantErr {
				t.Errorf("ValidateStrength(%q) = %v, want %v", tt.pwd, err, tt.wantErr)
			}
		})
	}
}

/* ========== ValidateChange ========== */

func TestValidateChange_SameAsOld(t *testing.T) {
	pwd := "OldP@ssw0rd"
	hash, _ := Hash(pwd)
	err := ValidateChange(pwd, hash)
	if err != ErrPasswordSameAsOld {
		t.Errorf("ValidateChange() expected ErrPasswordSameAsOld, got %v", err)
	}
}

func TestValidateChange_DifferentPassword(t *testing.T) {
	oldHash, _ := Hash("OldP@ssw0rd")
	err := ValidateChange("NewS3cure!", oldHash)
	if err != nil {
		t.Errorf("ValidateChange() unexpected error: %v", err)
	}
}

/* ========== CheckStrength ========== */

func TestCheckStrength(t *testing.T) {
	tests := []struct {
		name      string
		pwd       string
		wantLevel string
		minScore  int
	}{
		{"极弱", "abc", "weak", 0},
		{"仅长度达标", "abcdefgh", "fair", 1},
		{"大小写+长度", "Abcdefgh", "good", 2},
		{"大小写+数字", "Abcdefg1", "strong", 3},
		{"全满分", "Abcdefg1!xxx", "very_strong", 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := CheckStrength(tt.pwd)
			if r.Level != tt.wantLevel {
				t.Errorf("CheckStrength(%q).Level = %q, want %q (score=%d)", tt.pwd, r.Level, tt.wantLevel, r.Score)
			}
			if r.Score < tt.minScore {
				t.Errorf("CheckStrength(%q).Score = %d, want >= %d", tt.pwd, r.Score, tt.minScore)
			}
		})
	}
}

/* ========== NeedsRehash ========== */

func TestNeedsRehash(t *testing.T) {
	hash, _ := Hash("TestP@ss1")
	if NeedsRehash(hash) {
		t.Error("NeedsRehash() should return false for current cost hash")
	}
	if !NeedsRehash("invalid-hash") {
		t.Error("NeedsRehash() should return true for invalid hash")
	}
}

/* ========== GenerateRandom ========== */

func TestGenerateRandom(t *testing.T) {
	pwd, err := GenerateRandom(16)
	if err != nil {
		t.Fatalf("GenerateRandom() error: %v", err)
	}
	if len(pwd) != 16 {
		t.Errorf("GenerateRandom(16) length = %d, want 16", len(pwd))
	}
	/* 两次生成不应相同 */
	pwd2, _ := GenerateRandom(16)
	if pwd == pwd2 {
		t.Error("GenerateRandom() should produce different values on each call")
	}
}
