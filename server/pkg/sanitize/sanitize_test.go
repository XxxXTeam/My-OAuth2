package sanitize

import (
	"strings"
	"testing"
)

/* ========== String ========== */

func TestString_TrimSpace(t *testing.T) {
	got := String("  hello  ", 0)
	if got != "hello" {
		t.Errorf("String() = %q, want %q", got, "hello")
	}
}

func TestString_RemoveControlChars(t *testing.T) {
	got := String("he\x00ll\x07o", 0)
	if got != "hello" {
		t.Errorf("String() = %q, want %q", got, "hello")
	}
}

func TestString_MaxLen(t *testing.T) {
	got := String("abcdefghij", 5)
	if got != "abcde" {
		t.Errorf("String() = %q, want %q", got, "abcde")
	}
}

func TestString_MaxLen_Unicode(t *testing.T) {
	got := String("你好世界测试", 3)
	if got != "你好世" {
		t.Errorf("String() = %q, want %q", got, "你好世")
	}
}

func TestString_NoLimit(t *testing.T) {
	long := strings.Repeat("a", 1000)
	got := String(long, 0)
	if len(got) != 1000 {
		t.Errorf("String() length = %d, want 1000", len(got))
	}
}

/* ========== StripHTML ========== */

func TestStripHTML(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"<script>alert(1)</script>", "alert(1)"},
		{"<b>bold</b>", "bold"},
		{"<img src=x onerror=alert(1)>", ""},
		{"normal text", "normal text"},
		{"a<br/>b", "ab"},
	}
	for _, tt := range tests {
		got := StripHTML(tt.input)
		if got != tt.want {
			t.Errorf("StripHTML(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

/* ========== Username ========== */

func TestUsername_Valid(t *testing.T) {
	valids := []string{"alice", "bob_123", "用户名", "user-name", "abc"}
	for _, u := range valids {
		_, ok := Username(u)
		if !ok {
			t.Errorf("Username(%q) should be valid", u)
		}
	}
}

func TestUsername_Invalid(t *testing.T) {
	invalids := []string{"ab", "a b", "user@name", "<script>", "a!b"}
	for _, u := range invalids {
		_, ok := Username(u)
		if ok {
			t.Errorf("Username(%q) should be invalid", u)
		}
	}
}

/* ========== Email ========== */

func TestEmail(t *testing.T) {
	got := Email("  Admin@Example.COM  ")
	if got != "admin@example.com" {
		t.Errorf("Email() = %q, want %q", got, "admin@example.com")
	}
}

/* ========== PlainText ========== */

func TestPlainText(t *testing.T) {
	got := PlainText("  <b>Hello</b> World  ", 10)
	if got != "Hello Worl" {
		t.Errorf("PlainText() = %q, want %q", got, "Hello Worl")
	}
}

/* ========== URL ========== */

func TestURL_Valid(t *testing.T) {
	valids := []string{
		"https://example.com",
		"http://localhost:8080/callback",
		"https://sub.domain.com/path?q=1",
	}
	for _, u := range valids {
		_, ok := URL(u)
		if !ok {
			t.Errorf("URL(%q) should be valid", u)
		}
	}
}

func TestURL_Invalid(t *testing.T) {
	invalids := []string{
		"ftp://example.com",
		"javascript:alert(1)",
		"file:///etc/passwd",
		"http://example.com/javascript:void(0)",
	}
	for _, u := range invalids {
		_, ok := URL(u)
		if ok {
			t.Errorf("URL(%q) should be invalid", u)
		}
	}
}
