package config

import (
	"os"
	"testing"
)

/* ========== applyEnvOverrides ========== */

func TestApplyEnvOverrides_ServerPort(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("SERVER_PORT", "9090")
	defer os.Unsetenv("SERVER_PORT")

	cfg.applyEnvOverrides()
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
}

func TestApplyEnvOverrides_InvalidPort_Ignored(t *testing.T) {
	cfg := defaultConfig()
	original := cfg.Server.Port
	os.Setenv("SERVER_PORT", "not-a-number")
	defer os.Unsetenv("SERVER_PORT")

	cfg.applyEnvOverrides()
	if cfg.Server.Port != original {
		t.Errorf("Server.Port changed to %d on invalid input, should stay %d", cfg.Server.Port, original)
	}
}

func TestApplyEnvOverrides_GinMode(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("GIN_MODE", "release")
	defer os.Unsetenv("GIN_MODE")

	cfg.applyEnvOverrides()
	if cfg.Server.Mode != "release" {
		t.Errorf("Server.Mode = %q, want %q", cfg.Server.Mode, "release")
	}
}

func TestApplyEnvOverrides_DBDriver(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("DB_DRIVER", "postgres")
	defer os.Unsetenv("DB_DRIVER")

	cfg.applyEnvOverrides()
	if cfg.Database.Driver != "postgres" {
		t.Errorf("Database.Driver = %q, want %q", cfg.Database.Driver, "postgres")
	}
}

func TestApplyEnvOverrides_DBDSN(t *testing.T) {
	cfg := defaultConfig()
	dsn := "postgres://user:pass@localhost/oauth2"
	os.Setenv("DB_DSN", dsn)
	defer os.Unsetenv("DB_DSN")

	cfg.applyEnvOverrides()
	if cfg.Database.DSN != dsn {
		t.Errorf("Database.DSN = %q, want %q", cfg.Database.DSN, dsn)
	}
}

func TestApplyEnvOverrides_JWTSecret(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("JWT_SECRET", "my-env-secret")
	defer os.Unsetenv("JWT_SECRET")

	cfg.applyEnvOverrides()
	if cfg.JWT.Secret != "my-env-secret" {
		t.Errorf("JWT.Secret = %q, want %q", cfg.JWT.Secret, "my-env-secret")
	}
}

func TestApplyEnvOverrides_EmailConfig(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("EMAIL_HOST", "smtp.test.com")
	os.Setenv("EMAIL_PORT", "465")
	os.Setenv("EMAIL_USERNAME", "user@test.com")
	os.Setenv("EMAIL_PASSWORD", "secret123")
	os.Setenv("EMAIL_FROM", "noreply@test.com")
	defer func() {
		os.Unsetenv("EMAIL_HOST")
		os.Unsetenv("EMAIL_PORT")
		os.Unsetenv("EMAIL_USERNAME")
		os.Unsetenv("EMAIL_PASSWORD")
		os.Unsetenv("EMAIL_FROM")
	}()

	cfg.applyEnvOverrides()
	if cfg.Email.Host != "smtp.test.com" {
		t.Errorf("Email.Host = %q, want %q", cfg.Email.Host, "smtp.test.com")
	}
	if cfg.Email.Port != 465 {
		t.Errorf("Email.Port = %d, want 465", cfg.Email.Port)
	}
	if cfg.Email.Username != "user@test.com" {
		t.Errorf("Email.Username = %q, want %q", cfg.Email.Username, "user@test.com")
	}
	if cfg.Email.Password != "secret123" {
		t.Errorf("Email.Password = %q, want %q", cfg.Email.Password, "secret123")
	}
	if cfg.Email.From != "noreply@test.com" {
		t.Errorf("Email.From = %q, want %q", cfg.Email.From, "noreply@test.com")
	}
}

func TestApplyEnvOverrides_CacheRedis(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("CACHE_DRIVER", "redis")
	os.Setenv("REDIS_URL", "redis://localhost:6379/1")
	defer func() {
		os.Unsetenv("CACHE_DRIVER")
		os.Unsetenv("REDIS_URL")
	}()

	cfg.applyEnvOverrides()
	if cfg.Cache.Driver != "redis" {
		t.Errorf("Cache.Driver = %q, want %q", cfg.Cache.Driver, "redis")
	}
	if cfg.Cache.RedisURL != "redis://localhost:6379/1" {
		t.Errorf("Cache.RedisURL = %q, want %q", cfg.Cache.RedisURL, "redis://localhost:6379/1")
	}
}

func TestApplyEnvOverrides_NoEnv_NoChange(t *testing.T) {
	cfg := defaultConfig()
	origPort := cfg.Server.Port
	origDriver := cfg.Database.Driver

	cfg.applyEnvOverrides()
	if cfg.Server.Port != origPort {
		t.Errorf("Server.Port changed without env var")
	}
	if cfg.Database.Driver != origDriver {
		t.Errorf("Database.Driver changed without env var")
	}
}

/* ========== defaultConfig ========== */

func TestDefaultConfig_HasValidDefaults(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Server.Port != 8080 {
		t.Errorf("default Server.Port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.Database.Driver != "sqlite" {
		t.Errorf("default Database.Driver = %q, want %q", cfg.Database.Driver, "sqlite")
	}
	if cfg.JWT.Secret == "" {
		t.Error("default JWT.Secret should not be empty")
	}
	if cfg.JWT.AccessTokenTTLMin <= 0 {
		t.Error("default AccessTokenTTLMin should be positive")
	}
}

/* ========== GenerateRandomSecret ========== */

func TestGenerateRandomSecret_Length(t *testing.T) {
	s := GenerateRandomSecret(32)
	if s == "" {
		t.Error("GenerateRandomSecret() returned empty string")
	}
}

func TestGenerateRandomSecret_Unique(t *testing.T) {
	s1 := GenerateRandomSecret(32)
	s2 := GenerateRandomSecret(32)
	if s1 == s2 {
		t.Error("GenerateRandomSecret() should produce different values")
	}
}
