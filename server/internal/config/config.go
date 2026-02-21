/*
 * Package config 应用配置包
 * 功能：定义系统配置结构、加载配置文件、生成默认配置
 */
package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

/* 默认配置路径常量 */
const (
	DefaultConfigPath = "data/config.json"
	DefaultDataDir    = "data"
)

/*
 * Config 应用根配置
 * 功能：包含服务器、数据库、缓存、JWT、OAuth、邮件、社交登录、日志等全部配置
 */
type Config struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Cache    CacheConfig    `json:"cache"`
	JWT      JWTConfig      `json:"jwt"`
	OAuth    OAuthConfig    `json:"oauth"`
	Email    EmailConfig    `json:"email"`
	Social   SocialConfig   `json:"social"`
	Log      LogConfig      `json:"log"`
}

/* LogConfig 日志配置 */
type LogConfig struct {
	Level      string `json:"level"`       // debug, info, warn, error
	Format     string `json:"format"`      // text, json
	FileOutput string `json:"file_output"` // 日志文件路径，空则不输出文件
	MaxSizeMB  int    `json:"max_size_mb"` // 单文件最大MB
	MaxBackups int    `json:"max_backups"` // 保留历史文件数
	MaxAgeDays int    `json:"max_age_days"`
	Compress   bool   `json:"compress"` // 压缩历史文件
}

/* ServerConfig HTTP 服务器配置 */
type ServerConfig struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Mode               string `json:"mode"` // debug, release, test
	AllowRegistration  bool   `json:"allow_registration"`
	ShutdownTimeoutSec int    `json:"shutdown_timeout_sec"` // 优雅关停超时秒数
}

/* DatabaseConfig 数据库配置，支持 SQLite/PostgreSQL/MySQL */
type DatabaseConfig struct {
	Driver             string `json:"driver"` // sqlite, postgres, mysql
	DSN                string `json:"dsn"`
	MaxOpenConns       int    `json:"max_open_conns"`         // 最大打开连接数（0=使用驱动默认值）
	MaxIdleConns       int    `json:"max_idle_conns"`         // 最大空闲连接数
	ConnMaxLifetimeMin int    `json:"conn_max_lifetime_min"`  // 连接最大生存时间(分钟)
	ConnMaxIdleTimeMin int    `json:"conn_max_idle_time_min"` // 空闲连接最大存活时间(分钟)
}

/* CacheConfig 缓存配置，支持 memory/redis/memcached/badger/file */
type CacheConfig struct {
	Driver           string   `json:"driver"`            // memory, redis, memcached, badger, file
	RedisURL         string   `json:"redis_url"`         // Redis连接URL, 如 redis://localhost:6379/0
	MemcachedServers []string `json:"memcached_servers"` // Memcached服务器列表, 如 ["localhost:11211"]
	BadgerPath       string   `json:"badger_path"`       // BadgerDB数据目录
	FileDir          string   `json:"file_dir"`          // 文件缓存根目录
	Prefix           string   `json:"prefix"`            // 缓存键前缀
	DefaultTTLSec    int      `json:"default_ttl_sec"`   // 默认缓存TTL(秒)
}

type JWTConfig struct {
	Secret              string        `json:"secret"`
	AccessTokenTTLMin   int           `json:"access_token_ttl_minutes"`
	RefreshTokenTTLDays int           `json:"refresh_token_ttl_days"`
	Issuer              string        `json:"issuer"`
	AccessTokenTTL      time.Duration `json:"-"`
	RefreshTokenTTL     time.Duration `json:"-"`
}

type OAuthConfig struct {
	AuthCodeTTLMin      int           `json:"auth_code_ttl_minutes"`
	AccessTokenTTLHours int           `json:"access_token_ttl_hours"`
	RefreshTokenTTLDays int           `json:"refresh_token_ttl_days"`
	FrontendURL         string        `json:"frontend_url"`
	AuthCodeTTL         time.Duration `json:"-"`
	AccessTokenTTL      time.Duration `json:"-"`
	RefreshTokenTTL     time.Duration `json:"-"`
}

type EmailConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	FromName string `json:"from_name"`
	UseTLS   bool   `json:"use_tls"`
}

type SocialConfig struct {
	Enabled bool                 `json:"enabled"`
	GitHub  SocialProviderConfig `json:"github"`
	Google  SocialProviderConfig `json:"google"`
}

type SocialProviderConfig struct {
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// Load 加载配置文件
func Load() *Config {
	return LoadFromFile(DefaultConfigPath)
}

/*
 * LoadFromFile 从指定文件加载配置
 *
 * 加载策略：
 *  1. 文件不存在 → 生成默认配置（含随机 JWT Secret）并持久化
 *  2. 文件存在但 JSON 无效 → 在默认配置基础上解析，保留能解析的字段
 *  3. JWT Secret 为空 → 自动生成并回写配置文件，确保重启后密钥一致
 */
func LoadFromFile(configPath string) *Config {
	cfg := defaultConfig()

	// 确保 data 目录存在
	if err := os.MkdirAll(DefaultDataDir, 0755); err != nil {
		// 忽略错误，使用默认配置
	}

	// 尝试读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 配置文件不存在，创建默认配置文件（必须持久化 JWT Secret）
			if saveErr := saveConfig(configPath, cfg); saveErr != nil {
				// 持久化失败时输出醒目警告：此时 JWT Secret 仅存在于内存，
				// 重启后将生成新密钥，导致所有已签发的 token 失效
				fmt.Fprintf(os.Stderr, "WARNING: failed to save config to %s: %v\n", configPath, saveErr)
				fmt.Fprintf(os.Stderr, "WARNING: JWT secret is ephemeral — tokens will be invalidated on restart!\n")
			}
		}
		cfg.computeDurations()
		return cfg
	}

	// 解析 JSON —— 在 defaultConfig 基础上 Unmarshal，
	// 即使部分字段无效也能保留默认值，不会丢失 JWT Secret
	if err := json.Unmarshal(data, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: failed to parse config %s: %v (using defaults)\n", configPath, err)
		// 注意：这里不再 cfg = defaultConfig()，保留已成功解析的字段
	}

	// 确保 JWT Secret 非空：若配置文件中该字段为空或被清除，自动生成并回写
	needSave := false
	if cfg.JWT.Secret == "" {
		cfg.JWT.Secret = GenerateRandomSecret(32)
		needSave = true
	}
	if needSave {
		if saveErr := saveConfig(configPath, cfg); saveErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: failed to persist generated JWT secret: %v\n", saveErr)
		}
	}

	cfg.computeDurations()
	return cfg
}

// GenerateRandomSecret 生成随机密钥
func GenerateRandomSecret(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// 如果随机生成失败，返回一个基于时间的备用密钥
		return base64.URLEncoding.EncodeToString([]byte(time.Now().String()))
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

// defaultConfig 返回默认配置
func defaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:               "0.0.0.0",
			Port:               8080,
			Mode:               "debug",
			AllowRegistration:  true,
			ShutdownTimeoutSec: 15,
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			DSN:    filepath.Join(DefaultDataDir, "oauth2.db"),
		},
		Cache: CacheConfig{
			Driver:        "memory",
			RedisURL:      "",
			Prefix:        "oauth2:",
			DefaultTTLSec: 300,
		},
		JWT: JWTConfig{
			Secret:              GenerateRandomSecret(32), // 随机生成256位密钥
			AccessTokenTTLMin:   15,
			RefreshTokenTTLDays: 7,
			Issuer:              "my-oauth2",
		},
		OAuth: OAuthConfig{
			AuthCodeTTLMin:      10,
			AccessTokenTTLHours: 1,
			RefreshTokenTTLDays: 30,
			FrontendURL:         "",
		},
		Email: EmailConfig{
			Host:     "",
			Port:     587,
			Username: "",
			Password: "",
			From:     "noreply@example.com",
			FromName: "OAuth2 Service",
			UseTLS:   true,
		},
		Social: SocialConfig{
			Enabled: false, // 默认关闭第三方登录
			GitHub: SocialProviderConfig{
				Enabled:      false,
				ClientID:     "",
				ClientSecret: "",
			},
			Google: SocialProviderConfig{
				Enabled:      false,
				ClientID:     "",
				ClientSecret: "",
			},
		},
		Log: LogConfig{
			Level:      "info",
			Format:     "text",
			FileOutput: "",
			MaxSizeMB:  100,
			MaxBackups: 5,
			MaxAgeDays: 30,
			Compress:   false,
		},
	}
}

// ComputeDurations 计算时间 Duration（将配置文件中的分钟/小时/天数转为 time.Duration）
func (c *Config) ComputeDurations() {
	c.computeDurations()
}

func (c *Config) computeDurations() {
	c.JWT.AccessTokenTTL = time.Duration(c.JWT.AccessTokenTTLMin) * time.Minute
	c.JWT.RefreshTokenTTL = time.Duration(c.JWT.RefreshTokenTTLDays) * 24 * time.Hour
	c.OAuth.AuthCodeTTL = time.Duration(c.OAuth.AuthCodeTTLMin) * time.Minute
	c.OAuth.AccessTokenTTL = time.Duration(c.OAuth.AccessTokenTTLHours) * time.Hour
	c.OAuth.RefreshTokenTTL = time.Duration(c.OAuth.RefreshTokenTTLDays) * 24 * time.Hour
}

// saveConfig 保存配置到文件
func saveConfig(configPath string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}

// Save 保存当前配置
func (c *Config) Save() error {
	return saveConfig(DefaultConfigPath, c)
}

// GetDataDir 获取数据目录路径
func GetDataDir() string {
	return DefaultDataDir
}

/*
 * Validate 校验配置合法性
 * 功能：启动时检测必要参数，提前发现配置错误避免运行时异常
 * 返回值：错误切片（为空表示配置正常）
 */
func (c *Config) Validate() []string {
	var errs []string

	/* 服务配置 */
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		errs = append(errs, "server.port must be between 1 and 65535")
	}
	validModes := map[string]bool{"debug": true, "release": true, "test": true}
	if !validModes[c.Server.Mode] {
		errs = append(errs, "server.mode must be 'debug', 'release', or 'test'")
	}

	/* 数据库配置 */
	validDrivers := map[string]bool{"sqlite": true, "postgres": true, "mysql": true}
	if !validDrivers[c.Database.Driver] {
		errs = append(errs, "database.driver must be 'sqlite', 'postgres', or 'mysql'")
	}

	/* 缓存配置 */
	validCacheDrivers := map[string]bool{"memory": true, "redis": true, "memcached": true, "badger": true, "file": true}
	if c.Cache.Driver != "" && !validCacheDrivers[c.Cache.Driver] {
		errs = append(errs, "cache.driver must be one of: memory, redis, memcached, badger, file")
	}
	if c.Cache.Driver == "redis" && c.Cache.RedisURL == "" {
		errs = append(errs, "cache.redis_url must be set when cache.driver is 'redis'")
	}
	if c.Cache.Driver == "memcached" && len(c.Cache.MemcachedServers) == 0 {
		errs = append(errs, "cache.memcached_servers must be set when cache.driver is 'memcached'")
	}
	if c.Database.DSN == "" {
		errs = append(errs, "database.dsn must not be empty")
	}

	/* JWT 配置 */
	if len(c.JWT.Secret) < 16 {
		errs = append(errs, "jwt.secret must be at least 16 characters for security")
	}
	if c.JWT.AccessTokenTTLMin <= 0 {
		errs = append(errs, "jwt.access_token_ttl_minutes must be positive")
	}
	if c.JWT.RefreshTokenTTLDays <= 0 {
		errs = append(errs, "jwt.refresh_token_ttl_days must be positive")
	}
	if c.JWT.Issuer == "" {
		errs = append(errs, "jwt.issuer must not be empty")
	}

	/* OAuth 配置 */
	if c.OAuth.AuthCodeTTLMin <= 0 {
		errs = append(errs, "oauth.auth_code_ttl_minutes must be positive")
	}
	if c.OAuth.FrontendURL != "" {
		if _, err := url.ParseRequestURI(c.OAuth.FrontendURL); err != nil {
			errs = append(errs, "oauth.frontend_url must be a valid URL")
		}
	}

	/* 邮件配置：当 host 非空时校验必要字段 */
	if c.Email.Host != "" {
		if c.Email.Port <= 0 || c.Email.Port > 65535 {
			errs = append(errs, "email.port must be between 1 and 65535 when email.host is set")
		}
		if c.Email.From == "" {
			errs = append(errs, "email.from must not be empty when email.host is set")
		}
	}

	return errs
}
