/*
 * Package database 数据库初始化与管理
 * 功能：数据库连接建立、DSN 自动规范化、Schema 迁移、连接池配置、默认管理员初始化
 *       支持 SQLite（开发）、PostgreSQL（生产）、MySQL（生产）三种驱动
 *
 * 自动迁移表（17 张）：
 *   users, applications, authorization_codes, access_tokens, refresh_tokens,
 *   system_configs, user_authorizations, login_logs, webhooks, webhook_deliveries,
 *   federated_providers, federated_identities, trusted_apps, password_resets,
 *   device_codes, email_verifications, email_tasks
 */
package database

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/pkg/logger"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

/* DB 全局数据库实例 */
var DB *gorm.DB

/*
 * normalizeDSN 规范化 DSN，为各驱动自动补全关键参数
 * SQLite:    追加 _busy_timeout / _journal_mode=WAL / _synchronous 等
 * MySQL:     追加 parseTime=true / charset=utf8mb4 / collation / loc 等
 * PostgreSQL: 追加 connect_timeout / statement_timeout 等
 */
func normalizeDSN(driver, dsn string) string {
	switch driver {
	case "sqlite":
		return normalizeSQLiteDSN(dsn)
	case "mysql":
		return normalizeMySQLDSN(dsn)
	case "postgres":
		return normalizePostgresDSN(dsn)
	}
	return dsn
}

/*
 * normalizeSQLiteDSN 为 SQLite DSN 追加关键 PRAGMA 参数
 * 默认参数：_busy_timeout=5000, _journal_mode=WAL, _synchronous=NORMAL,
 *          _cache_size=-64000(64MB), _foreign_keys=ON
 */
func normalizeSQLiteDSN(dsn string) string {
	defaults := map[string]string{
		"_busy_timeout": "5000",
		"_journal_mode": "WAL",
		"_synchronous":  "NORMAL",
		"_cache_size":   "-64000",
		"_foreign_keys": "ON",
	}
	return ensureDSNParams(dsn, defaults)
}

/*
 * normalizeMySQLDSN 为 MySQL DSN 追加常用参数
 * 默认参数：parseTime=true, charset=utf8mb4, collation=utf8mb4_unicode_ci, loc=Local, timeout=10s
 */
func normalizeMySQLDSN(dsn string) string {
	defaults := map[string]string{
		"parseTime": "true",
		"charset":   "utf8mb4",
		"collation": "utf8mb4_unicode_ci",
		"loc":       "Local",
		"timeout":   "10s",
	}
	return ensureDSNParams(dsn, defaults)
}

/*
 * normalizePostgresDSN 为 PostgreSQL DSN 追加超时参数
 * 默认参数：connect_timeout=10, statement_timeout=30000(30s)
 * 同时支持 URI 格式（postgres://...）和 key=value 格式
 */
func normalizePostgresDSN(dsn string) string {
	// PostgreSQL 有两种格式：URI（postgres://...）和 key=value
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		defaults := map[string]string{
			"connect_timeout":   "10",
			"statement_timeout": "30000",
		}
		return ensureDSNParams(dsn, defaults)
	}
	// key=value 格式
	lower := strings.ToLower(dsn)
	if !strings.Contains(lower, "connect_timeout") {
		dsn += " connect_timeout=10"
	}
	if !strings.Contains(lower, "statement_timeout") {
		dsn += " statement_timeout=30000"
	}
	return dsn
}

/*
 * ensureDSNParams 向 DSN 追加缺失的查询参数（已有则跳过）
 * @param dsn      - 原始 DSN 字符串
 * @param defaults - 需要补全的参数键值对
 * @return string  - 补全后的 DSN
 */
func ensureDSNParams(dsn string, defaults map[string]string) string {
	lower := strings.ToLower(dsn)
	var missing []string
	for key, val := range defaults {
		if !strings.Contains(lower, strings.ToLower(key)+"=") {
			missing = append(missing, key+"="+val)
		}
	}
	if len(missing) == 0 {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + strings.Join(missing, "&")
}

/*
 * Init 初始化数据库
 * 流程：DSN 规范化 → 建立连接 → 验证连通性 → 配置连接池 → Schema 迁移 → 数据清理 → 初始化管理员
 * @param cfg - 数据库配置（驱动、DSN、连接池参数）
 *
 * SQLite 特殊处理：
 *   - 禁用 PrepareStmt（避免迁移时预编译语句持锁）
 *   - MaxOpenConns=1（单写模式，配合 WAL）
 *   - 自动设置 PRAGMA（journal_mode, synchronous, cache_size, busy_timeout）
 */
func Init(cfg *config.DatabaseConfig) error {
	var dialector gorm.Dialector

	/* 规范化 DSN：自动补全各驱动关键参数 */
	normalizedDSN := normalizeDSN(cfg.Driver, cfg.DSN)
	if normalizedDSN != cfg.DSN {
		logger.Info("Database DSN normalized", "driver", cfg.Driver, "dsn", normalizedDSN)
	}

	switch cfg.Driver {
	case "sqlite":
		dialector = sqlite.Open(normalizedDSN)
	case "postgres":
		dialector = postgres.Open(normalizedDSN)
	case "mysql":
		dialector = mysql.Open(normalizedDSN)
	default:
		return fmt.Errorf("unsupported database driver: %s", cfg.Driver)
	}
	silent := os.Getenv("GIN_MODE") == "release"
	gormLogger := logger.NewGormLogger(logger.Default(), silent)

	// SQLite 下禁用 PrepareStmt，避免迁移时预编译语句持锁导致 "database table is locked"
	usePrepareStmt := cfg.Driver != "sqlite"

	var err error
	DB, err = gorm.Open(dialector, &gorm.Config{
		Logger:                 gormLogger,
		SkipDefaultTransaction: true,
		PrepareStmt:            usePrepareStmt,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	if sqlDB, err := DB.DB(); err == nil {
		/* 验证数据库连通性 */
		if pingErr := sqlDB.Ping(); pingErr != nil {
			return fmt.Errorf("failed to ping database: %w", pingErr)
		}
		configureConnectionPool(sqlDB, cfg)
	}
	logger.Info("Database migrating...")
	if err := DB.AutoMigrate(
		&model.User{},
		&model.Application{},
		&model.AuthorizationCode{},
		&model.AccessToken{},
		&model.RefreshToken{},
		&model.SystemConfig{},
		&model.UserAuthorization{},
		&model.LoginLog{},
		&model.Webhook{},
		&model.WebhookDelivery{},
		&model.FederatedProvider{},
		&model.FederatedIdentity{},
		&model.TrustedApp{},
		&model.PasswordReset{},
		&model.DeviceCode{},
		&model.EmailVerification{},
		&model.EmailTask{},
	); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}
	logger.Info("Database migration completed")

	/* 数据清理：将历史数据中 access_token_id = 零值 UUID 的记录置为 NULL，
	 * 避免开启外键约束后导致异常 */
	DB.Exec("UPDATE refresh_tokens SET access_token_id = NULL WHERE access_token_id = '00000000-0000-0000-0000-000000000000'")

	// 初始化默认管理员（如果没有用户）
	if err := initDefaultAdmin(); err != nil {
		logger.Warn("Failed to init default admin", "error", err)
	}

	return nil
}

/*
 * initDefaultAdmin 初始化默认管理员账户
 * 功能：仅在数据库无用户时创建，从环境变量读取账号信息
 * 环境变量：ADMIN_EMAIL, ADMIN_USERNAME, ADMIN_PASSWORD
 * 默认值：admin@example.com / admin / admin123
 */
func initDefaultAdmin() error {
	var count int64
	if err := DB.Model(&model.User{}).Count(&count).Error; err != nil {
		return err
	}

	// 已有用户，跳过
	if count > 0 {
		return nil
	}

	// 从环境变量获取管理员信息，或使用默认值
	email := os.Getenv("ADMIN_EMAIL")
	if email == "" {
		email = "admin@example.com"
	}
	username := os.Getenv("ADMIN_USERNAME")
	if username == "" {
		username = "admin"
	}
	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		password = "admin123"
	}

	// 密码加密
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return err
	}

	admin := &model.User{
		Email:         email,
		Username:      username,
		PasswordHash:  hashedPassword,
		Role:          model.RoleAdmin,
		EmailVerified: true,
		Status:        "active",
	}

	if err := DB.Create(admin).Error; err != nil {
		return err
	}

	logger.Info("Default admin created", "email", email, "username", username)
	logger.Warn("⚠️  Please change the default admin password!")
	return nil
}

/* hashPassword 使用 bcrypt 生成密码哈希（cost=12） */
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

/* GetDB 获取全局数据库实例 */
func GetDB() *gorm.DB {
	return DB
}

/*
 * configureConnectionPool 配置数据库连接池
 * SQLite: MaxOpenConns=1, 无空闲超时（单文件锁）
 * PostgreSQL/MySQL: 可配置最大连接数、空闲连接数、生存时间等
 *   默认值：MaxOpen=25, MaxIdle=10, MaxLifetime=5min, MaxIdleTime=3min
 * @param sqlDB - 原生 sql.DB 实例
 * @param cfg   - 数据库配置
 */
func configureConnectionPool(sqlDB *sql.DB, cfg *config.DatabaseConfig) {
	switch cfg.Driver {
	case "sqlite":
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetConnMaxLifetime(0)
		DB.Exec("PRAGMA journal_mode=WAL")
		DB.Exec("PRAGMA synchronous=NORMAL")
		DB.Exec("PRAGMA cache_size=-64000")
		DB.Exec("PRAGMA busy_timeout=5000")
	case "postgres", "mysql":
		// 从配置读取连接池参数，0 表示使用默认值
		maxOpen := cfg.MaxOpenConns
		if maxOpen <= 0 {
			maxOpen = 25
		}
		maxIdle := cfg.MaxIdleConns
		if maxIdle <= 0 {
			maxIdle = 10
		}
		lifetime := time.Duration(cfg.ConnMaxLifetimeMin) * time.Minute
		if lifetime <= 0 {
			lifetime = 5 * time.Minute
		}
		idleTime := time.Duration(cfg.ConnMaxIdleTimeMin) * time.Minute
		if idleTime <= 0 {
			idleTime = 3 * time.Minute
		}

		sqlDB.SetMaxOpenConns(maxOpen)
		sqlDB.SetMaxIdleConns(maxIdle)
		sqlDB.SetConnMaxLifetime(lifetime)
		sqlDB.SetConnMaxIdleTime(idleTime)

		logger.Info("Database connection pool configured",
			"max_open", maxOpen,
			"max_idle", maxIdle,
			"max_lifetime", lifetime.String(),
			"max_idle_time", idleTime.String(),
		)
	}
}
