package database

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/pkg/logger"
	"server/pkg/password"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

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
	/* 迁移模型列表 */
	migrationModels := []any{
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
	}

	/* 计算 model 结构体指纹，仅在 schema 变化时执行迁移 */
	if needsMigration(DB, migrationModels) {
		logger.Info("Database migrating...")
		if err := DB.AutoMigrate(migrationModels...); err != nil {
			return fmt.Errorf("failed to migrate database: %w", err)
		}
		saveMigrationHash(DB, migrationModels)
		logger.Info("Database migration completed")
	} else {
		logger.Debug("Database schema unchanged, migration skipped")
	}

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

/* hashPassword 统一使用 password 包生成哈希，确保 bcrypt cost 与全局一致 */
func hashPassword(pwd string) (string, error) {
	return password.Hash(pwd)
}

/*
 * computeModelHash 计算所有迁移 model 的结构体指纹
 * 功能：基于 model 类型名和字段列表生成 SHA256 哈希，用于检测 schema 是否变化
 */
func computeModelHash(models []any) string {
	h := sha256.New()
	for _, m := range models {
		t := reflect.TypeOf(m)
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		h.Write([]byte(t.Name()))
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			h.Write([]byte(f.Name + ":" + f.Type.String() + ":" + string(f.Tag)))
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

/*
 * needsMigration 检查是否需要执行数据库迁移
 * 功能：对比 system_configs 表中存储的上次迁移哈希与当前 model 哈希
 *       首次运行或哈希不匹配时返回 true
 */
func needsMigration(db *gorm.DB, models []any) bool {
	currentHash := computeModelHash(models)
	var stored string
	/* system_configs 表可能尚不存在（首次启动），此时必须迁移 */
	err := db.Raw("SELECT value FROM system_configs WHERE key = ?", "_migration_hash").Scan(&stored).Error
	if err != nil || stored != currentHash {
		return true
	}
	return false
}

/*
 * saveMigrationHash 保存迁移哈希到 system_configs 表
 * 功能：迁移完成后记录当前 model 哈希，下次启动时用于跳过判断
 */
func saveMigrationHash(db *gorm.DB, models []any) {
	hash := computeModelHash(models)
	db.Exec("INSERT INTO system_configs (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
		"_migration_hash", hash, hash)
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
	case "postgres", "mysql":
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
