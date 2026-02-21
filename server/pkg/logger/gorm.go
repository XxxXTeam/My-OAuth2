package logger

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

/*
 * GormLogger GORM 日志适配器
 * 功能：将 GORM 的 SQL 日志接入统一日志系统，支持慢查询检测和迁移查询过滤
 */
type GormLogger struct {
	logger        *Logger
	SlowThreshold time.Duration
	LogLevel      gormlogger.LogLevel
	Silent        bool
}

/*
 * NewGormLogger 创建 GORM 日志适配器
 * @param l      - 统一日志器实例
 * @param silent - 静默模式（仅输出 Warn 级别以上）
 */
func NewGormLogger(l *Logger, silent bool) *GormLogger {
	logLevel := gormlogger.Warn
	if !silent {
		logLevel = gormlogger.Info
	}
	return &GormLogger{
		logger:        l,
		SlowThreshold: 200 * time.Millisecond,
		LogLevel:      logLevel,
		Silent:        silent,
	}
}

func (g *GormLogger) LogMode(level gormlogger.LogLevel) gormlogger.Interface {
	newLogger := *g
	newLogger.LogLevel = level
	return &newLogger
}

func (g *GormLogger) Info(ctx context.Context, msg string, data ...interface{}) {
	if g.LogLevel >= gormlogger.Info {
		g.logger.Info(fmt.Sprintf(msg, data...))
	}
}

func (g *GormLogger) Warn(ctx context.Context, msg string, data ...interface{}) {
	if g.LogLevel >= gormlogger.Warn {
		g.logger.Warn(fmt.Sprintf(msg, data...))
	}
}

func (g *GormLogger) Error(ctx context.Context, msg string, data ...interface{}) {
	if g.LogLevel >= gormlogger.Error {
		g.logger.Error(fmt.Sprintf(msg, data...))
	}
}

func (g *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	if g.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()

	// Skip migration queries (they're noisy)
	if isMigrationQuery(sql) {
		return
	}

	switch {
	case err != nil && !errors.Is(err, gorm.ErrRecordNotFound):
		g.logger.Error("DB Error",
			"error", err.Error(),
			"elapsed", formatDuration(elapsed),
			"rows", rows,
		)
	case elapsed > g.SlowThreshold && g.SlowThreshold != 0:
		g.logger.Warn("Slow Query",
			"elapsed", formatDuration(elapsed),
			"rows", rows,
			"sql", truncateSQL(sql, 100),
		)
	case g.LogLevel >= gormlogger.Info:
		// Only log non-trivial queries
		if rows > 0 || elapsed > 10*time.Millisecond {
			g.logger.Debug("DB Query",
				"elapsed", formatDuration(elapsed),
				"rows", rows,
			)
		}
	}
}

/* isMigrationQuery 检查是否为迁移相关查询（自动过滤避免噪音） */
func isMigrationQuery(sql string) bool {
	migrationKeywords := []string{
		"sqlite_master",
		"ALTER TABLE",
		"CREATE TABLE",
		"CREATE INDEX",
		"CREATE UNIQUE INDEX",
		"information_schema",
		"pg_catalog",
	}
	for _, keyword := range migrationKeywords {
		if contains(sql, keyword) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

/* truncateSQL 截断过长的 SQL 语句用于日志输出 */
func truncateSQL(sql string, maxLen int) string {
	if len(sql) <= maxLen {
		return sql
	}
	return sql[:maxLen] + "..."
}

/* formatDuration 格式化耗时为可读字符串（µs/ms/s） */
func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fµs", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}
