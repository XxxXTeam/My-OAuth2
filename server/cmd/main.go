/*
 * OAuth2 Authorization Server 入口
 * 功能：配置加载 → 日志初始化 → 数据库初始化 → 缓存初始化 → 路由注册 → HTTP 服务启动 → 优雅关停
 * 许可证：GNU General Public License v3.0
 */
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"server/internal/config"
	"server/internal/database"
	"server/internal/repository"
	"server/internal/router"
	"server/internal/service"
	"server/pkg/cache"
	"server/pkg/logger"

	"github.com/gin-gonic/gin"
)

/* version 服务器版本号 */
const version = "1.0.0"

/* ANSI 终端颜色码 */
const (
	colorReset   = "\033[0m"
	colorCyan    = "\033[36m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorGray    = "\033[90m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
)

/*
 * 构建时通过 ldflags 注入，例如：
 * go build -ldflags "-X main.buildID=abc123 -X main.buildTime=2025-01-01T00:00:00Z"
 */
var (
	buildID   = "dev"
	buildTime = "unknown"
)

/* printBanner 输出启动 Banner（ASCII Art + 版本信息） */
func printBanner() {
	fmt.Println()
	fmt.Printf("%s%s   ____  ___        __  __   ___  %s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s  / __ \\/ _ | __ __/ /_/ /  |_  | %s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s / /_/ / __ |/ // / __/ _ \\/ __/  %s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s \\____/_/ |_|\\_,_/\\__/_//_/____/  %s\n", colorBold, colorCyan, colorReset)
	fmt.Println()
	fmt.Printf("%s%s OAuth2 Authorization Server%s %sv%s%s\n", colorBold, colorGray, colorReset, colorGreen, version, colorReset)
	fmt.Printf("%s Go %s • %s/%s • Build %s%s\n", colorDim, runtime.Version()[2:], runtime.GOOS, runtime.GOARCH, buildID, colorReset)
	fmt.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorDim, colorGray, colorReset)
	fmt.Println()
}

/* GetBuildID 返回构建 ID，供其他包使用 */
func GetBuildID() string   { return buildID }
func GetBuildTime() string { return buildTime }

/* parseLogLevel 将配置字符串转为日志级别 */
func parseLogLevel(level string) logger.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// printInitStep 输出初始化步骤（美化格式）
func printInitStep(icon, name, detail string) {
	fmt.Printf("  %s%s%s %s%s%s %s%s%s\n", colorGreen, icon, colorReset, colorBold, name, colorReset, colorGray, detail, colorReset)
}

// printInitError 输出初始化错误
func printInitError(name string, err error) {
	fmt.Printf("  %s✗%s %s%s%s %s%v%s\n", "\033[31m", colorReset, colorBold, name, colorReset, "\033[31m", err, colorReset)
}

func main() {
	startTime := time.Now()

	printBanner()

	// 先用默认配置初始化日志，以便加载配置时能记录日志
	if err := logger.Init(logger.DefaultConfig()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	mode := os.Getenv("GIN_MODE")
	if mode == "" {
		mode = gin.ReleaseMode
	}
	gin.SetMode(mode)

	fmt.Printf("%s%s Initializing components...%s\n\n", colorBold, colorBlue, colorReset)

	// 加载配置
	cfg := config.Load()
	printInitStep("✓", "Config", "loaded from data/config.json")

	// 根据配置文件重新初始化日志系统
	logCfg := &logger.Config{
		Level:       parseLogLevel(cfg.Log.Level),
		Format:      cfg.Log.Format,
		Output:      "stdout",
		AddSource:   true,
		TimeFormat:  "2006-01-02 15:04:05",
		FileOutput:  cfg.Log.FileOutput,
		MaxSizeMB:   cfg.Log.MaxSizeMB,
		MaxBackups:  cfg.Log.MaxBackups,
		MaxAgeDays:  cfg.Log.MaxAgeDays,
		CompressOld: cfg.Log.Compress,
	}
	if err := logger.ReInit(logCfg); err != nil {
		printInitError("Logger", err)
	} else {
		logDetail := fmt.Sprintf("level=%s format=%s", cfg.Log.Level, cfg.Log.Format)
		if cfg.Log.FileOutput != "" {
			logDetail += " file=" + cfg.Log.FileOutput
		}
		printInitStep("✓", "Logger", logDetail)
	}

	/* 校验配置合法性 */
	if errs := cfg.Validate(); len(errs) > 0 {
		fmt.Printf("\n%s%s ✗ Configuration validation failed:%s\n", colorBold, "\033[31m", colorReset)
		for _, e := range errs {
			fmt.Printf("   %s• %s%s\n", "\033[31m", e, colorReset)
		}
		fmt.Println()
		os.Exit(1)
	}

	// 初始化数据库
	if err := database.Init(&cfg.Database); err != nil {
		printInitError("Database", err)
		os.Exit(1)
	}
	printInitStep("✓", "Database", fmt.Sprintf("driver=%s", cfg.Database.Driver))

	// 初始化缓存
	ttl := time.Duration(cfg.Cache.DefaultTTLSec) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	cacheInstance, err := cache.New(&cache.Config{
		Driver:           cfg.Cache.Driver,
		RedisURL:         cfg.Cache.RedisURL,
		MemcachedServers: cfg.Cache.MemcachedServers,
		BadgerPath:       cfg.Cache.BadgerPath,
		FileDir:          cfg.Cache.FileDir,
		Prefix:           cfg.Cache.Prefix,
		DefaultTTL:       ttl,
	})
	cacheDriver := cfg.Cache.Driver
	if err != nil {
		cacheInstance = cache.NewMemoryCache(ttl)
		cacheDriver = "memory (fallback)"
	}
	printInitStep("✓", "Cache", fmt.Sprintf("driver=%s ttl=%ds", cacheDriver, cfg.Cache.DefaultTTLSec))

	// 设置路由
	router.SetBuildInfo(buildID)
	r := router.Setup(cfg, cacheInstance)
	printInitStep("✓", "Router", "routes registered")

	// Webhook background retry worker
	webhookRepo := repository.NewWebhookRepository(database.GetDB())
	webhookSvc := service.NewWebhookService(webhookRepo)
	webhookCtx, webhookCancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-webhookCtx.Done():
				return
			case <-ticker.C:
				if err := webhookSvc.ProcessPendingDeliveries(webhookCtx); err != nil {
					logger.Warn("Webhook retry worker error", "error", err)
				}
			}
		}
	}()
	printInitStep("✓", "Webhook", "background retry worker started")

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	startupDuration := time.Since(startTime)
	srv := &http.Server{
		Addr:              addr,
		Handler:           r.Handler(),
		ReadHeaderTimeout: 10 * time.Second, /* 防止 Slowloris 攻击 */
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, /* 1MB */
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	// 输出启动成功信息
	fmt.Println()
	fmt.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorDim, colorGray, colorReset)
	fmt.Printf("%s%s 🚀 Server started successfully!%s\n", colorBold, colorGreen, colorReset)
	fmt.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorDim, colorGray, colorReset)
	fmt.Println()
	fmt.Printf("  %s➜%s  %sLocal:%s   %shttp://localhost:%d%s\n", colorGreen, colorReset, colorGray, colorReset, colorCyan, cfg.Server.Port, colorReset)
	if cfg.Server.Host != "localhost" && cfg.Server.Host != "127.0.0.1" {
		fmt.Printf("  %s➜%s  %sNetwork:%s %shttp://%s%s\n", colorGreen, colorReset, colorGray, colorReset, colorCyan, addr, colorReset)
	}
	fmt.Println()
	fmt.Printf("  %sStartup: %s%dms%s  |  Build: %s%s%s  |  Mode: %s%s%s\n",
		colorGray, colorYellow, startupDuration.Milliseconds(), colorGray,
		colorYellow, buildID, colorGray,
		colorYellow, mode, colorReset)
	fmt.Println()

	/* 等待中断信号 */
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	fmt.Println()
	fmt.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorDim, colorGray, colorReset)
	fmt.Printf("%s%s ⏳ Shutting down...%s %s(signal: %s)%s\n", colorBold, colorYellow, colorReset, colorGray, sig.String(), colorReset)
	fmt.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorDim, colorGray, colorReset)
	fmt.Println()

	/* 优雅关停：从配置读取超时时间 */
	shutdownStart := time.Now()
	shutdownTimeout := time.Duration(cfg.Server.ShutdownTimeoutSec) * time.Second
	if shutdownTimeout <= 0 {
		shutdownTimeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		printInitError("HTTP Server", err)
	} else {
		printInitStep("✓", "HTTP Server", "stopped")
	}

	/* 停止 Webhook 后台重试 */
	webhookCancel()
	printInitStep("✓", "Webhook", "retry worker stopped")

	/* 关闭缓存 */
	if cacheInstance != nil {
		_ = cacheInstance.Close()
		printInitStep("✓", "Cache", "closed")
	}

	/* 关闭数据库连接 */
	if sqlDB, err := database.GetDB().DB(); err == nil {
		_ = sqlDB.Close()
		printInitStep("✓", "Database", "closed")
	}

	/* 关闭 logger 文件句柄 */
	logger.Default().Close()

	fmt.Println()
	fmt.Printf("  %s✓%s %s%sServer exited gracefully%s %s(%dms)%s\n",
		colorGreen, colorReset,
		colorBold, colorGreen, colorReset,
		colorGray, time.Since(shutdownStart).Milliseconds(), colorReset)
	fmt.Println()
}
