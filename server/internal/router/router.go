package router

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"server/internal/config"
	"server/internal/database"
	"server/internal/handler"
	"server/internal/middleware"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"
	"server/pkg/cache"
	"server/pkg/email"
	"server/pkg/jwt"
	"server/pkg/logger"
	"server/web"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var buildID = "dev"

func SetBuildInfo(id string) {
	if id != "" {
		buildID = id
	}
}

func Setup(cfg *config.Config, cacheInstance cache.Cache) *gin.Engine {
	// Set gin mode
	gin.SetMode(cfg.Server.Mode)

	r := gin.New()

	// Disable automatic redirect for trailing slashes (prevents redirect loops with SPA)
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false

	/* 全局中间件 */
	r.Use(middleware.TraceID())
	r.Use(middleware.RecoveryWithLogger())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.RequestSizeLimit(10 << 20))
	r.Use(middleware.RequestLogger())
	r.Use(middleware.Timeout(30 * time.Second))             /* 请求超时 30 秒 */
	r.Use(middleware.CORSWithConfig(cfg.OAuth.FrontendURL)) /* CORS 允许前端 origin */

	// Initialize dependencies
	db := database.GetDB()
	jwtManager := jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Issuer)

	// Repositories
	userRepo := repository.NewUserRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	configRepo := repository.NewConfigRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	userAuthRepo := repository.NewUserAuthorizationRepository(db)
	webhookRepo := repository.NewWebhookRepository(db)
	passwordResetRepo := repository.NewPasswordResetRepository(db)
	federationRepo := repository.NewFederationRepository(db)
	// 缓存包装的 Federation Repository（支持 memory / redis 后端，减少 ListProviders 热路径 DB 查询）
	cachedFederationRepo := repository.NewCachedFederationRepository(federationRepo, cacheInstance)
	deviceCodeRepo := repository.NewDeviceCodeRepository(db)
	emailVerifyRepo := repository.NewEmailVerificationRepository(db)

	// Services
	authService := service.NewAuthService(userRepo, loginLogRepo, jwtManager, cfg)
	authService.SetOAuthRepo(oauthRepo) // 启用 refresh token 轮换
	appService := service.NewApplicationService(appRepo)
	oauthService := service.NewOAuthService(appRepo, oauthRepo, userRepo, userAuthRepo, cfg)
	oauthService.SetDeviceCodeRepository(deviceCodeRepo) // Enable device flow
	webhookService := service.NewWebhookService(webhookRepo)
	passwordResetService := service.NewPasswordResetService(userRepo, passwordResetRepo)
	emailVerifyService := service.NewEmailVerificationService(userRepo, emailVerifyRepo)
	socialAuthService := service.NewSocialAuthService(userRepo, federationRepo, loginLogRepo, jwtManager, cfg)
	socialAuthService.SetOAuthRepo(oauthRepo) // 启用 refresh token 轮换
	_ = cachedFederationRepo                  // 缓存 repo 已注册，可用于将来扩展

	// Get frontend URL from config or use default
	frontendURL := cfg.OAuth.FrontendURL
	if url, err := configRepo.Get("frontend_url"); err == nil && url != "" {
		frontendURL = url
	}

	// Handlers
	authHandler := handler.NewAuthHandler(authService, cfg)
	authHandler.SetWebhookService(webhookService)
	passwordResetHandler := handler.NewPasswordResetHandler(passwordResetService)
	socialAuthHandler := handler.NewSocialAuthHandler(socialAuthService)
	userHandler := handler.NewUserHandler(authService, userRepo, userAuthRepo)
	userHandler.SetWebhookService(webhookService)
	userHandler.SetOAuthRepo(oauthRepo, appRepo)
	appHandler := handler.NewApplicationHandler(appService)
	oauthHandler := handler.NewOAuthHandler(oauthService, webhookService, frontendURL)
	adminHandler := handler.NewAdminHandler(userRepo, appRepo, loginLogRepo, userAuthRepo)
	sdkHandler := handler.NewSDKHandler(authService, appRepo, jwtManager)
	sdkHandler.SetWebhookService(webhookService)
	sseHandler := handler.NewSSEHandler()
	configHandler := handler.NewConfigHandler(configRepo, cfg)
	webhookHandler := handler.NewWebhookHandler(webhookService)
	oidcHandler := handler.NewOIDCHandler(cfg.JWT.Issuer)
	baseURL := fmt.Sprintf("http://%s:%d", cfg.Server.Host, cfg.Server.Port)
	deviceHandler := handler.NewDeviceHandler(deviceCodeRepo, appRepo, baseURL, frontendURL)
	oidcHandler.SetOAuthRepo(oauthRepo, jwtManager) // 设置OAuth仓库用于token撤销
	avatarHandler := handler.NewAvatarHandler(userRepo, "./uploads/avatars", "/avatars")
	systemConfigHandler := handler.NewSystemConfigHandler(cfg)
	federationHandler := handler.NewFederationHandler(federationRepo, userRepo, jwtManager, baseURL)
	federationHandler.SetOAuthRepo(oauthRepo) // 启用 refresh token 轮换

	// 初始化邮件服务
	var emailService *email.Service
	emailCfg := &email.Config{
		Host:     cfg.Email.Host,
		Port:     cfg.Email.Port,
		Username: cfg.Email.Username,
		Password: cfg.Email.Password,
		From:     cfg.Email.From,
		FromName: cfg.Email.FromName,
		UseTLS:   cfg.Email.UseTLS,
	}
	emailService = email.NewService(emailCfg)

	// 从 DB 加载自定义邮件模板
	loadCustomEmailTemplates(emailService, configRepo)

	// 设置公共模板变量
	siteName := "OAuth2"
	if sn, err := configRepo.Get("site_name"); err == nil && sn != "" {
		siteName = sn
	}
	emailService.SetCommonData(siteName, frontendURL)

	// 邮件队列服务（所有邮件发送通过队列异步处理）
	emailTaskRepo := repository.NewEmailTaskRepository(db)
	emailQueueService := service.NewEmailQueueService(emailTaskRepo, emailService, logger.Default())
	emailQueueService.Start()

	// 注入邮件队列到各服务（无论是否配置 SMTP，队列始终可用，任务会等待配置完成后发送）
	passwordResetService.SetOAuthRepo(oauthRepo)
	passwordResetService.SetEmailQueue(emailQueueService, frontendURL)
	emailVerifyService.SetEmailQueue(emailQueueService, frontendURL)
	if cfg.Email.Host != "" {
		adminHandler.SetEmailService(emailService)
	}
	adminHandler.SetPasswordResetService(passwordResetService)
	userHandler.SetEmailVerificationService(emailVerifyService)

	// 邮件管理 handler
	emailAdminHandler := handler.NewEmailAdminHandler(emailService, configRepo, cfg)

	// Public routes
	api := r.Group("/api")
	{
		auth := api.Group("/auth")
		auth.Use(middleware.AuthRateLimiter()) // 认证相关接口使用严格限流
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.Refresh)
			auth.POST("/logout", authHandler.Logout)
			auth.POST("/forgot-password", passwordResetHandler.ForgotPassword)
			auth.POST("/validate-reset-token", passwordResetHandler.ValidateResetToken)
			auth.POST("/reset-password", passwordResetHandler.ResetPassword)
			auth.GET("/social/providers", socialAuthHandler.GetProviders)
			auth.GET("/social/:provider", socialAuthHandler.StartAuth)
			auth.GET("/social/:provider/callback", socialAuthHandler.Callback)
		}
		sdk := api.Group("/sdk")
		{
			sdk.POST("/register", sdkHandler.Register)
			sdk.POST("/login", sdkHandler.Login)
			sdk.POST("/refresh", sdkHandler.RefreshToken)
			sdk.POST("/verify", sdkHandler.VerifyToken)

			// 用户同步 API
			sdk.POST("/sync/user", sdkHandler.SyncUser)
			sdk.POST("/sync/batch", sdkHandler.BatchSync)
			sdk.POST("/user", sdkHandler.GetUser)
		}
	}
	r.GET("/.well-known/openid-configuration", oidcHandler.Discovery)
	r.GET("/.well-known/jwks.json", oidcHandler.JWKS)
	r.GET("/.well-known/webfinger", oidcHandler.WebFinger)
	oauth := r.Group("/oauth")
	{
		oauth.POST("/token", oauthHandler.Token)
		oauth.POST("/revoke", oauthHandler.Revoke)
		oauth.GET("/userinfo", oauthHandler.UserInfo)
		oauth.POST("/introspect", oauthHandler.Introspect) // Token introspection
		oauth.GET("/logout", oidcHandler.Logout)           // OIDC logout
		oauth.POST("/logout", oidcHandler.Logout)
		// Device Flow (RFC 8628)
		oauth.POST("/device/code", deviceHandler.DeviceAuthorization)
		if !oauthHandler.IsEmbeddedFrontend() {
			oauth.GET("/authorize", oauthHandler.Authorize)
		}
	}
	oauthAPI := r.Group("/api/oauth")
	{
		oauthAPI.GET("/app-info", oauthHandler.GetAppInfo)
		// Device Flow info (public)
		oauthAPI.GET("/device/info", deviceHandler.GetDeviceInfo)
	}

	// OAuth2 authorize submission (requires auth)
	oauthAPIAuth := r.Group("/api/oauth")
	oauthAPIAuth.Use(middleware.Auth(jwtManager))
	{
		oauthAPIAuth.POST("/authorize", oauthHandler.AuthorizeSubmit)
		// Device Flow authorization (requires auth)
		oauthAPIAuth.POST("/device/authorize", deviceHandler.DeviceAuthorizeSubmit)
	}

	// Protected routes
	protected := r.Group("/api")
	protected.Use(middleware.Auth(jwtManager))
	{
		user := protected.Group("/user")
		{
			user.GET("/profile", userHandler.GetProfile)
			user.POST("/profile", userHandler.UpdateProfile)
			user.POST("/password", userHandler.ChangePassword)
			user.GET("/authorizations", userHandler.GetAuthorizations)
			user.POST("/authorizations/:id/revoke", userHandler.RevokeAuthorization)
			user.POST("/avatar", avatarHandler.Upload)
			user.POST("/avatar/delete", avatarHandler.Delete)

			// 邮箱验证
			user.POST("/email/send-verify", userHandler.SendEmailVerification)
			user.POST("/email/verify", userHandler.VerifyEmail)
			user.POST("/email/change", userHandler.RequestEmailChange)

			// 社交账号关联
			user.GET("/social/linked", socialAuthHandler.GetLinkedAccounts)
			user.POST("/social/:provider/link", socialAuthHandler.LinkAccount)
			user.POST("/social/:provider/unlink", socialAuthHandler.UnlinkAccount)
		}

		/* 应用管理路由 - 仅管理员可用，普通用户只能管理个人信息 */
		apps := protected.Group("/apps")
		apps.Use(middleware.AdminOnly())
		{
			apps.GET("", appHandler.ListApps)
			apps.POST("", appHandler.CreateApp)
			apps.GET("/:id", appHandler.GetApp)
			apps.POST("/:id", appHandler.UpdateApp)
			apps.POST("/:id/delete", appHandler.DeleteApp)
			apps.POST("/:id/reset-secret", appHandler.ResetSecret)
			apps.GET("/:id/stats", appHandler.GetAppStats)

			// Webhook routes
			apps.GET("/:id/webhooks", webhookHandler.ListWebhooks)
			apps.POST("/:id/webhooks", webhookHandler.CreateWebhook)
			apps.POST("/:id/webhooks/:webhook_id", webhookHandler.UpdateWebhook)
			apps.POST("/:id/webhooks/:webhook_id/delete", webhookHandler.DeleteWebhook)
			apps.GET("/:id/webhooks/:webhook_id/deliveries", webhookHandler.ListDeliveries)
			apps.POST("/:id/webhooks/:webhook_id/test", webhookHandler.TestWebhook)
		}
	}

	// Admin routes (requires admin role)
	admin := r.Group("/api/admin")
	admin.Use(middleware.Auth(jwtManager), middleware.AdminOnly())
	{
		admin.GET("/stats", adminHandler.GetStats)
		admin.GET("/stats/login-trend", adminHandler.GetLoginTrend)
		admin.GET("/login-logs", adminHandler.GetLoginLogs)

		admin.GET("/users", adminHandler.ListUsers)
		admin.GET("/users/:id", adminHandler.GetUser)
		admin.POST("/users/:id/role", adminHandler.UpdateUserRole)
		admin.POST("/users/:id/status", adminHandler.UpdateUserStatus)
		admin.POST("/users/:id/reset-password", adminHandler.ResetUserPassword)
		admin.POST("/users/:id/delete", adminHandler.DeleteUser)
		// Batch operations
		admin.POST("/users/batch/status", adminHandler.BatchUpdateStatus)
		admin.POST("/users/batch/delete", adminHandler.BatchDeleteUsers)
		admin.GET("/users/export", adminHandler.ExportUsers)
		admin.POST("/users/import", adminHandler.ImportUsers)

		admin.GET("/users/search", adminHandler.SearchUsers)
		admin.GET("/users/:id/authorizations", adminHandler.GetUserAuthorizations)
		admin.POST("/users/:id/authorizations/:auth_id/revoke", adminHandler.RevokeUserAuthorization)

		admin.GET("/apps", adminHandler.ListAllApps)
		admin.GET("/apps/:id/stats", adminHandler.GetAppStats)
		admin.GET("/apps/:id/users", adminHandler.GetAppAuthorizedUsers)
		admin.POST("/apps/:id/authorizations/revoke", adminHandler.RevokeAppAuthorizations)

		// Batch authorization operations
		admin.POST("/authorizations/batch/revoke", adminHandler.BatchRevokeAuthorizations)

		// Config management
		admin.GET("/config", configHandler.GetAllConfig)
		admin.GET("/config/:key", configHandler.GetConfig)
		admin.POST("/config/:key", configHandler.SetConfig)
		admin.POST("/config", configHandler.SetConfigs)
		admin.POST("/config/:key/delete", configHandler.DeleteConfig)

		// User create & update
		admin.POST("/users", adminHandler.CreateUser)
		admin.POST("/users/:id/update", adminHandler.UpdateUser)
		admin.POST("/users/:id/send-reset-email", adminHandler.SendResetEmail)

		// Email management
		admin.GET("/email/config", emailAdminHandler.GetEmailConfig)
		admin.POST("/email/config", emailAdminHandler.UpdateEmailConfig)
		admin.POST("/email/test-connection", emailAdminHandler.TestConnection)
		admin.POST("/email/test", emailAdminHandler.SendTestEmail)
		admin.GET("/email/templates", emailAdminHandler.ListTemplates)
		admin.GET("/email/templates/:name", emailAdminHandler.GetTemplate)
		admin.POST("/email/templates/:name", emailAdminHandler.UpdateTemplate)
		admin.POST("/email/templates/:name/reset", emailAdminHandler.ResetTemplate)

		// System config management
		admin.GET("/system/config", systemConfigHandler.GetConfig)
		admin.POST("/system/config", systemConfigHandler.UpdateConfig)
		admin.POST("/system/regenerate-jwt-secret", systemConfigHandler.RegenerateJWTSecret)
	}

	/* 联邦登录路由 - 支持第三方 OAuth 一键接入 */
	federation := r.Group("/api/federation")
	{
		federation.GET("/providers", federationHandler.ListProviders)
		federation.GET("/login/:slug", federationHandler.InitiateLogin)
		federation.GET("/callback/:slug", federationHandler.Callback)
		federation.POST("/verify", federationHandler.VerifyToken)
	}

	/* 管理员联邦提供商管理路由 */
	adminFederation := r.Group("/api/admin/federation")
	adminFederation.Use(middleware.Auth(jwtManager), middleware.AdminOnly())
	{
		adminFederation.GET("/providers", federationHandler.AdminListProviders)
		adminFederation.POST("/providers", federationHandler.AdminCreateProvider)
		adminFederation.POST("/providers/:id", federationHandler.AdminUpdateProvider)
		adminFederation.POST("/providers/:id/delete", federationHandler.AdminDeleteProvider)
	}

	// Public config endpoint
	r.GET("/api/config", configHandler.GetPublicConfig)

	/* 构建信息端点（公开，前端用于显示版本） */
	r.GET("/api/build-info", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"version":    "1.0.0",
			"build_id":   buildID,
			"go_version": runtime.Version(),
		})
	})

	// Token signing endpoint (for apps to sign custom tokens)
	r.POST("/token/sign", sdkHandler.SignToken)

	/* SSE 事件流 - 使用 Cookie 鉴权（EventSource 自动携带 Cookie，无需查询字符串传递 token） */
	events := r.Group("/api/events")
	{
		events.GET("/app", sseHandler.StreamApp)
		events.GET("/stream", middleware.Auth(jwtManager), sseHandler.Stream)
	}

	// Avatar file serving
	r.GET("/avatars/:filename", avatarHandler.ServeAvatar)

	/* 健康检查 - 含数据库连通性、连接池状态和运行时指标 */
	serverStartTime := time.Now()
	r.GET("/health", func(c *gin.Context) {
		status := "ok"
		dbInfo := gin.H{"status": "ok"}

		if sqlDB, err := database.GetDB().DB(); err != nil {
			dbInfo["status"] = "error: " + err.Error()
			status = "degraded"
		} else {
			/* 测量 DB ping 延迟 */
			pingStart := time.Now()
			if err := sqlDB.Ping(); err != nil {
				dbInfo["status"] = "error: " + err.Error()
				status = "degraded"
			} else {
				dbInfo["ping_ms"] = fmt.Sprintf("%.2f", float64(time.Since(pingStart).Microseconds())/1000)
			}
			/* 连接池统计 */
			stats := sqlDB.Stats()
			dbInfo["open_connections"] = stats.OpenConnections
			dbInfo["in_use"] = stats.InUse
			dbInfo["idle"] = stats.Idle
		}

		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		code := 200
		if status != "ok" {
			code = 503
		}

		c.JSON(code, gin.H{
			"status":     status,
			"db":         dbInfo,
			"goroutines": runtime.NumGoroutine(),
			"memory_mb":  fmt.Sprintf("%.1f", float64(mem.Alloc)/1024/1024),
			"uptime":     fmt.Sprintf("%s", time.Since(serverStartTime).Round(time.Second)),
			"build_id":   buildID,
		})
	})

	// Static files - serve embedded web frontend
	if web.HasStaticFiles() {
		staticHandler := handler.NewStaticHandler(web.GetFileSystem())

		// Serve static assets (js, css, images, etc.)
		r.GET("/assets/*filepath", func(c *gin.Context) {
			c.FileFromFS(c.Request.URL.Path, web.GetFileSystem())
		})
		r.GET("/_next/*filepath", func(c *gin.Context) {
			c.FileFromFS(c.Request.URL.Path, web.GetFileSystem())
		})
		r.GET("/favicon.ico", func(c *gin.Context) {
			c.FileFromFS("/favicon.ico", web.GetFileSystem())
		})

		// NoRoute handler for SPA routing
		r.NoRoute(func(c *gin.Context) {
			// Skip API routes
			path := c.Request.URL.Path
			if len(path) >= 4 && path[:4] == "/api" {
				c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
				return
			}
			// Skip OAuth endpoints except /oauth/authorize (which is handled by SPA when embedded)
			if len(path) >= 6 && path[:6] == "/oauth" {
				// Allow /oauth/authorize to be handled by SPA
				if path == "/oauth/authorize" || (len(path) > 17 && path[:17] == "/oauth/authorize?") {
					staticHandler.ServeFile(c)
					return
				}
				c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
				return
			}
			// Serve SPA
			staticHandler.ServeFile(c)
		})
	}

	return r
}

// loadCustomEmailTemplates 从数据库加载自定义邮件模板
func loadCustomEmailTemplates(emailService *email.Service, configRepo *repository.ConfigRepository) {
	configs, err := configRepo.GetAll()
	if err != nil {
		return
	}

	for key, value := range configs {
		if !strings.HasPrefix(key, model.EmailTemplateKeyPrefix) {
			continue
		}
		name := strings.TrimPrefix(key, model.EmailTemplateKeyPrefix)
		var tpl model.EmailTemplate
		if err := json.Unmarshal([]byte(value), &tpl); err != nil {
			logger.Warn("Failed to parse email template", "name", name, "error", err)
			continue
		}
		if tpl.Subject != "" && tpl.Body != "" {
			emailService.SetCustomTemplate(name, tpl.Subject, tpl.Body)
			logger.Info("Loaded custom email template", "name", name)
		}
	}
}
