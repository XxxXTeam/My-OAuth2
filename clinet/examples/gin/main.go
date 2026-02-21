/*
 * Gin 框架集成示例
 * 功能：演示 Gin 框架集成 OAuth2 认证
 *       - Authorization Code + PKCE 登录流程
 *       - Gin 中间件保护 API 路由
 *       - 用户信息获取 / Token 刷新
 * 启动：go run main.go
 * 访问：http://localhost:9000
 */
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"client/oauth2"

	"github.com/gin-gonic/gin"
)

func main() {
	// ========================================
	// 1. 配置 OAuth2 客户端
	// ========================================
	config := oauth2.DefaultConfig(
		"your-client-id",     // 替换为你的 Client ID
		"your-client-secret", // 替换为你的 Client Secret
		"http://localhost:9000/callback",
	)

	client, err := oauth2.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// ========================================
	// 2. 设置 Gin 路由
	// ========================================
	r := gin.Default()

	// ---------- 首页 ----------
	r.GET("/", func(c *gin.Context) {
		token, _ := client.GetToken(context.Background())
		isLoggedIn := token != nil && token.IsValid()

		var html string
		if isLoggedIn {
			html = `<!DOCTYPE html>
<html><head><title>OAuth2 Gin 示例</title>
<style>body{font-family:system-ui;max-width:600px;margin:40px auto;padding:0 20px}
.btn{display:inline-block;padding:10px 20px;border-radius:8px;text-decoration:none;color:white;margin:4px}
.btn-blue{background:#3b82f6}.btn-red{background:#ef4444}.btn-green{background:#22c55e}
.card{background:#f8fafc;border-radius:12px;padding:24px;margin:16px 0}</style></head>
<body><h1>🔐 OAuth2 Gin 示例</h1>
<div class="card"><p style="color:#22c55e">✓ 已登录</p>
<a href="/api/profile" class="btn btn-green">查看个人信息</a>
<a href="/api/data" class="btn btn-blue">访问受保护数据</a>
<a href="/refresh" class="btn btn-blue">刷新 Token</a>
<a href="/logout" class="btn btn-red">退出登录</a>
</div></body></html>`
		} else {
			html = `<!DOCTYPE html>
<html><head><title>OAuth2 Gin 示例</title>
<style>body{font-family:system-ui;max-width:600px;margin:40px auto;padding:0 20px}
.btn{display:inline-block;padding:12px 24px;background:#3b82f6;color:white;border-radius:8px;text-decoration:none}
.card{background:#f8fafc;border-radius:12px;padding:24px;margin:16px 0}</style></head>
<body><h1>🔐 OAuth2 Gin 示例</h1>
<div class="card"><p>点击下方按钮通过 OAuth2 授权登录</p>
<a href="/login" class="btn">使用 OAuth2 登录</a>
</div></body></html>`
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
	})

	// ---------- 登录：重定向到 OAuth2 授权页 ----------
	r.GET("/login", func(c *gin.Context) {
		authURL, err := client.AuthCodeURL()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		log.Printf("[LOGIN] 重定向到: %s", authURL)
		c.Redirect(http.StatusFound, authURL)
	})

	// ---------- OAuth2 回调 ----------
	r.GET("/callback", func(c *gin.Context) {
		code := c.Query("code")
		state := c.Query("state")

		if errParam := c.Query("error"); errParam != "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":       errParam,
				"description": c.Query("error_description"),
			})
			return
		}

		if code == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
			return
		}

		// 用授权码换取 Token
		token, err := client.Exchange(c.Request.Context(), code, state)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		log.Printf("[CALLBACK] 获取 Token 成功, 过期: %s", token.Expiry)

		// 实际项目中应将 token 存入 session/cookie
		c.Redirect(http.StatusFound, "/")
	})

	// ---------- 刷新 Token ----------
	r.GET("/refresh", func(c *gin.Context) {
		newToken, err := client.RefreshToken(context.Background())
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("刷新失败: %v", err)})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message":    "Token 刷新成功",
			"expires_at": newToken.Expiry,
		})
	})

	// ---------- 退出登录 ----------
	r.GET("/logout", func(c *gin.Context) {
		client.Logout()
		c.Redirect(http.StatusFound, "/")
	})

	// ========================================
	// 3. 受保护的 API 路由（需要 Bearer Token）
	// ========================================
	api := r.Group("/api")
	api.Use(client.GinMiddleware())
	{
		// 获取当前用户信息
		api.GET("/profile", func(c *gin.Context) {
			userInfo := oauth2.GinUserInfo(c)
			if userInfo == nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "no user info"})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"id":       userInfo.Sub,
				"email":    userInfo.Email,
				"name":     userInfo.Name,
				"username": userInfo.PreferredUsername,
				"picture":  userInfo.Picture,
			})
		})

		// 受保护的数据接口
		api.GET("/data", func(c *gin.Context) {
			token := oauth2.GinToken(c)
			c.JSON(http.StatusOK, gin.H{
				"message": "这是受保护的数据",
				"token":   token.AccessToken[:min(10, len(token.AccessToken))] + "...",
			})
		})
	}

	// ========================================
	// 4. 启动服务器
	// ========================================
	fmt.Println("╔════════════════════════════════════════╗")
	fmt.Println("║   Gin OAuth2 示例                      ║")
	fmt.Println("║   http://localhost:9000                 ║")
	fmt.Println("╚════════════════════════════════════════╝")
	r.Run(":9000")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
