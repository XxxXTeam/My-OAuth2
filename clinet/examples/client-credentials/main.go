/*
 * Client Credentials 示例
 * 功能：演示客户端凭据授权流程 (client_credentials grant)
 *       适用于后端服务间调用、定时任务、无用户参与的自动化流程
 * 特性：
 *   1. 基础用法 - 手动获取 Token
 *   2. Manager 模式 - 自动刷新 Token
 *   3. HTTP Client - 自动注入 Bearer Token
 * 用法：go run main.go
 * 环境变量：
 *   OAUTH_CLIENT_ID      客户端ID
 *   OAUTH_CLIENT_SECRET  客户端密钥
 *   OAUTH_SERVER_URL     服务器地址（默认 http://localhost:8080）
 */
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"client/oauth2"
)

func main() {
	// 读取配置
	serverURL := getEnv("OAUTH_SERVER_URL", "http://localhost:8080")

	config := &oauth2.Config{
		ClientID:     getEnv("OAUTH_CLIENT_ID", "your-client-id"),
		ClientSecret: getEnv("OAUTH_CLIENT_SECRET", "your-client-secret"),
		AuthURL:      serverURL + "/oauth/authorize",
		TokenURL:     serverURL + "/oauth/token",
		UserInfoURL:  serverURL + "/oauth/userinfo",
		RedirectURL:  "http://localhost:9000/callback", // Client Credentials 不需要，但 Config 校验要求
		UsePKCE:      false,
	}

	client, err := oauth2.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║     Client Credentials 客户端凭据示例            ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")

	ctx := context.Background()

	// ========================================
	// 示例 1: 基础用法 - 手动获取 Token
	// ========================================
	fmt.Println("\n━━━ 示例 1: 基础用法 ━━━")

	resp, err := client.ClientCredentials(ctx, &oauth2.ClientCredentialsRequest{
		Scope: "openid profile",
	})
	if err != nil {
		fmt.Printf("❌ 获取 Token 失败: %v\n", err)
		return
	}

	fmt.Println("✅ Token 获取成功!")
	fmt.Printf("   Access Token: %s...\n", resp.AccessToken[:min(20, len(resp.AccessToken))])
	fmt.Printf("   Token Type:   %s\n", resp.TokenType)
	fmt.Printf("   Expires In:   %d 秒\n", resp.ExpiresIn)
	fmt.Printf("   Scope:        %s\n", resp.Scope)

	// ========================================
	// 示例 2: Manager 模式 - 自动管理 Token 生命周期
	// ========================================
	fmt.Println("\n━━━ 示例 2: Manager 自动刷新 ━━━")
	fmt.Println("ClientCredentialsManager 会在 Token 过期前自动重新获取")

	manager := client.NewClientCredentialsManager("openid profile")

	// 模拟多次调用，Manager 会自动缓存和刷新
	for i := 1; i <= 3; i++ {
		token, err := manager.GetToken(ctx)
		if err != nil {
			fmt.Printf("   第 %d 次获取失败: %v\n", i, err)
			continue
		}
		fmt.Printf("   第 %d 次: Token = %s... (来自缓存: %v)\n",
			i, token[:min(16, len(token))], i > 1)
		time.Sleep(100 * time.Millisecond)
	}

	// ========================================
	// 示例 3: 自动注入 Token 的 HTTP Client
	// ========================================
	fmt.Println("\n━━━ 示例 3: 自动注入 Token 的 HTTP Client ━━━")
	fmt.Println("HTTPClient 会自动在每个请求中添加 Authorization: Bearer <token>")

	httpClient := manager.HTTPClient(ctx)

	// 使用自动注入 Token 的 HTTP Client 调用受保护的 API
	apiResp, err := httpClient.Get(serverURL + "/oauth/userinfo")
	if err != nil {
		fmt.Printf("   ❌ 请求失败: %v\n", err)
	} else {
		defer apiResp.Body.Close()
		body, _ := io.ReadAll(apiResp.Body)
		fmt.Printf("   HTTP %d: %s\n", apiResp.StatusCode, truncate(string(body), 80))
	}

	// ========================================
	// 示例 4: 实际场景 - 定时同步数据
	// ========================================
	fmt.Println("\n━━━ 示例 4: 模拟定时任务 ━━━")
	fmt.Println("模拟每隔几秒执行一次的定时任务，Token 由 Manager 自动管理")

	for i := 1; i <= 3; i++ {
		token, err := manager.GetToken(ctx)
		if err != nil {
			fmt.Printf("   [任务 %d] ❌ 获取 Token 失败: %v\n", i, err)
			continue
		}

		fmt.Printf("   [任务 %d] ✅ 使用 Token %s... 调用 API\n",
			i, token[:min(16, len(token))])

		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("✅ 所有示例执行完成")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
