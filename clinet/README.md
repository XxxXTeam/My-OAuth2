# OAuth2 Client SDK

Go语言 OAuth2 客户端 SDK，用于快速集成 OAuth2 认证，支持 SDK 接入实现跨系统账号互通。

## 功能特性

- 完整的 OAuth2 Authorization Code 流程
- PKCE 支持（增强安全性）
- Token 自动刷新
- 内置中间件支持（标准库 http、Gin、Echo）
- 可扩展的 Token 存储接口
- **SDK 接入** - 直接注册/登录用户，实现跨系统账号同步
- **Device Flow** - 设备授权流程 (RFC 8628)
- **Client Credentials** - 机器对机器认证，含自动刷新 Manager
- **Webhook 支持** - 接收实时事件通知
- **SSE 事件流** - 实时监听认证事件
- **自定义日志** - 可配置的日志接口

## 安装

```bash
go get github.com/your-org/oauth2-client
```

## 快速开始

### 基础使用

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "client/oauth2"
)

func main() {
    // 创建配置
    config := &oauth2.Config{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        AuthURL:      "http://localhost:3000/oauth/authorize",
        TokenURL:     "http://localhost:8080/oauth/token",
        UserInfoURL:  "http://localhost:8080/oauth/userinfo",
        RedirectURL:  "http://localhost:9000/callback",
        Scopes:       []string{"openid", "profile", "email"},
        UsePKCE:      true,
    }

    // 创建客户端
    client, err := oauth2.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }

    // 生成授权 URL
    authURL, err := client.AuthCodeURL()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Visit:", authURL)

    // 用户授权后，使用回调中的 code 和 state 交换 token
    // token, err := client.Exchange(ctx, code, state)

    // 获取用户信息
    // userInfo, err := client.GetUserInfo(ctx)
}
```

### Gin 中间件

```go
package main

import (
    "client/oauth2"
    "github.com/gin-gonic/gin"
)

func main() {
    config := oauth2.DefaultConfig(
        "your-client-id",
        "your-client-secret",
        "http://localhost:9000/callback",
    )

    client, _ := oauth2.NewClient(config)

    r := gin.Default()

    // 登录路由
    r.GET("/login", func(c *gin.Context) {
        authURL, _ := client.AuthCodeURL()
        c.Redirect(302, authURL)
    })

    // 回调路由
    r.GET("/callback", func(c *gin.Context) {
        code := c.Query("code")
        state := c.Query("state")
        
        token, err := client.Exchange(c.Request.Context(), code, state)
        if err != nil {
            c.JSON(400, gin.H{"error": err.Error()})
            return
        }
        
        c.JSON(200, gin.H{"token": token.AccessToken})
    })

    // 受保护的路由
    protected := r.Group("/api")
    protected.Use(client.GinMiddleware())
    {
        protected.GET("/profile", func(c *gin.Context) {
            userInfo := oauth2.GinUserInfo(c)
            c.JSON(200, userInfo)
        })
    }

    r.Run(":9000")
}
```

### 标准库 HTTP 中间件

```go
package main

import (
    "net/http"
    "client/oauth2"
)

func main() {
    config := oauth2.DefaultConfig(
        "your-client-id",
        "your-client-secret",
        "http://localhost:9000/callback",
    )

    client, _ := oauth2.NewClient(config)

    // 受保护的处理器
    protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        userInfo := oauth2.UserInfoFromContext(r.Context())
        // 使用 userInfo
    })

    // 应用中间件
    http.Handle("/api/profile", client.Middleware(protectedHandler))
    
    http.ListenAndServe(":9000", nil)
}
```

## 自定义 Token 存储

默认使用内存存储，可以实现 `TokenStore` 接口来自定义存储：

```go
type TokenStore interface {
    GetToken() (*Token, error)
    SetToken(token *Token) error
    DeleteToken() error
}

// 示例：Redis 存储
type RedisTokenStore struct {
    client *redis.Client
    key    string
}

func (s *RedisTokenStore) GetToken() (*oauth2.Token, error) {
    // 从 Redis 获取 token
}

func (s *RedisTokenStore) SetToken(token *oauth2.Token) error {
    // 存储到 Redis
}

func (s *RedisTokenStore) DeleteToken() error {
    // 从 Redis 删除
}

// 使用自定义存储
client.SetTokenStore(&RedisTokenStore{...})
```

## API 参考

### Config

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| ClientID | string | 是 | 应用的 Client ID |
| ClientSecret | string | 否 | 应用的 Client Secret（公开客户端可不填） |
| AuthURL | string | 是 | 授权端点 URL |
| TokenURL | string | 是 | Token 端点 URL |
| UserInfoURL | string | 否 | 用户信息端点 URL |
| RedirectURL | string | 是 | 回调 URL |
| Scopes | []string | 否 | 请求的权限范围 |
| UsePKCE | bool | 否 | 是否启用 PKCE |

### Client 方法

| 方法 | 说明 |
|------|------|
| `AuthCodeURL()` | 生成授权 URL |
| `Exchange(ctx, code, state)` | 用授权码交换 Token |
| `Refresh(ctx)` | 刷新 Token |
| `GetToken(ctx)` | 获取当前 Token（自动刷新） |
| `GetUserInfo(ctx)` | 获取用户信息 |
| `Logout()` | 清除 Token |
| `Middleware(next)` | 标准库 HTTP 中间件 |
| `GinMiddleware()` | Gin 中间件 |
| `EchoMiddleware()` | Echo 中间件 |
| `EchoMiddlewareWithOptions(opts)` | Echo 中间件（高级选项） |
| `DeviceFlow(ctx, scope)` | 设备授权流程 |
| `DeviceFlowWithCallback(ctx, scope, cb)` | 设备流（带状态回调） |
| `ClientCredentials(ctx, req)` | 客户端凭据获取 Token |
| `NewClientCredentialsManager(scope)` | 创建自动刷新的凭据管理器 |
| `NewSSEClient()` | 创建 SSE 事件流客户端 |
| `RegisterUser(ctx, req)` | SDK 直接注册用户 |
| `LoginUser(ctx, req)` | SDK 直接登录用户 |
| `SyncUser(ctx, req)` | 同步用户（自动注册或登录） |
| `BatchSyncUsers(ctx, users)` | 批量同步用户 |
| `GetUserByEmail(ctx, email)` | 通过邮箱查询用户 |
| `ValidateUserToken(ctx, token)` | 验证用户 Token |
| `SignToken(ctx, req)` | 签发自定义 Token |
| `HealthCheck(ctx)` | 检查服务端连通性和健康状态 |
| `RevokeToken(ctx, hint)` | 撤销令牌 |
| `IntrospectToken(ctx, token, hint)` | Token 内省查询 |
| `SetLogger(logger)` | 设置自定义日志 |
| `Close()` | 关闭客户端，释放后台资源 |

---

## SDK 接入（跨系统账号同步）

SDK 接入模式允许你的系统直接注册和登录用户到 OAuth2 服务器，实现跨系统账号互通。

### 注册用户

```go
ctx := context.Background()

// 通过 SDK 注册用户
resp, err := client.RegisterUser(ctx, &oauth2.SDKRegisterRequest{
    Email:    "user@example.com",
    Username: "newuser",
    Password: "securepassword",
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("User ID: %s\n", resp.User.ID)
fmt.Printf("Access Token: %s\n", resp.AccessToken)
```

### 登录用户

```go
// 通过 SDK 登录用户
resp, err := client.LoginUser(ctx, &oauth2.SDKLoginRequest{
    Email:    "user@example.com",
    Password: "securepassword",
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Access Token: %s\n", resp.AccessToken)
```

### 用户同步（推荐）

`SyncUser` 方法会自动尝试登录，如果用户不存在则自动注册：

```go
// 同步用户 - 自动处理注册或登录
resp, err := client.SyncUser(ctx, &oauth2.SyncUserRequest{
    Email:    "user@example.com",
    Username: "syncuser",
    Password: "securepassword",
})
if err != nil {
    log.Fatal(err)
}

if resp.Created {
    fmt.Println("New user created")
} else {
    fmt.Println("Existing user logged in")
}
fmt.Printf("User ID: %s\n", resp.UserID)
```

### 验证 Token

```go
// 验证从其他系统传来的 Token
userInfo, err := client.ValidateUserToken(ctx, "bearer-token-here")
if err != nil {
    if err == oauth2.ErrTokenExpired {
        fmt.Println("Token has expired")
    }
    log.Fatal(err)
}

fmt.Printf("User: %s (%s)\n", userInfo.Username, userInfo.Email)
```

---

## Webhook 接收

接收 OAuth2 服务器推送的实时事件通知。

### 设置 Webhook 服务器

```go
package main

import (
    "fmt"
    "net/http"
    "client/oauth2"
)

func main() {
    // 创建 Webhook 服务器
    webhookServer := oauth2.NewWebhookServer(&oauth2.WebhookHandlerOptions{
        Secret:            "your-webhook-secret", // 与服务器配置的密钥一致
        ValidateTimestamp: true,
        MaxTimeDrift:      5 * time.Minute,
    })

    // 监听用户注册事件
    webhookServer.On(oauth2.WebhookEventUserRegistered, func(payload *oauth2.WebhookPayload) error {
        fmt.Printf("New user registered: %v\n", payload.Data)
        return nil
    })

    // 监听用户登录事件
    webhookServer.On(oauth2.WebhookEventUserLogin, func(payload *oauth2.WebhookPayload) error {
        fmt.Printf("User logged in: %v\n", payload.Data)
        return nil
    })

    // 监听 OAuth 授权事件
    webhookServer.On(oauth2.WebhookEventOAuthAuthorized, func(payload *oauth2.WebhookPayload) error {
        fmt.Printf("OAuth authorized: %v\n", payload.Data)
        return nil
    })

    // 监听所有事件
    webhookServer.OnAll(func(payload *oauth2.WebhookPayload) error {
        fmt.Printf("[%s] Event: %s\n", payload.Timestamp, payload.Event)
        return nil
    })

    // 启动 HTTP 服务器
    http.Handle("/webhook", webhookServer)
    http.ListenAndServe(":9001", nil)
}
```

### Webhook 事件类型

| 事件 | 说明 |
|------|------|
| `user.registered` | 用户注册 |
| `user.login` | 用户登录 |
| `user.updated` | 用户信息更新 |
| `oauth.authorized` | OAuth 授权 |
| `oauth.revoked` | OAuth 撤销 |
| `token.refreshed` | Token 刷新 |

---

## SSE 事件流

实时监听认证事件流。

```go
package main

import (
    "fmt"
    "client/oauth2"
)

func main() {
    // 创建 SSE 客户端
    sseClient := oauth2.NewSSEClient("http://localhost:8080/api/events/app?app_id=your-app-id")

    // 设置事件处理器
    sseClient.OnEvent(func(event oauth2.AuthEvent) {
        fmt.Printf("Event: %s, User: %s\n", event.Type, event.UserID)
    })

    // 设置错误处理器
    sseClient.OnError(func(err error) {
        fmt.Printf("SSE Error: %v\n", err)
    })

    // 开始监听（阻塞）
    if err := sseClient.Connect(); err != nil {
        log.Fatal(err)
    }
}
```

---

## 自定义日志

```go
// 实现 Logger 接口
type MyLogger struct{}

func (l *MyLogger) Debug(msg string, args ...interface{}) {
    log.Printf("[DEBUG] %s %v", msg, args)
}
func (l *MyLogger) Info(msg string, args ...interface{}) {
    log.Printf("[INFO] %s %v", msg, args)
}
func (l *MyLogger) Warn(msg string, args ...interface{}) {
    log.Printf("[WARN] %s %v", msg, args)
}
func (l *MyLogger) Error(msg string, args ...interface{}) {
    log.Printf("[ERROR] %s %v", msg, args)
}
func (l *MyLogger) SetLevel(level oauth2.LogLevel) {}
func (l *MyLogger) GetLevel() oauth2.LogLevel { return oauth2.LogLevelInfo }

// 使用自定义日志
client.SetLogger(&MyLogger{})

// 或者禁用日志
client.SetLogger(&oauth2.NopLogger{})

// 设置全局日志级别
oauth2.SetGlobalLogger(oauth2.NewDefaultLogger())
oauth2.GetGlobalLogger().SetLevel(oauth2.LogLevelDebug)
```

---

## Echo 中间件

```go
package main

import (
    "client/oauth2"
    "github.com/labstack/echo/v4"
)

func main() {
    config := oauth2.DefaultConfig(
        "your-client-id",
        "your-client-secret",
        "http://localhost:9003/callback",
    )
    client, _ := oauth2.NewClient(config)
    e := echo.New()

    // 严格认证
    api := e.Group("/api")
    api.Use(client.EchoMiddleware())
    api.GET("/profile", func(c echo.Context) error {
        userInfo := oauth2.EchoGetUserInfo(c)
        return c.JSON(200, userInfo)
    })

    // 允许匿名访问
    public := e.Group("/public")
    public.Use(client.EchoMiddlewareWithOptions(oauth2.EchoMiddlewareOptions{
        AllowAnonymous: true,
        SkipPaths:      []string{"/health"},
    }))

    e.Start(":9003")
}
```

---

## Device Flow (RFC 8628)

设备授权流程，适用于智能电视、CLI 工具、IoT 设备等输入受限场景。

```go
ctx := context.Background()

// 方式 1: 简单模式（阻塞等待，自动打印提示）
token, err := client.DeviceFlow(ctx, "openid profile email")

// 方式 2: 回调模式（推荐，可自定义 UI）
token, err := client.DeviceFlowWithCallback(ctx, "openid profile", func(status string, data interface{}) {
    switch status {
    case "device_code":
        auth := data.(*oauth2.DeviceAuthResponse)
        fmt.Printf("请访问 %s 输入验证码: %s\n", auth.VerificationURI, auth.UserCode)
    case "authorized":
        fmt.Println("授权成功!")
    case "expired":
        fmt.Println("验证码已过期")
    }
})
```

---

## Client Credentials

机器对机器认证，无需用户参与。

```go
// 基础用法
resp, err := client.ClientCredentials(ctx, &oauth2.ClientCredentialsRequest{
    Scope: "openid profile",
})
fmt.Println(resp.AccessToken)

// Manager 模式：自动管理 Token 生命周期
manager := client.NewClientCredentialsManager("openid profile")
token, err := manager.GetToken(ctx) // 自动缓存和刷新

// 自动注入 Token 的 HTTP Client
httpClient := manager.HTTPClient(ctx)
resp, err := httpClient.Get("https://api.example.com/data")
```

---

## 安全建议

1. **始终启用 PKCE** - 即使是机密客户端也建议启用
2. **安全存储 Token** - 生产环境使用加密存储
3. **使用 HTTPS** - 所有 OAuth2 通信都应使用 HTTPS
4. **验证 State** - SDK 自动验证，防止 CSRF 攻击
5. **Webhook 签名验证** - 始终配置并验证 Webhook 签名
6. **Token 过期处理** - 使用 `GetToken()` 自动刷新，或处理 `ErrTokenExpired`
7. **保护 Client Secret** - 不要在客户端代码中硬编码，使用环境变量

---

## 错误处理

```go
import "client/oauth2"

// 常见错误
var (
    oauth2.ErrTokenExpired   // Token 已过期
    oauth2.ErrInvalidState   // State 验证失败
    oauth2.ErrInvalidGrant   // 授权码无效
    oauth2.ErrServerError    // 服务器错误
)

// 错误处理示例
token, err := client.Exchange(ctx, code, state)
if err != nil {
    switch err {
    case oauth2.ErrInvalidState:
        // CSRF 攻击或 state 过期
    case oauth2.ErrInvalidGrant:
        // 授权码已使用或过期
    default:
        // 其他错误
    }
}
```

---

## 完整示例

查看 `examples/` 目录获取更多示例：

- `examples/gin/` - Gin 框架集成（Authorization Code + PKCE + 中间件）
- `examples/echo/` - Echo 框架集成（中间件 + 匿名访问 + Scope 检查）
- `examples/sdk/` - SDK 接入模式（用户同步、注册、Token 验证）
- `examples/device/` - Device Flow 设备授权（CLI 交互式 + 简单模式）
- `examples/client-credentials/` - Client Credentials 机器认证（Manager + HTTP Client）
- `examples/sse/` - SSE 事件流（实时监听认证事件）
- `examples/webhook/` - Webhook 接收服务器（事件处理 + 签名验证）
- `examples/test/` - 综合测试客户端（Web UI + CLI，覆盖全部流程）

## 许可证

本项目基于 [GNU General Public License v3.0](../LICENSE) 发布。