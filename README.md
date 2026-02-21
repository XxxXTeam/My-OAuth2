# My-OAuth2

<p align="center">
  <strong>完整的 OAuth2 / OpenID Connect 认证授权系统</strong><br>
  包含授权服务器、管理前端和客户端 SDK，开箱即用
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go" alt="Go">
  <img src="https://img.shields.io/badge/Next.js-16-black?logo=next.js" alt="Next.js">
  <img src="https://img.shields.io/badge/License-GPL%20v3-blue" alt="License">
  <img src="https://img.shields.io/badge/OAuth2-RFC%206749-green" alt="OAuth2">
</p>

---

## 项目结构

```
My-OAuth2/
├── server/          # Go 授权服务器（Gin + GORM + SQLite/PostgreSQL/MySQL）
│   ├── cmd/         # 程序入口
│   ├── internal/    # 内部模块（model/repository/service/handler/middleware）
│   ├── pkg/         # 公共包（cache/jwt/logger/password/email）
│   └── web/         # 嵌入的前端静态文件
├── web/             # Next.js 管理前端（React + TailwindCSS + shadcn/ui）
│   ├── app/         # 页面路由
│   ├── components/  # UI 组件
│   └── lib/         # 工具库（api/i18n/auth）
└── clinet/          # Go 客户端 SDK（支持 Gin/Echo/标准库集成）
    ├── oauth2/      # SDK 核心
    └── examples/    # 8 个完整示例
```

## 核心特性

### 授权服务器 (server/)

| 分类 | 特性 | RFC |
|------|------|-----|
| **授权流程** | Authorization Code + PKCE | RFC 7636 |
| **客户端凭证** | 机器对机器认证 | RFC 6749 §4.4 |
| **设备授权** | 无浏览器设备（TV/CLI/IoT） | RFC 8628 |
| **令牌交换** | 跨服务委托/降权 | RFC 8693 |
| **令牌内省** | Token 有效性查询 | RFC 7662 |
| **OIDC 发现** | .well-known + JWKS | OpenID Connect |
| **Token 轮换** | Refresh Token 单次使用 + 重放检测 | — |
| **联邦认证** | GitHub/Google/自定义 SSO 登录 | — |
| **邮件队列** | 数据库持久化、后台 Worker、失败重试 | — |
| **Webhook** | HMAC-SHA256 签名、指数退避重试 | — |
| **异常检测** | 新设备/新位置/异常时间/暴力破解 | — |
| **SDK 接入** | 第三方应用注册/登录/同步用户 | — |
| **日志系统** | 彩色输出、TraceID、脱敏、文件轮转 | — |

### 管理前端 (web/)

- **用户认证** — 登录/注册/忘记密码/邮箱验证/社交登录
- **OAuth2 授权** — 授权确认页面 + Device Flow 输入页
- **管理后台** — 用户管理/应用管理/系统配置/登录日志/联邦提供者
- **个人中心** — OIDC 资料编辑/头像上传/密码修改/授权管理/邮箱更换
- **仪表盘** — 登录趋势图表/系统统计/SSE 实时事件流
- **Webhook** — 可视化配置/投递历史/测试发送
- **国际化** — 中文/英文完整 i18n（130+ key）
- **错误边界** — 详细错误信息 + 堆栈展示 + 一键复制

### 客户端 SDK (clinet/)

- **多授权流程** — Authorization Code (PKCE) / Client Credentials / Device Flow
- **框架中间件** — Gin / Echo / 标准库 `http.Handler`
- **Token 管理** — 自动刷新 + 可扩展存储接口 (`TokenStore`)
- **Webhook 客户端** — 接收/签名验证/事件路由
- **SSE 客户端** — 实时监听授权事件流
- **用户同步** — `SyncUser()` 跨系统账号互通
- **日志接口** — 可替换的 `Logger` 接口

## 快速开始

### 方式一：单一服务部署（推荐）

前端嵌入 Go 二进制，单进程运行：

```bash
# 构建
./build.sh    # 或 make build

# 运行
./bin/oauth2-server
# → http://localhost:8080（API + 前端）
```

### 方式二：开发模式

```bash
# 后端
cd server && go run ./cmd
# → http://localhost:8080

# 前端（另一个终端）
cd web && pnpm dev
# → http://localhost:3000
```

### 方式三：使用 SDK 接入

```go
import "client/oauth2"

client, _ := oauth2.NewClient(oauth2.DefaultConfig(
    "your-client-id",
    "your-client-secret",
    "http://localhost:9000/callback",
))

/* 生成授权 URL（自动 PKCE） */
authURL, _ := client.AuthCodeURL()

/* 授权回调后交换 Token */
token, _ := client.Exchange(ctx, code, state)

/* 获取用户信息 */
userInfo, _ := client.GetUserInfo(ctx)
```

## 数据库支持

| 数据库 | 驱动 | 推荐场景 | DSN 示例 |
|--------|------|----------|----------|
| **SQLite** | `sqlite` | 开发/小规模部署 | `data/oauth2.db` |
| **PostgreSQL** | `postgres` | 生产环境 | `postgres://user:pass@localhost/oauth2` |
| **MySQL** | `mysql` | 生产环境 | `user:pass@tcp(localhost:3306)/oauth2` |

自动功能：
- DSN 参数补全（WAL/超时/字符集等）
- 连接池配置（最大连接/空闲/生存时间）
- Schema 自动迁移（17 张表）
- 首次启动自动创建管理员

## API 端点

### 认证 (`/api/auth/`)
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/register` | 用户注册 |
| POST | `/login` | 用户登录（返回 JWT + httpOnly Cookie） |
| POST | `/refresh` | Token 刷新（Rotation） |
| POST | `/logout` | 登出（清除 Cookie） |
| POST | `/forgot-password` | 忘记密码（邮件队列） |
| POST | `/reset-password` | 重置密码 |

### OAuth2 (`/oauth/`)
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/authorize` | 授权端点 |
| POST | `/token` | Token 签发（支持 5 种 grant_type） |
| GET | `/userinfo` | 用户信息（OIDC） |
| POST | `/revoke` | 令牌撤销 |
| POST | `/introspect` | 令牌内省 |
| POST | `/device/code` | 设备码申请 |
| GET/POST | `/logout` | OIDC 登出 |

### OIDC Discovery
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/.well-known/openid-configuration` | OIDC 配置 |
| GET | `/.well-known/jwks.json` | JSON Web Key Set |
| GET | `/.well-known/webfinger` | WebFinger |

### SDK (`/api/sdk/`)
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/register` | SDK 注册用户 |
| POST | `/login` | SDK 登录用户 |
| POST | `/refresh` | Token 刷新 |
| POST | `/verify` | Token 验证 |
| POST | `/sync/user` | 用户同步 |
| POST | `/sync/batch` | 批量同步 |

### 用户 (`/api/user/`) — 需登录
| 方法 | 路径 | 说明 |
|------|------|------|
| GET/POST | `/profile` | 个人资料（OIDC Claims） |
| POST | `/password` | 修改密码 |
| POST | `/avatar` | 上传头像 |
| POST | `/email/send-verify` | 发送邮箱验证 |
| POST | `/email/change` | 更换邮箱 |
| GET | `/authorizations` | 已授权应用列表 |

### 管理员 (`/api/admin/`) — 需管理员权限
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/stats` | 系统概览统计 |
| GET | `/stats/login-trend` | 登录趋势 |
| GET | `/users` | 用户列表（搜索/筛选/分页） |
| GET | `/login-logs` | 登录日志 |
| POST | `/users/:id/send-reset-email` | 发送密码重置 |

## 技术栈

| 层级 | 技术 |
|------|------|
| **后端框架** | Go 1.21+, Gin, GORM |
| **认证** | JWT (HMAC-SHA256), bcrypt, PKCE |
| **数据库** | SQLite / PostgreSQL / MySQL |
| **缓存** | Memory / Redis / Memcached / BadgerDB / File |
| **前端框架** | Next.js 16, React 19, TypeScript |
| **UI** | TailwindCSS, shadcn/ui, Lucide Icons |
| **SDK** | Go, 支持 Gin / Echo / 标准库 |

## 安全机制

- **PKCE** — 防止授权码拦截攻击 (RFC 7636)
- **State** — 防止 CSRF 攻击
- **Token Rotation** — Refresh Token 单次使用 + 重放检测
- **bcrypt** — 密码哈希（cost=12）
- **CORS** — 基于 Origin 白名单
- **httpOnly Cookie** — 防止 XSS 窃取 Token
- **CSRF Token** — Cookie + Header 双重校验
- **Webhook 签名** — HMAC-SHA256 负载签名
- **日志脱敏** — 密码/密钥/Token 自动脱敏
- **异常检测** — 基于历史行为的登录风险评估
- **限流** — IP + 端点级别令牌桶限流

## Webhook 事件

| 事件 | 触发时机 |
|------|----------|
| `user.registered` | 用户注册成功 |
| `user.login` | 用户登录成功 |
| `user.updated` | 用户信息更新 |
| `oauth.authorized` | OAuth2 授权同意 |
| `oauth.revoked` | OAuth2 授权撤销 |
| `token.issued` | 令牌签发 |
| `token.refreshed` | 令牌刷新 |

## 配置

配置文件位于 `server/data/config.json`，首次运行自动生成。

```jsonc
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "mode": "release",
    "allow_registration": true
  },
  "database": {
    "driver": "sqlite",
    "dsn": "data/oauth2.db"
  },
  "jwt": {
    "secret": "auto-generated",
    "issuer": "my-oauth2",
    "access_token_ttl": "15m",
    "refresh_token_ttl": "720h"
  },
  "email": {
    "host": "smtp.example.com",
    "port": 587,
    "username": "noreply@example.com",
    "password": "xxx",
    "from": "noreply@example.com"
  }
}
```

环境变量覆盖：
```bash
ADMIN_EMAIL=admin@example.com    # 初始管理员邮箱
ADMIN_USERNAME=admin             # 初始管理员用户名
ADMIN_PASSWORD=admin123          # 初始管理员密码
```

## 开发

```bash
# 后端开发
cd server && go run ./cmd

# 前端开发
cd web && pnpm dev

# SDK 示例（8 个完整示例）
cd clinet/examples/test && go run main.go           # 综合测试
cd clinet/examples/gin && go run main.go            # Gin 集成
cd clinet/examples/echo && go run main.go           # Echo 集成
cd clinet/examples/device && go run main.go         # Device Flow
cd clinet/examples/client-credentials && go run main.go  # M2M
cd clinet/examples/webhook && go run main.go        # Webhook
cd clinet/examples/sse && go run main.go            # SSE 事件流
cd clinet/examples/sdk && go run main.go            # SDK 同步

# 构建生产版本
make build    # 或 ./build.sh
```

## 许可证

本项目基于 [GNU General Public License v3.0](LICENSE) 发布。

```
Copyright (C) 2024 My-OAuth2 Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```
