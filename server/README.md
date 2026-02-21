# OAuth2 Server

Go语言实现的 OAuth2 授权服务器。

## 功能特性

- 完整的 OAuth2 Authorization Code 流程
- PKCE 支持
- JWT Token
- 用户注册/登录
- 应用管理
- Token 刷新和撤销

## 技术栈

- **Web 框架**: Gin
- **ORM**: GORM
- **数据库**: SQLite (开发) / PostgreSQL (生产)
- **JWT**: golang-jwt/jwt/v5

## 快速开始

```bash
# 安装依赖
go mod tidy

# 运行服务
go run cmd/main.go
```

服务默认运行在 `http://localhost:8080`

## API 端点

### 认证

| Method | Path | 说明 |
|--------|------|------|
| POST | /api/auth/register | 用户注册 |
| POST | /api/auth/login | 用户登录 |
| POST | /api/auth/refresh | 刷新 Token |
| POST | /api/auth/logout | 登出 |

### 用户

| Method | Path | 说明 |
|--------|------|------|
| GET | /api/user/profile | 获取个人信息 |

### 应用管理

| Method | Path | 说明 |
|--------|------|------|
| GET | /api/apps | 获取应用列表 |
| POST | /api/apps | 创建应用 |
| GET | /api/apps/:id | 获取应用详情 |
| PUT | /api/apps/:id | 更新应用 |
| DELETE | /api/apps/:id | 删除应用 |

### OAuth2

| Method | Path | 说明 |
|--------|------|------|
| GET | /oauth/authorize | 授权端点 |
| POST | /oauth/token | Token 端点 |
| POST | /oauth/revoke | 撤销 Token |
| GET | /oauth/userinfo | 获取用户信息 |

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| SERVER_HOST | 0.0.0.0 | 服务器地址 |
| SERVER_PORT | 8080 | 服务器端口 |
| SERVER_MODE | debug | Gin 模式 |
| DB_DRIVER | sqlite | 数据库驱动 |
| DB_DSN | oauth2.db | 数据库连接 |
| JWT_SECRET | - | JWT 密钥 |
| JWT_ISSUER | my-oauth2 | JWT 签发者 |

## 项目结构

```
server/
├── cmd/
│   └── main.go              # 入口
├── internal/
│   ├── config/              # 配置
│   ├── context/             # 上下文工具
│   ├── database/            # 数据库
│   ├── handler/             # HTTP 处理器
│   ├── middleware/          # 中间件
│   ├── model/               # 数据模型
│   ├── repository/          # 数据访问层
│   ├── router/              # 路由
│   └── service/             # 业务逻辑
└── pkg/
    ├── jwt/                 # JWT 工具
    └── password/            # 密码工具
```