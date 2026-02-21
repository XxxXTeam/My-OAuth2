# OAuth2 Web

OAuth2 统一登录与管理前端，基于 Next.js 构建。

## 功能特性

- 用户登录/注册
- OAuth2 授权确认页面
- 应用管理后台
- 用户仪表盘
- 响应式设计

## 技术栈

- **框架**: Next.js 16
- **UI**: TailwindCSS + shadcn/ui
- **图标**: Lucide React
- **状态**: React Context

## 快速开始

```bash
# 安装依赖
bun install

# 开发模式
bun dev

# 构建
bun build

# 生产模式
bun start
```

服务默认运行在 `http://localhost:3000`

## 页面结构

```
app/
├── (auth)/                  # 认证页面
│   ├── login/               # 登录
│   └── register/            # 注册
├── (dashboard)/             # 用户后台
│   └── dashboard/
│       ├── page.tsx         # 仪表盘
│       ├── apps/            # 应用管理
│       │   ├── page.tsx     # 应用列表
│       │   ├── new/         # 创建应用
│       │   └── [id]/        # 应用详情
│       └── profile/         # 个人资料
├── oauth/
│   └── authorize/           # OAuth2 授权页面
└── page.tsx                 # 首页
```

## 环境变量

创建 `.env.local` 文件：

```env
NEXT_PUBLIC_API_URL=http://localhost:8080
```

## 与 Server 配合

1. 启动 Server (`http://localhost:8080`)
2. 启动 Web (`http://localhost:3000`)
3. 访问 `http://localhost:3000` 开始使用