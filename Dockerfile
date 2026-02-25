##
## OAuth2 Authorization Server - 多阶段构建
## 阶段 1: 前端构建（Node/Bun）
## 阶段 2: Go 编译（嵌入前端静态文件）
## 阶段 3: 最小运行镜像（distroless）
##

# ============================================================
# 阶段 1: 构建前端
# ============================================================
FROM node:20-alpine AS frontend

WORKDIR /build/web

# 安装 bun（用于更快的依赖安装和构建）
RUN npm install -g bun

# 先复制依赖清单以利用 Docker 缓存
COPY web/package.json web/bun.lock* web/package-lock.json* ./
RUN bun install --frozen-lockfile || npm ci

# 复制前端源码并构建
COPY web/ ./
RUN bun run build || npm run build

# ============================================================
# 阶段 2: 构建 Go 服务端（嵌入前端静态文件）
# ============================================================
FROM golang:1.24-alpine AS backend

RUN apk add --no-cache gcc musl-dev

WORKDIR /build/server

# 先复制 go.mod/go.sum 以利用 Docker 缓存
COPY server/go.mod server/go.sum ./
RUN go mod download

# 复制服务端源码
COPY server/ ./

# 将前端构建产物复制到嵌入目录
COPY --from=frontend /build/web/out/ ./web/dist/

# 编译参数：静态链接、去除调试信息、注入构建信息
ARG BUILD_ID=docker
ARG BUILD_TIME=""
RUN CGO_ENABLED=1 go build \
    -ldflags="-s -w -X main.buildID=${BUILD_ID} -X main.buildTime=${BUILD_TIME}" \
    -o /oauth2-server \
    ./cmd/main.go

# ============================================================
# 阶段 3: 最小运行镜像
# ============================================================
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

# 创建非 root 用户
RUN addgroup -g 1000 -S oauth2 && \
    adduser -u 1000 -S oauth2 -G oauth2

# 创建数据和上传目录
RUN mkdir -p /app/data /app/uploads/avatars && \
    chown -R oauth2:oauth2 /app

WORKDIR /app

# 从构建阶段复制二进制
COPY --from=backend /oauth2-server /app/oauth2-server

# 切换到非 root 用户
USER oauth2

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

# 数据卷（配置和数据库文件）
VOLUME ["/app/data"]

# 默认环境变量
ENV GIN_MODE=release

ENTRYPOINT ["/app/oauth2-server"]
