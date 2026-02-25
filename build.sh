#!/bin/bash
set -e

##
## OAuth2 Authorization Server 构建脚本
## 功能：前端构建 → 静态文件复制 → 服务端编译（含构建 ID 注入）
##

BUILD_ID="${BUILD_ID:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "🔧 Building OAuth2 Server (build=${BUILD_ID})..."

# 1. 前端构建
echo "📦 Building web frontend..."
cd web
if command -v bun &>/dev/null; then
  bun install && bun run build
elif command -v pnpm &>/dev/null; then
  pnpm install && pnpm run build
else
  npm install && npm run build
fi
cd ..

# 2. 复制静态文件
echo "📋 Copying static files..."
mkdir -p server/web/dist
rm -rf server/web/dist/*
cp -r web/out/* server/web/dist/

# 3. 编译服务端（注入构建信息）
echo "🏗️  Building server..."
mkdir -p bin
cd server
go build \
  -ldflags "-s -w -X main.buildID=${BUILD_ID} -X main.buildTime=${BUILD_TIME}" \
  -o ../bin/oauth2-server ./cmd/main.go
cd ..

echo ""
echo "✅ Build complete! (${BUILD_ID} @ ${BUILD_TIME})"
echo ""
echo "Run the server:"
echo "  ./bin/oauth2-server"
echo ""
echo "Or with Docker:"
echo "  docker compose up -d"
