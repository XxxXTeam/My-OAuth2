#!/bin/bash
set -e

echo "🔧 Building OAuth2 Server with embedded frontend..."

# Build web frontend
echo "📦 Building web frontend..."
cd web
bun install
bun run build
cd ..

# Copy static files
echo "📋 Copying static files..."
rm -rf server/web/dist/*
cp -r web/out/* server/web/dist/

# Build server
echo "🏗️  Building server..."
cd server
go build -o ../bin/oauth2-server ./cmd/main.go
cd ..

echo ""
echo "✅ Build complete!"
echo ""
echo "Run the server:"
echo "  ./bin/oauth2-server"
echo ""
echo "Or with environment variables:"
echo "  JWT_SECRET=your-secret ./bin/oauth2-server"
