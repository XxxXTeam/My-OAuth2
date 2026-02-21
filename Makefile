.PHONY: all build build-web build-server clean dev

# Build everything
all: build

# Build web and server
build: build-web build-server

# Build web frontend (static export)
build-web:
	@echo "Building web frontend..."
	cd web && bun install && bun run build
	@echo "Copying static files to server..."
	rm -rf server/web/dist/*
	cp -r web/out/* server/web/dist/
	@echo "Web build complete!"

# Build server with embedded static files
build-server:
	@echo "Building server..."
	cd server && go build -o ../bin/oauth2-server ./cmd/main.go
	@echo "Server build complete!"

# Clean build artifacts
clean:
	rm -rf bin/
	rm -rf web/out/
	rm -rf web/.next/
	rm -rf server/web/dist/*
	touch server/web/dist/.gitkeep

# Development mode (separate servers)
dev:
	@echo "Starting development servers..."
	@echo "Run these commands in separate terminals:"
	@echo "  cd server && go run cmd/main.go"
	@echo "  cd web && bun dev"

# Run server only (with embedded frontend)
run:
	cd server && go run cmd/main.go

# Build for production
prod: build
	@echo "Production build complete!"
	@echo "Run: ./bin/oauth2-server"

# Help
help:
	@echo "Available targets:"
	@echo "  make build      - Build web frontend and server"
	@echo "  make build-web  - Build web frontend only"
	@echo "  make build-server - Build server only"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make dev        - Show development instructions"
	@echo "  make run        - Run server (dev mode)"
	@echo "  make prod       - Build for production"
