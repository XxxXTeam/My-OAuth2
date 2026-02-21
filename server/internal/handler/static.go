package handler

import (
	"io"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

/*
 * StaticHandler 静态文件服务处理器
 * 功能：服务前端 SPA 静态文件，支持 HTML5 History 模式回退到 index.html
 */
type StaticHandler struct {
	fileSystem http.FileSystem
	indexPath  string
}

/*
 * NewStaticHandler 创建静态文件处理器实例
 * @param fsys - HTTP 文件系统（嵌入式或磁盘）
 */
func NewStaticHandler(fsys http.FileSystem) *StaticHandler {
	return &StaticHandler{
		fileSystem: fsys,
		indexPath:  "/index.html",
	}
}

/* serveFileContent 直接提供文件内容（不重定向），返回是否成功 */
func (h *StaticHandler) serveFileContent(c *gin.Context, filePath string) bool {
	file, err := h.fileSystem.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil || stat.IsDir() {
		return false
	}

	// Set content type based on extension
	ext := filepath.Ext(filePath)
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	c.Header("Content-Type", contentType)

	// Read and write content
	content, err := io.ReadAll(file)
	if err != nil {
		return false
	}

	c.Data(http.StatusOK, contentType, content)
	return true
}

// ServeFile serves a static file or falls back to index.html for SPA routing
func (h *StaticHandler) ServeFile(c *gin.Context) {
	urlPath := c.Request.URL.Path

	// Remove trailing slash for consistency
	if urlPath != "/" && strings.HasSuffix(urlPath, "/") {
		urlPath = strings.TrimSuffix(urlPath, "/")
	}

	// Try to serve the file directly
	if h.serveFileContent(c, urlPath) {
		return
	}

	// Try path/index.html for directory-like paths (Next.js static export format)
	indexPath := path.Join(urlPath, "index.html")
	if h.serveFileContent(c, indexPath) {
		return
	}

	// Try path.html
	if !strings.HasSuffix(urlPath, ".html") {
		htmlPath := urlPath + ".html"
		if h.serveFileContent(c, htmlPath) {
			return
		}
	}

	// Handle Next.js dynamic routes with _placeholder_
	// e.g., /dashboard/apps/[uuid] -> /dashboard/apps/_placeholder_/index.html
	if dynamicPath := h.tryDynamicRoute(urlPath); dynamicPath != "" {
		if h.serveFileContent(c, dynamicPath) {
			return
		}
	}

	// Check if it's a static asset that should 404
	if isStaticAsset(urlPath) {
		c.Status(http.StatusNotFound)
		return
	}

	// Fall back to index.html for SPA client-side routing
	if h.serveFileContent(c, h.indexPath) {
		return
	}

	// No index.html found
	c.Status(http.StatusNotFound)
}

// tryDynamicRoute checks if the path matches a Next.js dynamic route pattern
// and returns the placeholder path if found
func (h *StaticHandler) tryDynamicRoute(urlPath string) string {
	// Known dynamic route patterns
	dynamicPatterns := []struct {
		prefix      string
		placeholder string
	}{
		{"/dashboard/apps/", "/dashboard/apps/_placeholder_/index.html"},
	}

	for _, pattern := range dynamicPatterns {
		if strings.HasPrefix(urlPath, pattern.prefix) {
			// Extract the dynamic segment
			rest := strings.TrimPrefix(urlPath, pattern.prefix)
			// If there's no sub-path (just the ID), use placeholder
			if !strings.Contains(rest, "/") && rest != "" && rest != "new" {
				return pattern.placeholder
			}
		}
	}
	return ""
}

// isStaticAsset checks if the path looks like a static asset
func isStaticAsset(p string) bool {
	exts := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"}
	for _, ext := range exts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// Serve returns a gin handler function
func (h *StaticHandler) Serve() gin.HandlerFunc {
	return h.ServeFile
}
