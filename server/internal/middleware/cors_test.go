package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

/* 辅助函数：创建带 CORS 中间件的 Gin 引擎 */
func setupCORSRouter(origins ...string) *gin.Engine {
	r := gin.New()
	r.Use(CORSWithConfig(origins...))
	r.GET("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	r.POST("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	return r
}

func TestCORS_NoOrigin_SameOrigin(t *testing.T) {
	r := setupCORSRouter("http://localhost:3000")
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("same-origin request (no Origin header) should pass, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("same-origin request should not have CORS headers")
	}
}

func TestCORS_AllowedOrigin(t *testing.T) {
	r := setupCORSRouter("http://localhost:3000")
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("allowed origin should pass, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("Allow-Origin = %q, want %q", got, "http://localhost:3000")
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials = %q, want %q", got, "true")
	}
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	r := setupCORSRouter("http://localhost:3000")
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://evil.com")
	r.ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("disallowed origin should not get CORS headers")
	}
}

func TestCORS_Preflight_Allowed(t *testing.T) {
	r := setupCORSRouter("http://localhost:3000")
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	r.ServeHTTP(w, req)
	if w.Code != 204 {
		t.Errorf("allowed preflight should return 204, got %d", w.Code)
	}
}

func TestCORS_Preflight_Disallowed(t *testing.T) {
	r := setupCORSRouter("http://localhost:3000")
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://evil.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("disallowed preflight should return 403, got %d", w.Code)
	}
}

func TestCORS_EmptyConfig_AllowAll(t *testing.T) {
	r := setupCORSRouter() /* 空列表 = 允许所有 */
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://any-domain.com")
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://any-domain.com" {
		t.Errorf("empty config should allow all origins, got %q", got)
	}
}

func TestCORS_TrailingSlash_Normalized(t *testing.T) {
	r := setupCORSRouter("http://localhost:3000/")
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("trailing slash normalization failed, got %q", got)
	}
}
