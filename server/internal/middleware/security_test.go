package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

/* 辅助函数：创建带 SecurityHeaders 中间件的 Gin 引擎 */
func setupSecurityRouter() *gin.Engine {
	r := gin.New()
	r.Use(SecurityHeaders())
	r.GET("/test", func(c *gin.Context) { c.String(200, "ok") })
	r.GET("/api/data", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	return r
}

func TestSecurityHeaders_XContentTypeOptions(t *testing.T) {
	r := setupSecurityRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
}

func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	r := setupSecurityRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want %q", got, "DENY")
	}
}

func TestSecurityHeaders_ReferrerPolicy(t *testing.T) {
	r := setupSecurityRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy = %q, want %q", got, "strict-origin-when-cross-origin")
	}
}

func TestSecurityHeaders_CSP(t *testing.T) {
	r := setupSecurityRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy should be set")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP should contain default-src 'self', got: %s", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Error("CSP should contain frame-ancestors 'none'")
	}
}

func TestSecurityHeaders_HSTS_WithHTTPS(t *testing.T) {
	r := setupSecurityRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	r.ServeHTTP(w, req)
	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("HSTS should be set for HTTPS requests")
	}
	if !strings.Contains(hsts, "max-age=") {
		t.Error("HSTS should contain max-age")
	}
}

func TestSecurityHeaders_NoHSTS_WithHTTP(t *testing.T) {
	r := setupSecurityRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS should NOT be set for plain HTTP, got %q", got)
	}
}

func TestSecurityHeaders_API_NoCache(t *testing.T) {
	r := setupSecurityRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/data", nil)
	r.ServeHTTP(w, req)
	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("API paths should have no-store Cache-Control, got %q", cc)
	}
}

func TestSecurityHeaders_NonAPI_NoNoCacheHeader(t *testing.T) {
	r := setupSecurityRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	cc := w.Header().Get("Cache-Control")
	if strings.Contains(cc, "no-store") {
		t.Errorf("non-API paths should NOT have no-store, got %q", cc)
	}
}

func TestSecurityHeaders_CrossOriginOpenerPolicy(t *testing.T) {
	r := setupSecurityRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Cross-Origin-Opener-Policy"); got != "same-origin" {
		t.Errorf("Cross-Origin-Opener-Policy = %q, want %q", got, "same-origin")
	}
}

func TestSecurityHeaders_PermissionsPolicy(t *testing.T) {
	r := setupSecurityRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	pp := w.Header().Get("Permissions-Policy")
	if pp == "" {
		t.Error("Permissions-Policy should be set")
	}
	if !strings.Contains(pp, "camera=()") {
		t.Error("Permissions-Policy should disable camera")
	}
}

/* ========== RequestSizeLimit ========== */

func TestRequestSizeLimit_Accept(t *testing.T) {
	r := gin.New()
	r.Use(RequestSizeLimit(1024))
	r.POST("/test", func(c *gin.Context) { c.String(200, "ok") })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", strings.NewReader("small body"))
	req.ContentLength = 10
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("small request should pass, got %d", w.Code)
	}
}

func TestRequestSizeLimit_Reject(t *testing.T) {
	r := gin.New()
	r.Use(RequestSizeLimit(10))
	r.POST("/test", func(c *gin.Context) { c.String(200, "ok") })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", strings.NewReader("this is a large body"))
	req.ContentLength = 100
	r.ServeHTTP(w, req)
	if w.Code != 413 {
		t.Errorf("oversized request should be 413, got %d", w.Code)
	}
}
