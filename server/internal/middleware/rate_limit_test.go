package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

/* ========== RateLimiter 核心逻辑 ========== */

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(10, 5)
	defer rl.Stop()

	/* 前 5 次应该全部允许（burst=5） */
	for i := 0; i < 5; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Errorf("request %d should be allowed (within burst)", i+1)
		}
	}

	/* 第 6 次应该被拒绝（令牌已耗尽，还没来得及补充） */
	if rl.Allow("1.2.3.4") {
		t.Error("request 6 should be rejected (burst exhausted)")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	defer rl.Stop()

	/* 不同 IP 互不影响 */
	if !rl.Allow("1.1.1.1") {
		t.Error("first request from IP1 should be allowed")
	}
	if !rl.Allow("2.2.2.2") {
		t.Error("first request from IP2 should be allowed")
	}
}

func TestRateLimiter_Check_ReturnsDetails(t *testing.T) {
	rl := NewRateLimiter(10, 3)
	defer rl.Stop()

	r := rl.Check("5.5.5.5")
	if !r.Allowed {
		t.Error("first request should be allowed")
	}
	if r.Limit != 3 {
		t.Errorf("Limit = %d, want 3", r.Limit)
	}
	if r.Remaining != 2 {
		t.Errorf("Remaining = %d, want 2", r.Remaining)
	}
}

func TestRateLimiter_Stop_Idempotent(t *testing.T) {
	rl := NewRateLimiter(10, 10)
	rl.Stop()
	rl.Stop() /* 二次调用不应 panic */
}

/* ========== RateLimitMiddleware HTTP 集成 ========== */

func setupRateLimitRouter(rate, burst int) *gin.Engine {
	r := gin.New()
	r.Use(RateLimitMiddleware(rate, burst))
	r.GET("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	return r
}

func TestRateLimitMiddleware_PassesWithinBurst(t *testing.T) {
	r := setupRateLimitRouter(100, 3)
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Errorf("request %d should pass, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimitMiddleware_BlocksOverBurst(t *testing.T) {
	r := setupRateLimitRouter(1, 1)
	/* 第一次通过 */
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "10.0.0.2:12345"
	r.ServeHTTP(w1, req1)
	if w1.Code != 200 {
		t.Errorf("first request should pass, got %d", w1.Code)
	}

	/* 第二次被限流 */
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "10.0.0.2:12345"
	r.ServeHTTP(w2, req2)
	if w2.Code != 429 {
		t.Errorf("second request should be rate limited (429), got %d", w2.Code)
	}
	if w2.Header().Get("Retry-After") == "" {
		t.Error("rate limited response should include Retry-After header")
	}
}

func TestRateLimitMiddleware_HasRateLimitHeaders(t *testing.T) {
	r := setupRateLimitRouter(100, 10)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.3:12345"
	r.ServeHTTP(w, req)

	if w.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("response should include X-RateLimit-Limit header")
	}
	if w.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("response should include X-RateLimit-Remaining header")
	}
}
