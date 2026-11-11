package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupRouter(cfg *config.Config) *gin.Engine {
	r := gin.New()
	r.Use(RequestID())
	return r
}

func TestRequestID_AddsToContextAndHeader(t *testing.T) {
	r := gin.New()
	r.Use(RequestID())
	r.GET("/test", func(c *gin.Context) {
		rid := c.GetString("request_id")
		if rid == "" {
			t.Fatal("request_id not set in context")
		}
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Header().Get("X-Request-Id") == "" {
		t.Fatal("X-Request-Id header not set")
	}
	if w.Header().Get("X-Request-Id") != w.Header().Get("X-Request-Id") {
		t.Fatal("header mismatch")
	}
}

func TestRequestID_UniquePerRequest(t *testing.T) {
	r := gin.New()
	r.Use(RequestID())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w2, req2)

	id1 := w1.Header().Get("X-Request-Id")
	id2 := w2.Header().Get("X-Request-Id")
	if id1 == "" || id2 == "" {
		t.Fatal("missing request IDs")
	}
	if id1 == id2 {
		t.Fatal("request IDs should be unique per request")
	}
}

func TestJWTMiddleware_MissingAuthorization(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}
	r := gin.New()
	r.Use(RequestID())
	r.Use(JWTMiddleware(cfg))
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestJWTMiddleware_InvalidToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}
	r := gin.New()
	r.Use(RequestID())
	r.Use(JWTMiddleware(cfg))
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestJWTMiddleware_ExpiredToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:          "test-secret",
		JWTExpiry:          -1 * time.Hour,
		RefreshTokenExpiry: 30 * 24 * time.Hour,
	}
	userID := uuid.New()
	accessToken, _ := GenerateAccessToken(userID, "device-1", cfg)

	r := gin.New()
	r.Use(RequestID())
	r.Use(JWTMiddleware(cfg))
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestJWTMiddleware_ValidToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:          "test-secret",
		JWTExpiry:          15 * time.Minute,
		RefreshTokenExpiry: 30 * 24 * time.Hour,
	}
	userID := uuid.New()
	accessToken, _ := GenerateAccessToken(userID, "device-1", cfg)

	r := gin.New()
	r.Use(RequestID())
	r.Use(JWTMiddleware(cfg))
	r.GET("/protected", func(c *gin.Context) {
		uid, exists := c.Get("user_id")
		if !exists {
			t.Fatal("user_id not set in context")
		}
		if uid.(uuid.UUID) != userID {
			t.Fatalf("expected user_id %s, got %s", userID, uid)
		}
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestJWTMiddleware_MalformedHeader(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}
	r := gin.New()
	r.Use(RequestID())
	r.Use(JWTMiddleware(cfg))
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Token abc123")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRateLimit_AllowsWithinLimit(t *testing.T) {
	r := gin.New()
	r.Use(RateLimit(3))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	for i := range 3 {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimit_RejectsOverLimit(t *testing.T) {
	r := gin.New()
	r.Use(RateLimit(2))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	for i := range 2 {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
}

func TestRateLimit_DifferentIPsIndependent(t *testing.T) {
	r := gin.New()
	r.Use(RateLimit(1))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "1.1.1.1:1234"
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first IP: expected 200, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "2.2.2.2:5678"
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second IP: expected 200, got %d", w2.Code)
	}
}

func TestRateLimit_XForwardedForSpoofDoesNotBypass(t *testing.T) {
	r := gin.New()
	r.SetTrustedProxies(nil)
	r.Use(RateLimit(4))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	for i := range 4 {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "5.6.7.8:1234"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i))
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "5.6.7.8:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 despite spoofed X-Forwarded-For, got %d", w.Code)
	}
}

func TestRateLimit_PreflightDoesNotConsumeBudget(t *testing.T) {
	r := gin.New()
	r.SetTrustedProxies(nil)
	r.Use(RateLimit(1))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	for i := range 3 {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("OPTIONS", "/test", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("preflight %d: expected 404 (no route), got %d", i+1, w.Code)
		}
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expectated real request to pass after preflights, got %d", w.Code)
	}
}

func TestCORS_SetsHeaders(t *testing.T) {
	r := gin.New()
	r.Use(CORS([]string{"http://localhost:1420", "tauri://localhost"}))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:1420")
	r.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:1420" {
		t.Fatalf("expected echo of allowed origin, got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatal("Access-Control-Allow-Methods not set")
	}
	if w.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Fatal("Access-Control-Allow-Headers not set")
	}
}

func TestCORS_PreflightRequest(t *testing.T) {
	r := gin.New()
	r.Use(CORS([]string{"http://localhost:1420", "tauri://localhost"}))
	r.Handle("OPTIONS", "/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:1420")
	req.Header.Set("Access-Control-Request-Method", "POST")
	r.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatal("Access-Control-Allow-Origin not set on preflight")
	}
}

func TestCORS_NoOrigin_PassesThrough(t *testing.T) {
	r := gin.New()
	r.Use(CORS([]string{"http://localhost:1420"}))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for no-origin request, got %d", w.Code)
	}
}

func TestCORS_DisallowedOrigin_Rejected(t *testing.T) {
	r := gin.New()
	r.Use(CORS([]string{"http://localhost:1420", "tauri://localhost"}))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	for _, origin := range []string{"http://evil.example.com", "https://evil.example.com", "null"} {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", origin)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("origin %q: expected 403, got %d", origin, w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("origin %q: must not echo Access-Control-Allow-Origin", origin)
		}
	}
}
