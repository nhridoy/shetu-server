package auth

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
)

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := uuid.New().String()
		c.Set("request_id", rid)
		c.Header("X-Request-Id", rid)
		c.Next()
	}
}

func JWTMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":       "UNAUTHORIZED",
					"message":    "missing authorization header",
					"request_id": c.GetString("request_id"),
				},
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":       "UNAUTHORIZED",
					"message":    "invalid authorization format",
					"request_id": c.GetString("request_id"),
				},
			})
			return
		}

		claims, err := VerifyAccessToken(parts[1], cfg)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":       "UNAUTHORIZED",
					"message":    "invalid or expired token",
					"request_id": c.GetString("request_id"),
				},
			})
			return
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":       "UNAUTHORIZED",
					"message":    "invalid user id in token",
					"request_id": c.GetString("request_id"),
				},
			})
			return
		}

		c.Set("user_id", userID)
		c.Set("device_id", claims.DeviceID)
		c.Next()
	}
}

type rateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
}

var limiters = make(map[int]*rateLimiter)
var limitersMu sync.Mutex

func getLimiter(max int) *rateLimiter {
	limitersMu.Lock()
	defer limitersMu.Unlock()
	if l, ok := limiters[max]; ok {
		return l
	}
	l := &rateLimiter{requests: make(map[string][]time.Time)}
	limiters[max] = l
	return l
}

func RateLimit(max int) gin.HandlerFunc {
	limiter := getLimiter(max)
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		ip := c.ClientIP()
		now := time.Now()
		window := time.Minute

		limiter.mu.Lock()
		defer limiter.mu.Unlock()

		reqs := limiter.requests[ip]
		cutoff := now.Add(-window)
		valid := reqs[:0]
		for _, t := range reqs {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		limiter.requests[ip] = valid

		if len(valid) >= max {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": gin.H{
					"code":       "RATE_LIMITED",
					"message":    "too many requests",
					"request_id": c.GetString("request_id"),
				},
			})
			return
		}

		limiter.requests[ip] = append(limiter.requests[ip], now)
		c.Next()
	}
}

func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		o = strings.TrimSuffix(o, "/")
		allowed[o] = struct{}{}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}
		origin = strings.TrimSuffix(origin, "/")

		if _, ok := allowed[origin]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": gin.H{
					"code":       "CORS_ORIGIN_NOT_ALLOWED",
					"message":    "origin not allowed",
					"request_id": c.GetString("request_id"),
				},
			})
			return
		}

		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Request-Id")
		c.Header("Access-Control-Expose-Headers", "X-Request-Id")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
