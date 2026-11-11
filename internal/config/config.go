package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port                     string
	Host                     string
	DatabaseURL              string
	JWTSecret                string
	JWTExpiry                time.Duration
	RefreshTokenExpiry       time.Duration
	BaseURL                  string
	OAuthGoogleID            string
	OAuthGoogleSecret        string
	OAuthGitHubID            string
	OAuthGitHubSecret        string
	OAuthRedirectBase        string
	OAuthRedirectURIs        []string
	AppScheme                string
	RateLimitAuth            int
	RateLimitAPI             int
	TrustedProxies           []string
	CORSAllowedOrigins       []string
	RequireEmailVerification bool
	LogOtpFallback           bool
	SMTPHost                 string
	SMTPPort                 int
	SMTPUsername             string
	SMTPPassword             string
	SMTPFrom                 string
}

func Load() *Config {
	godotenv.Load()

	rateLimitAuth := 10
	rateLimitAPI := 30

	cfg := &Config{
		Port:               getEnv("SHETU_PORT", "8080"),
		Host:               getEnv("SHETU_HOST", "0.0.0.0"),
		DatabaseURL:        getEnv("DATABASE_URL", "sqlite://shetu.db"),
		JWTSecret:          os.Getenv("JWT_SECRET"),
		JWTExpiry:          parseDuration(getEnv("JWT_EXPIRY", "15m")),
		RefreshTokenExpiry: parseDuration(getEnv("REFRESH_TOKEN_EXPIRY", "720h")),
		BaseURL:            getEnv("BASE_URL", "http://localhost:8080"),
		OAuthGoogleID:      os.Getenv("OAUTH_GOOGLE_CLIENT_ID"),
		OAuthGoogleSecret:  os.Getenv("OAUTH_GOOGLE_CLIENT_SECRET"),
		OAuthGitHubID:      os.Getenv("OAUTH_GITHUB_CLIENT_ID"),
		OAuthGitHubSecret:  os.Getenv("OAUTH_GITHUB_CLIENT_SECRET"),
		OAuthRedirectBase:  getEnv("OAUTH_REDIRECT_BASE", getEnv("BASE_URL", "http://localhost:8080")),
		AppScheme:          getEnv("SHETU_APP_SCHEME", "shetu"),
		RateLimitAuth:      rateLimitAuth,
		RateLimitAPI:       rateLimitAPI,
	}

	if v := os.Getenv("RATE_LIMIT_AUTH"); v != "" {
		if n, err := parseIntSafe(v, 10); err == nil {
			cfg.RateLimitAuth = n
		}
	}
	if v := os.Getenv("RATE_LIMIT_API"); v != "" {
		if n, err := parseIntSafe(v, 30); err == nil {
			cfg.RateLimitAPI = n
		}
	}

	cfg.RequireEmailVerification = parseBoolEnv("REQUIRE_EMAIL_VERIFICATION", false)
	cfg.LogOtpFallback = parseBoolEnv("LOG_OTP_FALLBACK", false)
	cfg.SMTPHost = os.Getenv("SMTP_HOST")
	cfg.SMTPPort = 587
	if v := os.Getenv("SMTP_PORT"); v != "" {
		if n, err := parseIntSafe(v, 587); err == nil {
			cfg.SMTPPort = n
		}
	}
	cfg.SMTPUsername = os.Getenv("SMTP_USERNAME")
	cfg.SMTPPassword = os.Getenv("SMTP_PASSWORD")
	cfg.SMTPFrom = os.Getenv("SMTP_FROM")

	if v := os.Getenv("TRUSTED_PROXIES"); v != "" {
		for cidr := range strings.SplitSeq(v, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr != "" {
				cfg.TrustedProxies = append(cfg.TrustedProxies, cidr)
			}
		}
	}

	cfg.CORSAllowedOrigins = []string{
		"http://localhost:1420",
		"http://127.0.0.1:1420",
		"http://tauri.localhost",
		"tauri://localhost",
	}
	if v := os.Getenv("CORS_ALLOWED_ORIGINS"); v != "" {
		cfg.CORSAllowedOrigins = nil
		for o := range strings.SplitSeq(v, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				cfg.CORSAllowedOrigins = append(cfg.CORSAllowedOrigins, o)
			}
		}
	}

	cfg.OAuthRedirectURIs = []string{
		"http://127.0.0.1:1421/oauth/callback",
		"http://127.0.0.1:1422/oauth/callback",
		"http://127.0.0.1:1423/oauth/callback",
	}
	if v := getEnv("SHETU_OAUTH_REDIRECT_URIS", ""); v != "" {
		cfg.OAuthRedirectURIs = nil
		for uri := range strings.SplitSeq(v, ",") {
			uri = strings.TrimSpace(uri)
			if uri != "" {
				cfg.OAuthRedirectURIs = append(cfg.OAuthRedirectURIs, uri)
			}
		}
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDuration(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	return d
}

func parseIntSafe(s string, fallback int) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return fallback, err
	}
	return n, nil
}

func parseBoolEnv(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	return fallback
}
