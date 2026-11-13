package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nhridoy/shetu-server/internal/auth"
	"github.com/nhridoy/shetu-server/internal/config"
	"github.com/nhridoy/shetu-server/internal/database"
	"github.com/nhridoy/shetu-server/internal/models"
	"github.com/nhridoy/shetu-server/internal/purge"
	syncapi "github.com/nhridoy/shetu-server/internal/sync"
	"github.com/nhridoy/shetu-server/internal/teams"
)

func main() {
	cfg := config.Load()

	if cfg.RequireEmailVerification && cfg.SMTPHost == "" && !cfg.LogOtpFallback {
		slog.Error("REQUIRE_EMAIL_VERIFICATION is enabled but SMTP is not configured. " +
			"Set SMTP_HOST (plus SMTP_PORT/USERNAME/PASSWORD/FROM), or set LOG_OTP_FALLBACK=true " +
			"to log verification codes to the console — DEV ONLY, never in production")
		os.Exit(1)
	}

	db, err := database.Open(cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect database", "error", err)
		os.Exit(1)
	}

	if err := models.AutoMigrate(db); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go purge.RunPurgeLoop(ctx, db, 24*time.Hour)

	r := gin.New()
	// The Docker health check requests "/" every 30s; logging it buries real traffic.
	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{SkipPaths: []string{"/"}}), gin.Recovery())

	r.Use(auth.RequestID())
	r.Use(auth.CORS(cfg.CORSAllowedOrigins))

	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		slog.Error("invalid TRUSTED_PROXIES, trusting no proxies", "error", err)
		r.SetTrustedProxies(nil)
	}

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Shetu API"})
	})

	apiAuth := r.Group("/api/v1/auth")
	apiAuth.POST("/prelogin", auth.RateLimit(cfg.RateLimitAuth), auth.HandlePrelogin(db, cfg))
	apiAuth.POST("/register", auth.RateLimit(cfg.RateLimitAuth), auth.HandleRegister(db, cfg))
	apiAuth.POST("/login", auth.RateLimit(cfg.RateLimitAuth), auth.HandleLogin(db, cfg))
	apiAuth.POST("/refresh", auth.RateLimit(cfg.RateLimitAuth), auth.HandleRefresh(db, cfg))
	apiAuth.POST("/logout", auth.RateLimit(cfg.RateLimitAuth), auth.HandleLogout(db))
	apiAuth.POST("/account-status", auth.RateLimit(cfg.RateLimitAuth), auth.HandleAccountStatus(db))
	apiAuth.POST("/recovery", auth.RateLimit(cfg.RateLimitAuth), auth.HandleRecovery(db, cfg))
	apiAuth.POST("/recovery/prefetch", auth.RateLimit(cfg.RateLimitAuth), auth.HandleRecoveryPrefetch(db))
	apiAuth.POST("/verify-email", auth.RateLimit(cfg.RateLimitAuth), auth.HandleVerifyEmail(db, cfg))
	apiAuth.POST("/resend-verification", auth.RateLimit(cfg.RateLimitAuth), auth.HandleResendVerification(db, cfg))
	apiAuth.GET("/oauth/start/:provider", auth.RateLimit(cfg.RateLimitAuth), auth.HandleOAuthStart(db, cfg))
	apiAuth.GET("/oauth/callback/:provider", auth.RateLimit(cfg.RateLimitAuth), auth.HandleOAuthCallback(db, cfg))
	apiAuth.POST("/oauth/exchange", auth.RateLimit(cfg.RateLimitAuth), auth.HandleOAuthExchange(db, cfg))
	apiAuth.POST("/oauth/setup", auth.RateLimit(cfg.RateLimitAuth), auth.HandleOAuthSetup(db, cfg))

	protected := r.Group("/api/v1")
	protected.Use(auth.RateLimit(cfg.RateLimitAPI), auth.JWTMiddleware(cfg), auth.DeletionGate(db))
	protected.GET("/me", auth.HandleMe(db))
	protected.GET("/vaults/default", auth.HandleDefaultVault(db))
	protected.GET("/auth/keyring", auth.HandleKeyring(db))
	protected.POST("/auth/password-change", auth.HandlePasswordChange(db, cfg))
	protected.POST("/me/deletion", auth.HandleRequestDeletion(db, cfg))
	protected.DELETE("/me/deletion", auth.HandleCancelDeletion(db))
	protected.POST("/auth/recovery-material", auth.RateLimit(cfg.RateLimitAuth), auth.HandleAttachRecoveryMaterial(db, cfg))
	protected.POST("/sync/push", syncapi.HandlePush(db))
	protected.POST("/sync/pull", syncapi.HandlePull(db))
	teams.RegisterRoutes(protected, db)

	addr := cfg.Host + ":" + cfg.Port

	go func() {
		slog.Info("server starting", "addr", addr)
		if err := r.Run(addr); err != nil {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	cancel()
}
