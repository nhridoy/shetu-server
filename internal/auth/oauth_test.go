package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/terra-server/internal/config"
	"github.com/nhridoy/terra-server/internal/models"
	"gorm.io/gorm"
)

func oauthTestConfig() *config.Config {
	return &config.Config{
		JWTSecret:          "test-secret-key",
		JWTExpiry:          15 * 60e9,
		RefreshTokenExpiry: 30 * 24 * 60e9,
		OAuthGoogleID:      "google-client-id",
		OAuthGoogleSecret:  "google-client-secret",
		OAuthGitHubID:      "github-client-id",
		OAuthGitHubSecret:  "github-client-secret",
		OAuthRedirectBase:  "http://localhost:8080",
		AppScheme:          "terra",
		OAuthRedirectURIs: []string{
			"http://127.0.0.1:1421/oauth/callback",
			"http://127.0.0.1:1422/oauth/callback",
			"http://127.0.0.1:1423/oauth/callback",
		},
	}
}

func oauthRouter(db *gorm.DB, cfg *config.Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())

	apiAuth := r.Group("/api/v1/auth")
	apiAuth.GET("/oauth/start/:provider", HandleOAuthStart(db, cfg))
	apiAuth.GET("/oauth/callback/:provider", HandleOAuthCallback(db, cfg))
	apiAuth.POST("/oauth/exchange", HandleOAuthExchange(db, cfg))
	apiAuth.POST("/oauth/setup", HandleOAuthSetup(db, cfg))
	return r
}

func seedOAuthState(t *testing.T, db *gorm.DB, state, provider, codeVerifier, deviceID string, expiresAt time.Time, usedAt *time.Time, redirectURI string) {
	t.Helper()
	os := models.OAuthState{
		State:        state,
		Provider:     provider,
		CodeVerifier: codeVerifier,
		DeviceID:     deviceID,
		RedirectURI:  redirectURI,
		ExpiresAt:    expiresAt,
		UsedAt:       usedAt,
	}
	if err := db.Create(&os).Error; err != nil {
		t.Fatalf("seed OAuth state: %v", err)
	}
}

func seedAuthCode(t *testing.T, db *gorm.DB, code, purpose string, userID uuid.UUID, deviceID string, expiresAt time.Time, usedAt *time.Time) {
	t.Helper()
	codeHash := hashToken(code)
	ac := models.AuthCode{
		CodeHash:  codeHash,
		Purpose:   purpose,
		UserID:    userID,
		DeviceID:  deviceID,
		ExpiresAt: expiresAt,
		UsedAt:    usedAt,
	}
	if err := db.Create(&ac).Error; err != nil {
		t.Fatalf("seed auth code: %v", err)
	}
}

func seedOAuthUser(t *testing.T, db *gorm.DB, provider, providerSub, email string, initialized bool) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	user := models.User{
		ID:           userID,
		Email:        email,
		FullName:     email,
		AuthProvider: provider,
		ProviderSub:  &providerSub,
		Initialized:  initialized,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("seed OAuth user: %v", err)
	}
	return userID
}

func TestOAuthStart_ValidGoogle(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/start/google", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header")
	}
	if !contains(location, "accounts.google.com") {
		t.Errorf("expected Google auth URL, got: %s", location)
	}
	if !contains(location, "code_challenge=") {
		t.Errorf("expected code_challenge in URL, got: %s", location)
	}
	if !contains(location, "code_challenge_method=S256") {
		t.Errorf("expected code_challenge_method=S256 in URL, got: %s", location)
	}

	var count int64
	db.Model(&models.OAuthState{}).Count(&count)
	if count != 1 {
		t.Errorf("expected 1 OAuth state, got %d", count)
	}
}

func TestOAuthStart_ValidGitHub(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/start/github", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if !contains(location, "github.com") {
		t.Errorf("expected GitHub auth URL, got: %s", location)
	}
}

func TestOAuthStart_UnknownProvider(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/start/facebook", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthStart_UnconfiguredProvider(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	cfg.OAuthGoogleID = ""
	cfg.OAuthGoogleSecret = ""
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/start/google", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !contains(w.Body.String(), "PROVIDER_NOT_CONFIGURED") {
		t.Errorf("expected PROVIDER_NOT_CONFIGURED code, got: %s", w.Body.String())
	}
	if !contains(w.Body.String(), "not configured") {
		t.Errorf("expected 'not configured' message, got: %s", w.Body.String())
	}
}

func TestOAuthStart_UnconfiguredGitHub(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	cfg.OAuthGitHubID = ""
	cfg.OAuthGitHubSecret = ""
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/start/github", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !contains(w.Body.String(), "PROVIDER_NOT_CONFIGURED") {
		t.Errorf("expected PROVIDER_NOT_CONFIGURED code, got: %s", w.Body.String())
	}
}

func TestOAuthCallback_ProviderError_RedirectsToClient(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	seedOAuthState(t, db, "err-state", "google", "verifier", "dev1", time.Now().Add(10*time.Minute), nil, "http://127.0.0.1:1421/oauth/callback")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?error=access_denied&state=err-state", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !contains(location, "http://127.0.0.1:1421/oauth/callback") {
		t.Errorf("expected redirect to stored app callback, got: %s", location)
	}
	if !contains(location, "dest=error") {
		t.Errorf("expected dest=error, got: %s", location)
	}
	if !contains(location, "access_denied") {
		t.Errorf("expected provider error message, got: %s", location)
	}

	var os models.OAuthState
	db.Where("state = ?", "err-state").First(&os)
	if os.UsedAt == nil {
		t.Error("state should be marked used after provider error")
	}
}

func TestOAuthStart_StoresDeviceID(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/start/google?device_id=my-device", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	var os models.OAuthState
	db.Where("provider = ?", "google").First(&os)
	if os.DeviceID != "my-device" {
		t.Errorf("expected device_id 'my-device', got '%s'", os.DeviceID)
	}
}

func TestOAuthStart_RejectsUnregisteredAppCallback(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/start/google?app_callback=http://evil.example/cb", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthStart_JSONFormatWithAppCallback(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/oauth/start/google?device_id=dev-1&format=json&app_callback=http://127.0.0.1:1421/oauth/callback",
		nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data := resp["data"].(map[string]any)
	authURL, ok := data["auth_url"].(string)
	if !ok || !contains(authURL, "accounts.google.com") {
		t.Errorf("expected auth_url for Google, got: %v", data["auth_url"])
	}

	var os models.OAuthState
	db.Where("provider = ?", "google").First(&os)
	if os.RedirectURI != "http://127.0.0.1:1421/oauth/callback" {
		t.Errorf("expected RedirectURI stored, got %q", os.RedirectURI)
	}
}

func TestOAuthCallback_RedirectsToStoredAppCallback(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	usedAt := time.Now()
	seedOAuthState(t, db, "cb-state", "google", "verifier", "dev1", time.Now().Add(10*time.Minute), &usedAt, "http://127.0.0.1:1421/oauth/callback")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?code=abc&state=cb-state", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !contains(location, "http://127.0.0.1:1421/oauth/callback") {
		t.Errorf("expected redirect to stored app callback, got: %s", location)
	}
	if !contains(location, "dest=error") {
		t.Errorf("expected dest=error, got: %s", location)
	}
	if !contains(location, "state_already_used") {
		t.Errorf("expected state_already_used, got: %s", location)
	}
	if contains(location, "terra://") {
		t.Errorf("expected loopback redirect, not app scheme, got: %s", location)
	}
}

func TestOAuthCallback_InvalidState(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?code=abc&state=nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if !contains(location, "auth/error") {
		t.Errorf("expected error redirect, got: %s", location)
	}
	if !contains(location, "invalid_state") {
		t.Errorf("expected invalid_state in redirect, got: %s", location)
	}
}

func TestOAuthCallback_UsedState(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	usedAt := time.Now()
	seedOAuthState(t, db, "used-state", "google", "verifier", "dev1", time.Now().Add(10*time.Minute), &usedAt, "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?code=abc&state=used-state", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !contains(location, "state_already_used") {
		t.Errorf("expected state_already_used, got: %s", location)
	}
}

func TestOAuthCallback_ExpiredState(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	seedOAuthState(t, db, "expired-state", "google", "verifier", "dev1", time.Now().Add(-1*time.Hour), nil, "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?code=abc&state=expired-state", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !contains(location, "state_expired") {
		t.Errorf("expected state_expired, got: %s", location)
	}
}

func TestOAuthCallback_MissingCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?state=abc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !contains(location, "missing_code_or_state") {
		t.Errorf("expected missing_code_or_state, got: %s", location)
	}
}

func TestOAuthCallback_MissingState(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?code=abc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !contains(location, "missing_code_or_state") {
		t.Errorf("expected missing_code_or_state, got: %s", location)
	}
}

func TestOAuthCallback_CreatesVerifiedUser(t *testing.T) {
	db := setupTestDB(t)

	ui := &userInfo{Email: "new-oauth@example.com", Name: "New OAuth User", ProviderSub: "new-sub-1"}
	user, err := linkOrCreateOAuthUser(db, "google", ui)
	if err != nil {
		t.Fatalf("linkOrCreateOAuthUser: %v", err)
	}
	if user.EmailVerifiedAt == nil {
		t.Error("new OAuth user should be email-verified at creation")
	}

	var persisted models.User
	if err := db.Where("id = ?", user.ID).First(&persisted).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if persisted.EmailVerifiedAt == nil {
		t.Error("created user row should have email_verified_at set")
	}
}

func TestOAuthCallback_LinksExistingEmailVerified(t *testing.T) {
	db := setupTestDB(t)

	existing := models.User{
		ID:       uuid.New(),
		Email:    "existing-oauth@example.com",
		FullName: "Existing User",
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	ui := &userInfo{Email: "existing-oauth@example.com", Name: "Existing User", ProviderSub: "link-sub-1"}
	user, err := linkOrCreateOAuthUser(db, "google", ui)
	if err != nil {
		t.Fatalf("linkOrCreateOAuthUser: %v", err)
	}
	if user.ID != existing.ID {
		t.Errorf("expected linked user id %s, got %s", existing.ID, user.ID)
	}
	if user.EmailVerifiedAt == nil {
		t.Error("email-linked OAuth user should be email-verified at link time")
	}

	var persisted models.User
	if err := db.Where("id = ?", user.ID).First(&persisted).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if persisted.EmailVerifiedAt == nil {
		t.Error("linked user row should have email_verified_at set")
	}
}

func TestOAuthExchange_ValidCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "exchange@example.com", false)
	seedAuthCode(t, db, "valid-exchange-code", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), nil)

	body, _ := json.Marshal(gin.H{
		"setup_code": "valid-exchange-code",
		"user_id":    uid.String(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	data := resp["data"].(map[string]any)
	if data["access_token"] == nil || data["access_token"] == "" {
		t.Error("access_token should not be empty")
	}
	if data["refresh_token"] == nil || data["refresh_token"] == "" {
		t.Error("refresh_token should not be empty")
	}
	if data["initialized"] != false {
		t.Error("expected initialized=false for new OAuth user")
	}

	var ac models.AuthCode
	codeHash := hashToken("valid-exchange-code")
	db.Where("code_hash = ?", codeHash).First(&ac)
	if ac.UsedAt == nil {
		t.Error("setup code should be marked as used")
	}

	// Regression: the refresh token must be persisted server-side so the
	// client can refresh after a relaunch. Previously the OAuth paths
	// returned a JWT that was never stored -> 401 "invalid refresh token".
	r.POST("/api/v1/auth/refresh", HandleRefresh(db, cfg))
	rt := data["refresh_token"].(string)
	body2, _ := json.Marshal(gin.H{"refresh_token": rt})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected refresh 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestOAuthExchange_ExpiredCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "expired-exchange@example.com", false)
	seedAuthCode(t, db, "expired-exchange-code", "oauth_setup", uid, "dev1", time.Now().Add(-1*time.Hour), nil)

	body, _ := json.Marshal(gin.H{
		"setup_code": "expired-exchange-code",
		"user_id":    uid.String(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthExchange_UsedCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "used-exchange@example.com", false)
	usedAt := time.Now()
	seedAuthCode(t, db, "used-exchange-code", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), &usedAt)

	body, _ := json.Marshal(gin.H{
		"setup_code": "used-exchange-code",
		"user_id":    uid.String(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthExchange_InvalidCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"setup_code": "nonexistent-code",
		"user_id":    uuid.New().String(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthSetup_ValidSetupToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "setup@example.com", false)
	seedAuthCode(t, db, "valid-setup-token", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), nil)

	recoveryCode := "recovery-code-123"
	body, _ := json.Marshal(gin.H{
		"setup_token":   "valid-setup-token",
		"auth_verifier": "new-verifier",
		"recovery_code": base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"public_key":    "base64-public-key",
		"keyring": gin.H{
			"dek_wrapped_by_kek":         "dek-a",
			"dek_wrapped_by_recovery":    "dek-b",
			"private_key_wrapped_by_dek": "priv-c",
		},
		"kdf": gin.H{
			"m": 65536,
			"t": 3,
			"p": 2,
		},
		"server_salt": "server-salt",
		"salt_cl":     "client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	data := resp["data"].(map[string]any)
	if data["access_token"] == nil || data["access_token"] == "" {
		t.Error("access_token should not be empty")
	}
	if data["refresh_token"] == nil || data["refresh_token"] == "" {
		t.Error("refresh_token should not be empty")
	}

	// Regression: oauth/setup must persist the refresh token server-side,
	// otherwise the first relaunch after signup logs the user out.
	r.POST("/api/v1/auth/refresh", HandleRefresh(db, cfg))
	rt := data["refresh_token"].(string)
	body2, _ := json.Marshal(gin.H{"refresh_token": rt})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected refresh 200 after oauth setup, got %d: %s", w2.Code, w2.Body.String())
	}

	var user models.User
	db.Where("id = ?", uid).First(&user)
	if !user.Initialized {
		t.Error("user should be initialized after setup")
	}
	if user.AuthVerifier == nil || *user.AuthVerifier != "new-verifier" {
		t.Error("auth_verifier should be set")
	}
	if user.AuthSalt == nil || *user.AuthSalt != "server-salt" {
		t.Errorf("server_salt: want server-salt, got %v", user.AuthSalt)
	}
	if user.SaltCL == nil || *user.SaltCL != "client-salt" {
		t.Errorf("salt_cl: want client-salt, got %v", user.SaltCL)
	}
	if user.KDFM != 65536 || user.KDFT != 3 || user.KDFP != 2 {
		t.Errorf("kdf not stored: %d/%d/%d", user.KDFM, user.KDFT, user.KDFP)
	}
	if user.PublicKey == nil || *user.PublicKey != "base64-public-key" {
		t.Errorf("public_key not stored: %v", user.PublicKey)
	}
	expectedCodeHash := sha256.Sum256([]byte(recoveryCode))
	expectedB64 := base64.RawStdEncoding.EncodeToString(expectedCodeHash[:])
	if user.RecoveryHash == nil || *user.RecoveryHash != expectedB64 {
		t.Errorf("recovery_hash: want %q, got %v", expectedB64, user.RecoveryHash)
	}

	rows := map[string]string{}
	var uks []models.UserKey
	db.Where("user_id = ?", uid).Find(&uks)
	for _, uk := range uks {
		rows[uk.KeyType] = uk.Payload
	}
	if rows["dek_wrapped_by_kek"] != "dek-a" {
		t.Errorf("dek_wrapped_by_kek: want dek-a, got %q", rows["dek_wrapped_by_kek"])
	}
	if rows["dek_wrapped_by_recovery"] != "dek-b" {
		t.Errorf("dek_wrapped_by_recovery: want dek-b, got %q", rows["dek_wrapped_by_recovery"])
	}
	if rows["private_key_wrapped_by_dek"] != "priv-c" {
		t.Errorf("private_key_wrapped_by_dek: want priv-c, got %q", rows["private_key_wrapped_by_dek"])
	}
	if len(uks) != 3 {
		t.Errorf("expected 3 keyring rows, got %d", len(uks))
	}
}

func TestOAuthSetup_ExpiredToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "expired-setup@example.com", false)
	seedAuthCode(t, db, "expired-setup-token", "oauth_setup", uid, "dev1", time.Now().Add(-1*time.Hour), nil)

	body, _ := json.Marshal(gin.H{
		"setup_token":   "expired-setup-token",
		"auth_verifier": "new-verifier",
		"server_salt":   "server-salt",
		"salt_cl":       "client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthSetup_AlreadyInitialized(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "init-setup@example.com", true)
	seedAuthCode(t, db, "init-setup-token", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), nil)

	body, _ := json.Marshal(gin.H{
		"setup_token":   "init-setup-token",
		"auth_verifier": "new-verifier",
		"server_salt":   "server-salt",
		"salt_cl":       "client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthSetup_UsedToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "used-setup@example.com", false)
	usedAt := time.Now()
	seedAuthCode(t, db, "used-setup-token", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), &usedAt)

	body, _ := json.Marshal(gin.H{
		"setup_token":   "used-setup-token",
		"auth_verifier": "new-verifier",
		"server_salt":   "server-salt",
		"salt_cl":       "client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthSetup_WithoutKeyring(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "no-keyring-setup@example.com", false)
	seedAuthCode(t, db, "no-keyring-token", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), nil)

	body, _ := json.Marshal(gin.H{
		"setup_token":   "no-keyring-token",
		"auth_verifier": "new-verifier",
		"kdf":           gin.H{"m": 65536, "t": 3, "p": 2},
		"server_salt":   "server-salt",
		"salt_cl":       "client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int64
	db.Model(&models.UserKey{}).Where("user_id = ?", uid).Count(&count)
	if count != 0 {
		t.Errorf("expected no keyring rows when not provided, got %d", count)
	}
}

func TestOAuthSetup_InvalidToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"setup_token":   "nonexistent-token",
		"auth_verifier": "new-verifier",
		"server_salt":   "server-salt",
		"salt_cl":       "client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthSetup_EmptyBody(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthExchange_EmptyBody(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/exchange", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthSetup_WeakKDF_Rejected(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "weak-kdf-setup@example.com", false)
	seedAuthCode(t, db, "weak-kdf-setup-token", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), nil)

	body, _ := json.Marshal(gin.H{
		"setup_token":   "weak-kdf-setup-token",
		"auth_verifier": "new-verifier",
		"server_salt":   "server-salt",
		"salt_cl":       "client-salt",
		"kdf":           gin.H{"m": 1024, "t": 1, "p": 1},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
