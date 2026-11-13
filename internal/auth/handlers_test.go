package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	gormsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	return db
}

func setupHandlerRouter(db *gorm.DB, cfg *config.Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())
	auth := r.Group("/api/v1/auth")
	auth.POST("/prelogin", HandlePrelogin(db, cfg))
	auth.POST("/register", HandleRegister(db, cfg))
	auth.POST("/verify-email", HandleVerifyEmail(db, cfg))
	auth.POST("/resend-verification", HandleResendVerification(db, cfg))
	auth.POST("/login", HandleLogin(db, cfg))
	auth.POST("/refresh", HandleRefresh(db, cfg))
	auth.POST("/logout", HandleLogout(db))
	auth.POST("/recovery", HandleRecovery(db, cfg))
	auth.POST("/recovery/prefetch", HandleRecoveryPrefetch(db))

	protected := r.Group("/api/v1")
	protected.Use(JWTMiddleware(cfg))
	protected.GET("/me", HandleMe(db))
	protected.GET("/auth/keyring", HandleKeyring(db))
	protected.POST("/auth/password-change", HandlePasswordChange(db, cfg))
	protected.POST("/auth/recovery-material", HandleAttachRecoveryMaterial(db, cfg))
	protected.POST("/me/deletion", HandleRequestDeletion(db, cfg))
	protected.DELETE("/me/deletion", HandleCancelDeletion(db))
	return r
}

func testConfig() *config.Config {
	return &config.Config{
		JWTSecret:          "test-secret-key",
		JWTExpiry:          15 * 60e9,
		RefreshTokenExpiry: 30 * 24 * 60e9,
	}
}

func testConfigWithVerification() *config.Config {
	cfg := testConfig()
	cfg.RequireEmailVerification = true
	// tests have no SMTP; log the OTP like a dev server would
	cfg.LogOtpFallback = true
	return cfg
}

func registerRequestPayload(email, userID string) map[string]any {
	return map[string]any{
		"user_id":       userID,
		"email":         email,
		"full_name":     email,
		"password_hash": base64.RawStdEncoding.EncodeToString([]byte("verifier-bytes")),
		"keyring": map[string]string{
			"dek_wrapped_by_kek":         "kek",
			"dek_wrapped_by_recovery":    "rec",
			"private_key_wrapped_by_dek": "pk",
		},
		"kdf":         map[string]int{"m": 32768, "t": 2, "p": 1},
		"server_salt": "server-salt",
		"salt_cl":     "salt-cl",
	}
}

func seedUserWithVerifier(t *testing.T, db *gorm.DB, email string) (uuid.UUID, []byte) {
	t.Helper()
	userID := uuid.New()
	verifier := []byte("test-secret-verifier-bytes")
	verifierB64 := base64.RawStdEncoding.EncodeToString(verifier)
	salt := "test-salt"
	saltCL := "test-salt-cl"
	user := models.User{
		ID:           userID,
		Email:        email,
		FullName:     email,
		AuthProvider: "password",
		AuthVerifier: &verifierB64,
		AuthSalt:     &salt,
		SaltCL:       &saltCL,
		KDFM:         67108864,
		KDFT:         3,
		KDFP:         1,
		Initialized:  true,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return userID, verifier
}

func seedUnverifiedUser(t *testing.T, db *gorm.DB, email string) (uuid.UUID, string) {
	t.Helper()
	userID, _ := seedUserWithVerifier(t, db, email)
	for _, keyType := range []string{"dek_wrapped_by_kek", "dek_wrapped_by_recovery", "private_key_wrapped_by_dek"} {
		db.Create(&models.UserKey{UserID: userID, KeyType: keyType, Payload: "wrapped-" + keyType})
	}
	otp, err := issueEmailVerifyCode(db, userID)
	if err != nil {
		t.Fatal(err)
	}
	return userID, otp
}

func seedLoginNonce(t *testing.T, db *gorm.DB, email, nonceB64 string) {
	t.Helper()
	if err := db.Create(&models.LoginNonce{
		Email:     email,
		NonceHash: hashToken(nonceB64),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}).Error; err != nil {
		t.Fatalf("seed login nonce: %v", err)
	}
}

func makeVerifyEmailRequest(email, otp string) *http.Request {
	raw, _ := json.Marshal(map[string]string{"email": email, "otp": otp, "device_id": "dev-1"})
	req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func makeAccessToken(userID uuid.UUID, cfg *config.Config) string {
	at, err := GenerateAccessToken(userID, "", cfg)
	if err != nil {
		panic("makeAccessToken: " + err.Error())
	}
	return at
}

func makeAccessTokenForDevice(userID uuid.UUID, deviceID string, cfg *config.Config) string {
	at, err := GenerateAccessToken(userID, deviceID, cfg)
	if err != nil {
		panic("makeAccessTokenForDevice: " + err.Error())
	}
	return at
}

const testPublicKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHw"

func seedRecoveryCode(db *gorm.DB, userID uuid.UUID, recoveryCode string) {
	codeHash := sha256.Sum256([]byte(recoveryCode))
	codeHashB64 := base64.RawStdEncoding.EncodeToString(codeHash[:])
	db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]any{
		"recovery_hash": codeHashB64,
		"public_key":    testPublicKey,
	})
}

func recoverySignature(t *testing.T, nonceB64 string) string {
	t.Helper()
	pubKey, err := base64.RawStdEncoding.DecodeString(testPublicKey)
	if err != nil {
		t.Fatalf("pubkey decode: %v", err)
	}
	nonceBytes, err := base64.RawStdEncoding.DecodeString(nonceB64)
	if err != nil {
		t.Fatalf("nonce decode: %v", err)
	}
	mac := hmac.New(sha256.New, pubKey)
	mac.Write(nonceBytes)
	return base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
}

func TestPrelogin_KnownEmail(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()

	salt := "stored-salt"
	saltCL := "stored-salt-cl"
	verifier := "stored-verifier"
	user := models.User{
		ID:           uuid.New(),
		Email:        "alice@example.com",
		FullName:     "Alice",
		AuthProvider: "password",
		AuthSalt:     &salt,
		SaltCL:       &saltCL,
		AuthVerifier: &verifier,
		KDFM:         67108864,
		KDFT:         3,
		KDFP:         1,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{"email": "alice@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/prelogin", bytes.NewReader(body))
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

	data, ok := resp["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object, got %v", resp["data"])
	}

	if data["server_salt"] != salt {
		t.Errorf("server_salt: want %q, got %v", salt, data["server_salt"])
	}
	if data["salt_cl"] != saltCL {
		t.Errorf("salt_cl: want %q, got %v", saltCL, data["salt_cl"])
	}
	if data["nonce"] == nil || data["nonce"] == "" {
		t.Error("nonce should not be empty")
	}

	kdf, ok := data["kdf"].(map[string]any)
	if !ok {
		t.Fatalf("expected kdf object, got %v", data["kdf"])
	}
	if int(kdf["m"].(float64)) != 67108864 {
		t.Errorf("kdf.m: want 67108864, got %v", kdf["m"])
	}
	if int(kdf["t"].(float64)) != 3 {
		t.Errorf("kdf.t: want 3, got %v", kdf["t"])
	}
	if int(kdf["p"].(float64)) != 1 {
		t.Errorf("kdf.p: want 1, got %v", kdf["p"])
	}
}

func TestPrelogin_UnknownEmail(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{"email": "nobody@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/prelogin", bytes.NewReader(body))
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
	if data["nonce"] == nil || data["nonce"] == "" {
		t.Error("nonce should not be empty (random fallback)")
	}
	if data["server_salt"] == nil || data["server_salt"] == "" {
		t.Error("server_salt should not be empty (random fallback)")
	}
	if data["salt_cl"] == nil || data["salt_cl"] == "" {
		t.Error("salt_cl should not be empty (random fallback)")
	}
	if data["kdf"] == nil {
		t.Error("kdf should not be nil (random fallback)")
	}
}

func TestPrelogin_EmptyBody(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/prelogin", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_NewUser(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	userID := uuid.New()
	body, _ := json.Marshal(gin.H{
		"user_id":           userID.String(),
		"email":             "bob@example.com",
		"password_hash":     "base64-verifier",
		"encrypted_dek":     "base64-dek",
		"encrypted_privkey": "base64-privkey",
		"kdf":               map[string]int{"m": 67108864, "t": 3, "p": 1},
		"server_salt":       "server-salt",
		"salt_cl":           "client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
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

	// Regression: register must persist the refresh token server-side,
	// otherwise a relaunch cannot refresh and the user gets logged out.
	rt := data["refresh_token"].(string)
	body2, _ := json.Marshal(gin.H{"refresh_token": rt})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected refresh 200 after register, got %d: %s", w2.Code, w2.Body.String())
	}

	userObj, ok := data["user"].(map[string]any)
	if !ok {
		t.Fatalf("expected user object, got %v", data["user"])
	}
	if userObj["email"] != "bob@example.com" {
		t.Errorf("user.email: want bob@example.com, got %v", userObj["email"])
	}
	if userObj["id"] != userID.String() {
		t.Errorf("user.id: want %s, got %v", userID, userObj["id"])
	}

	var vault models.Vault
	if err := db.Where("owner_id = ? AND kind = ?", userID, "personal").First(&vault).Error; err != nil {
		t.Errorf("personal vault not created: %v", err)
	}
}

func TestRegister_ExistingEmail(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()

	salt := "existing-salt"
	saltCL := "existing-salt-cl"
	existing := models.User{
		ID:           uuid.New(),
		Email:        "taken@example.com",
		FullName:     "Existing",
		AuthProvider: "password",
		AuthSalt:     &salt,
		SaltCL:       &saltCL,
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"user_id":       uuid.New().String(),
		"email":         "taken@example.com",
		"password_hash": "base64-verifier",
		"kdf":           map[string]int{"m": 67108864, "t": 3, "p": 1},
		"server_salt":   "server-salt",
		"salt_cl":       "client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_ExistingEmail_VerificationOn_Uniform(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfigWithVerification()

	storedID := uuid.New()
	salt := "existing-salt"
	saltCL := "existing-salt-cl"
	existing := models.User{
		ID:           storedID,
		Email:        "taken2@example.com",
		FullName:     "Stored Full Name",
		AuthProvider: "password",
		AuthSalt:     &salt,
		SaltCL:       &saltCL,
		KDFM:         67108864,
		KDFT:         3,
		KDFP:         1,
		CreatedAt:    time.Now().Add(-24 * time.Hour),
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	var usersBefore int64
	db.Model(&models.User{}).Count(&usersBefore)

	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"user_id":       uuid.New().String(),
		"email":         "taken2@example.com",
		"full_name":     "Probe Name",
		"password_hash": "base64-verifier",
		"kdf":           map[string]int{"m": 32768, "t": 2, "p": 1},
		"server_salt":   "probe-server-salt",
		"salt_cl":       "probe-salt-cl",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}

	// no rows created, no OTP issued to the real owner
	var usersAfter int64
	db.Model(&models.User{}).Count(&usersAfter)
	if usersAfter != usersBefore {
		t.Fatalf("expected no new user row, before=%d after=%d", usersBefore, usersAfter)
	}
	var codeCount int64
	db.Model(&models.AuthCode{}).Where("user_id = ? AND purpose = ?", storedID, emailVerifyPurpose).Count(&codeCount)
	if codeCount != 0 {
		t.Fatalf("expected no verification code issued for existing account, got %d", codeCount)
	}
}

func TestRegister_DuplicateSamePayload_Rejected(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()

	userID := uuid.New()
	salt := "server-salt"
	saltCL := "client-salt"
	verifier := "base64-verifier"
	existing := models.User{
		ID:           userID,
		Email:        "idempotent@example.com",
		FullName:     "Existing",
		AuthProvider: "password",
		AuthVerifier: &verifier,
		AuthSalt:     &salt,
		SaltCL:       &saltCL,
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"user_id":       userID.String(),
		"email":         "idempotent@example.com",
		"password_hash": "base64-verifier",
		"kdf":           map[string]int{"m": 67108864, "t": 3, "p": 1},
		"server_salt":   "new-server-salt",
		"salt_cl":       "new-client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate register, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_Idempotent_WrongVerifier_Rejected(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()

	userID := uuid.New()
	salt := "server-salt"
	saltCL := "client-salt"
	verifier := "correct-verifier"
	existing := models.User{
		ID:           userID,
		Email:        "idem-attack@example.com",
		FullName:     "Existing",
		AuthProvider: "password",
		AuthVerifier: &verifier,
		AuthSalt:     &salt,
		SaltCL:       &saltCL,
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"user_id":       userID.String(),
		"email":         "idem-attack@example.com",
		"password_hash": "attacker-guessed-verifier",
		"kdf":           map[string]int{"m": 67108864, "t": 3, "p": 1},
		"server_salt":   "new-server-salt",
		"salt_cl":       "new-client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_Idempotent_WrongEmail_Rejected(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()

	userID := uuid.New()
	salt := "server-salt"
	saltCL := "client-salt"
	verifier := "correct-verifier"
	existing := models.User{
		ID:           userID,
		Email:        "victim@example.com",
		FullName:     "Existing",
		AuthProvider: "password",
		AuthVerifier: &verifier,
		AuthSalt:     &salt,
		SaltCL:       &saltCL,
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"user_id":       userID.String(),
		"email":         "attacker@example.com",
		"password_hash": "correct-verifier",
		"kdf":           map[string]int{"m": 67108864, "t": 3, "p": 1},
		"server_salt":   "new-server-salt",
		"salt_cl":       "new-client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_VerificationRequired_NoTokens(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())

	body := registerRequestPayload("verify@example.com", uuid.New().String())
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			VerificationRequired bool   `json:"verification_required"`
			AccessToken          string `json:"access_token"`
			RefreshToken         string `json:"refresh_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Data.VerificationRequired {
		t.Fatal("expected verification_required true")
	}
	if resp.Data.AccessToken != "" || resp.Data.RefreshToken != "" {
		t.Fatal("expected no tokens in register response")
	}

	var user models.User
	if err := db.Where("email = ?", "verify@example.com").First(&user).Error; err != nil {
		t.Fatal(err)
	}
	if user.EmailVerifiedAt != nil {
		t.Fatal("expected user unverified")
	}
	var codeCount int64
	db.Model(&models.AuthCode{}).Where("user_id = ? AND purpose = ?", user.ID, emailVerifyPurpose).Count(&codeCount)
	if codeCount != 1 {
		t.Fatalf("expected 1 verification code, got %d", codeCount)
	}
}

func TestRegister_VerificationOff_ReturnsTokens(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())

	body := registerRequestPayload("plain@example.com", uuid.New().String())
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			VerificationRequired bool   `json:"verification_required"`
			AccessToken          string `json:"access_token"`
			RefreshToken         string `json:"refresh_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.AccessToken == "" {
		t.Fatal("expected access token when verification off")
	}
	if resp.Data.RefreshToken == "" {
		t.Fatal("expected refresh token when verification off")
	}
	if resp.Data.VerificationRequired {
		t.Fatal("expected no verification_required flag")
	}
}

func TestRegister_TokensUseSuppliedDeviceID(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	deviceID := uuid.New().String()
	body := registerRequestPayload("register-device@example.com", uuid.New().String())
	body["device_id"] = deviceID
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyAccessToken(resp.Data.AccessToken, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if claims.DeviceID != deviceID {
		t.Fatalf("access token device: got %q, want %q", claims.DeviceID, deviceID)
	}
	refreshRaw, _ := json.Marshal(gin.H{"refresh_token": resp.Data.RefreshToken})
	refreshReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(refreshRaw))
	refreshReq.Header.Set("Content-Type", "application/json")
	refresh := httptest.NewRecorder()
	r.ServeHTTP(refresh, refreshReq)
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", refresh.Code, refresh.Body.String())
	}
	var refreshed struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(refresh.Body.Bytes(), &refreshed); err != nil {
		t.Fatal(err)
	}
	claims, err = VerifyAccessToken(refreshed.Data.AccessToken, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if claims.DeviceID != deviceID {
		t.Fatalf("refreshed access token device: got %q, want %q", claims.DeviceID, deviceID)
	}
}

func TestRegister_VerificationRequired_Reissue(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())

	userID := uuid.New().String()
	body := registerRequestPayload("reissue@example.com", userID)
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(raw))
	req2.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 on re-register, got %d: %s", w2.Code, w2.Body.String())
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		t.Fatal(err)
	}
	var codeCount int64
	db.Model(&models.AuthCode{}).Where("user_id = ? AND purpose = ?", uid, emailVerifyPurpose).Count(&codeCount)
	if codeCount != 1 {
		t.Fatalf("expected exactly 1 verification code after re-register, got %d", codeCount)
	}
}

func TestVerifyEmail_Success(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())
	userID, otp := seedUnverifiedUser(t, db, "verify-ok@example.com")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, makeVerifyEmailRequest("verify-ok@example.com", otp))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			AccessToken  string            `json:"access_token"`
			RefreshToken string            `json:"refresh_token"`
			Keyring      map[string]string `json:"keyring"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.AccessToken == "" || resp.Data.RefreshToken == "" {
		t.Fatal("expected tokens after verification")
	}
	if resp.Data.Keyring == nil {
		t.Fatal("expected keyring in verify response")
	}

	var user models.User
	db.First(&user, "id = ?", userID)
	if user.EmailVerifiedAt == nil {
		t.Fatal("expected user verified")
	}
	var codeCount int64
	db.Model(&models.AuthCode{}).Where("user_id = ? AND purpose = ?", userID, emailVerifyPurpose).Count(&codeCount)
	if codeCount != 0 {
		t.Fatalf("expected code row deleted after verification, got %d", codeCount)
	}

	// refresh token must be usable
	var rt models.RefreshToken
	if err := db.Where("user_id = ?", userID).First(&rt).Error; err != nil {
		t.Fatalf("expected refresh token row: %v", err)
	}
}

func TestVerifyEmail_WrongCode_ExhaustsAttempts(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())
	userID, otp := seedUnverifiedUser(t, db, "brute@example.com")

	for i := 1; i <= maxOtpAttempts; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, makeVerifyEmailRequest("brute@example.com", "000000"))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: expected 400, got %d", i, w.Code)
		}
		if otp == "000000" {
			t.Fatal("test otp collided with wrong code")
		}
	}

	// after 5 failures the row is gone; next attempt still 400
	w := httptest.NewRecorder()
	r.ServeHTTP(w, makeVerifyEmailRequest("brute@example.com", otp))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 after attempts exhausted, got %d", w.Code)
	}
	var user models.User
	db.First(&user, "id = ?", userID)
	if user.EmailVerifiedAt != nil {
		t.Fatal("user must not be verified after exhausted attempts")
	}
	var codeCount int64
	db.Model(&models.AuthCode{}).Where("user_id = ? AND purpose = ?", userID, emailVerifyPurpose).Count(&codeCount)
	if codeCount != 0 {
		t.Fatalf("expected code row deleted after 5 attempts, got %d", codeCount)
	}
}

func TestVerifyEmail_ExpiredCode(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())
	userID, otp := seedUnverifiedUser(t, db, "expired@example.com")

	db.Model(&models.AuthCode{}).Where("user_id = ? AND purpose = ?", userID, emailVerifyPurpose).
		Update("expires_at", time.Now().Add(-time.Hour))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, makeVerifyEmailRequest("expired@example.com", otp))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyEmail_UnknownEmail(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, makeVerifyEmailRequest("nobody@example.com", "123456"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error.Code != "INVALID_VERIFICATION_CODE" {
		t.Fatalf("expected INVALID_VERIFICATION_CODE, got %s", resp.Error.Code)
	}
}

func TestVerifyEmail_AlreadyVerified(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())
	userID, _ := seedUnverifiedUser(t, db, "already@example.com")
	now := time.Now()
	db.Model(&models.User{}).Where("id = ?", userID).Update("email_verified_at", &now)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, makeVerifyEmailRequest("already@example.com", "123456"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error.Code != "INVALID_VERIFICATION_CODE" {
		t.Fatalf("expected INVALID_VERIFICATION_CODE, got %s", resp.Error.Code)
	}
}

func TestVerifyEmail_UnknownAndWrongCode_Identical(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())
	_, _ = seedUnverifiedUser(t, db, "probe@example.com")

	wrong := httptest.NewRecorder()
	r.ServeHTTP(wrong, makeVerifyEmailRequest("probe@example.com", "999999"))

	unknown := httptest.NewRecorder()
	r.ServeHTTP(unknown, makeVerifyEmailRequest("ghost@example.com", "999999"))

	if wrong.Code != http.StatusBadRequest || unknown.Code != http.StatusBadRequest {
		t.Fatalf("statuses must match: wrong=%d unknown=%d", wrong.Code, unknown.Code)
	}
	if wrong.Body.String() != unknown.Body.String() {
		t.Fatalf("bodies must be identical:\n wrong:  %s\n unknown: %s", wrong.Body.String(), unknown.Body.String())
	}
}

func TestRegister_VerifiedUser_RejectsDuplicate(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())

	userID := uuid.New()
	now := time.Now()
	salt := "server-salt"
	saltCL := "client-salt"
	verifier := base64.RawStdEncoding.EncodeToString([]byte("verifier-bytes"))
	existing := models.User{
		ID:              userID,
		Email:           "verified@example.com",
		FullName:        "Verified",
		AuthProvider:    "password",
		AuthVerifier:    &verifier,
		AuthSalt:        &salt,
		SaltCL:          &saltCL,
		EmailVerifiedAt: &now,
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	body := registerRequestPayload("verified@example.com", userID.String())
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for existing verified user, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	code, _ := resp["error"].(map[string]any)["code"].(string)
	if code != "CONFLICT" {
		t.Fatalf("expected CONFLICT, got %q", code)
	}
}

func TestRegister_StoresKeyringAndRecovery(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	userID := uuid.New()
	recoveryCode := "recovery-code-123"
	body, _ := json.Marshal(gin.H{
		"user_id":       userID.String(),
		"email":         "keyring@example.com",
		"password_hash": "base64-verifier",
		"recovery_code": base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"public_key":    "base64-public-key",
		"keyring": gin.H{
			"dek_wrapped_by_kek":         "dek-a",
			"dek_wrapped_by_recovery":    "dek-b",
			"private_key_wrapped_by_dek": "priv-c",
		},
		"kdf":         map[string]int{"m": 67108864, "t": 3, "p": 1},
		"server_salt": "server-salt",
		"salt_cl":     "client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var user models.User
	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
		t.Fatalf("user not found: %v", err)
	}
	if user.PublicKey == nil || *user.PublicKey != "base64-public-key" {
		t.Errorf("public_key not stored: %v", user.PublicKey)
	}
	expectedCodeHash := sha256.Sum256([]byte(recoveryCode))
	expectedB64 := base64.RawStdEncoding.EncodeToString(expectedCodeHash[:])
	if user.RecoveryHash == nil || *user.RecoveryHash != expectedB64 {
		t.Errorf("recovery_hash: want %q, got %v", expectedB64, user.RecoveryHash)
	}

	var count int64
	db.Model(&models.UserKey{}).Where("user_id = ?", userID).Count(&count)
	if count != 3 {
		t.Fatalf("expected 3 keyring rows, got %d", count)
	}

	loginBody, _ := json.Marshal(gin.H{
		"email":     "keyring@example.com",
		"proof":     base64.RawStdEncoding.EncodeToString([]byte("dummy")),
		"nonce":     base64.RawStdEncoding.EncodeToString([]byte("dummy")),
		"device_id": "dev-1",
	})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	r.ServeHTTP(loginW, loginReq)

	// wrong proof → 401, keyring should still echo once a valid login succeeds
	if loginW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with bad proof, got %d", loginW.Code)
	}
}

func TestRecoveryPrefetch(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "prefetch@example.com")
	recoveryCode := "prefetch-code"
	codeHash := sha256.Sum256([]byte(recoveryCode))
	codeHashB64 := base64.RawStdEncoding.EncodeToString(codeHash[:])
	db.Model(&models.User{}).Where("id = ?", uid).Update("recovery_hash", codeHashB64)

	saltCL := "prefetch-salt-cl"
	db.Model(&models.User{}).Where("id = ?", uid).Update("salt_cl", saltCL)
	db.Create(&models.UserKey{
		UserID:  uid,
		KeyType: "dek_wrapped_by_recovery",
		Payload: "wrapped-recovery-dek",
	})
	db.Create(&models.UserKey{
		UserID:  uid,
		KeyType: "private_key_wrapped_by_dek",
		Payload: "wrapped-private-key",
	})

	body, _ := json.Marshal(gin.H{
		"recovery_code": base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery/prefetch", bytes.NewReader(body))
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
	if data["salt_cl"] != saltCL {
		t.Errorf("salt_cl: want %q, got %v", saltCL, data["salt_cl"])
	}
	if data["email"] != "prefetch@example.com" {
		t.Errorf("email: want %q, got %v", "prefetch@example.com", data["email"])
	}
	if data["dek_wrapped_by_recovery"] != "wrapped-recovery-dek" {
		t.Errorf("dek_wrapped_by_recovery: want wrapped-recovery-dek, got %v", data["dek_wrapped_by_recovery"])
	}
	if data["private_key_wrapped_by_dek"] != "wrapped-private-key" {
		t.Errorf("private_key_wrapped_by_dek: want wrapped-private-key, got %v", data["private_key_wrapped_by_dek"])
	}
	if data["nonce"] == nil || data["nonce"] == "" {
		t.Error("nonce should be present")
	}
}

func TestRecoveryPrefetch_InvalidCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"recovery_code": base64.RawStdEncoding.EncodeToString([]byte("wrong-code")),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery/prefetch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_InvalidBody(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_CorrectProof(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	_, verifier := seedUserWithVerifier(t, db, "alice@example.com")
	nonce := []byte("test-nonce-for-login")
	proof := GenerateProof(verifier, nonce)
	seedLoginNonce(t, db, "alice@example.com", base64.RawStdEncoding.EncodeToString(nonce))

	body, _ := json.Marshal(gin.H{
		"email":     "alice@example.com",
		"proof":     base64.RawStdEncoding.EncodeToString(proof),
		"nonce":     base64.RawStdEncoding.EncodeToString(nonce),
		"device_id": "device-1",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
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
	userObj, ok := data["user"].(map[string]any)
	if !ok {
		t.Fatalf("expected user object, got %v", data["user"])
	}
	if userObj["email"] != "alice@example.com" {
		t.Errorf("user.email: want alice@example.com, got %v", userObj["email"])
	}
}

func TestLogin_WrongProof(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	seedUserWithVerifier(t, db, "alice@example.com")
	wrongProof := []byte("wrong-proof-data")
	nonce := []byte("test-nonce")
	seedLoginNonce(t, db, "alice@example.com", base64.RawStdEncoding.EncodeToString(nonce))

	body, _ := json.Marshal(gin.H{
		"email": "alice@example.com",
		"proof": base64.RawStdEncoding.EncodeToString(wrongProof),
		"nonce": base64.RawStdEncoding.EncodeToString(nonce),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_NonExistentEmail(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"email": "nobody@example.com",
		"proof": "dGVzdA",
		"nonce": "dGVzdA",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("ok")
}

func TestLogin_ReplayNonce_Rejected(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	_, verifier := seedUserWithVerifier(t, db, "alice@example.com")
	nonce := []byte("replay-nonce")
	proof := GenerateProof(verifier, nonce)
	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)
	seedLoginNonce(t, db, "alice@example.com", nonceB64)

	login := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(gin.H{
			"email": "alice@example.com",
			"proof": base64.RawStdEncoding.EncodeToString(proof),
			"nonce": nonceB64,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	first := login()
	if first.Code != http.StatusOK {
		t.Fatalf("first login: expected 200, got %d: %s", first.Code, first.Body.String())
	}

	second := login()
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("replay: expected 401, got %d: %s", second.Code, second.Body.String())
	}
}

func TestLogin_NonceNeverIssued_Rejected(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	_, verifier := seedUserWithVerifier(t, db, "bob@example.com")
	nonce := []byte("never-issued-nonce")
	proof := GenerateProof(verifier, nonce)

	body, _ := json.Marshal(gin.H{
		"email": "bob@example.com",
		"proof": base64.RawStdEncoding.EncodeToString(proof),
		"nonce": base64.RawStdEncoding.EncodeToString(nonce),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (nonce never issued), got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_NonceForOtherEmail_Rejected(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	_, verifier := seedUserWithVerifier(t, db, "victim@example.com")
	_, _ = seedUserWithVerifier(t, db, "attacker@example.com")
	nonce := []byte("cross-email-nonce")
	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)
	seedLoginNonce(t, db, "attacker@example.com", nonceB64)

	// victim sends attacker-issued nonce: must be rejected even with a valid proof
	proof := GenerateProof(verifier, nonce)
	body, _ := json.Marshal(gin.H{
		"email": "victim@example.com",
		"proof": base64.RawStdEncoding.EncodeToString(proof),
		"nonce": nonceB64,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (nonce issued for another email), got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_ExpiredNonce_Rejected(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	_, verifier := seedUserWithVerifier(t, db, "tardy@example.com")
	nonce := []byte("expired-nonce")
	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)
	if err := db.Create(&models.LoginNonce{
		Email:     "tardy@example.com",
		NonceHash: hashToken(nonceB64),
		ExpiresAt: time.Now().Add(-time.Minute),
	}).Error; err != nil {
		t.Fatal(err)
	}

	proof := GenerateProof(verifier, nonce)
	body, _ := json.Marshal(gin.H{
		"email": "tardy@example.com",
		"proof": base64.RawStdEncoding.EncodeToString(proof),
		"nonce": nonceB64,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (expired nonce), got %d: %s", w.Code, w.Body.String())
	}
}

func TestPrelogin_StoresNonce(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	seedUserWithVerifier(t, db, "stored@example.com")

	body, _ := json.Marshal(gin.H{"email": "stored@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/prelogin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	nonce, _ := resp["data"].(map[string]any)["nonce"].(string)

	var nonceRow models.LoginNonce
	if err := db.Where("email = ? AND nonce_hash = ?", "stored@example.com", hashToken(nonce)).First(&nonceRow).Error; err != nil {
		t.Fatalf("expected stored login nonce, got: %v", err)
	}
	if nonceRow.UsedAt != nil {
		t.Fatal("fresh nonce must not be marked used")
	}
	if time.Now().After(nonceRow.ExpiresAt) {
		t.Fatal("fresh nonce must not be expired")
	}
}

func TestPasswordChange_ClearsNonces(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, verifier := seedUserWithVerifier(t, db, "clear@example.com")
	token := makeAccessToken(uid, cfg)

	nonce := []byte("clear-nonce")
	proof := GenerateProof(verifier, nonce)
	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)
	seedLoginNonce(t, db, "clear@example.com", nonceB64)

	body, _ := json.Marshal(gin.H{
		"old_proof":    base64.RawStdEncoding.EncodeToString(proof),
		"old_nonce":    nonceB64,
		"new_verifier": "fresh-verifier",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var count int64
	db.Model(&models.LoginNonce{}).Where("email = ?", "clear@example.com").Count(&count)
	if count != 0 {
		t.Fatalf("expected all nonces cleared after password change, got %d", count)
	}
}

func TestRefresh_ValidToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "refresh@example.com")
	rtToken, err := createRefreshToken(db, uid, "device-1", cfg)
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	body, _ := json.Marshal(gin.H{"refresh_token": rtToken})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
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
	if data["refresh_token"] == rtToken {
		t.Error("refresh_token should be rotated (different from old)")
	}
}

func TestRefresh_ExpiredToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "expired@example.com")
	rawToken := "expired-token-value"
	tokenHash := hashToken(rawToken)
	now := time.Now()
	rt := models.RefreshToken{
		UserID:    uid,
		TokenHash: tokenHash,
		DeviceID:  "device-1",
		ExpiresAt: now.Add(-1 * time.Hour),
	}
	db.Create(&rt)

	body, _ := json.Marshal(gin.H{"refresh_token": rawToken})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRefresh_ReuseDetection(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "reuse@example.com")

	rawToken1 := "token-for-rotation"
	tokenHash1 := hashToken(rawToken1)
	now := time.Now()
	rt1 := models.RefreshToken{
		UserID:    uid,
		TokenHash: tokenHash1,
		DeviceID:  "device-1",
		ExpiresAt: now.Add(24 * time.Hour),
	}
	db.Create(&rt1)

	body, _ := json.Marshal(gin.H{"refresh_token": rawToken1})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first refresh should succeed: %d: %s", w.Code, w.Body.String())
	}

	body2, _ := json.Marshal(gin.H{"refresh_token": rawToken1})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("reuse should return 401, got %d: %s", w2.Code, w2.Body.String())
	}

	var count int64
	db.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NOT NULL", uid).Count(&count)
	if count < 2 {
		t.Errorf("expected at least 2 revoked tokens after reuse, got %d", count)
	}
}

func TestLogout_ValidToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "logout@example.com")
	rtToken, err := createRefreshToken(db, uid, "device-1", cfg)
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	body, _ := json.Marshal(gin.H{"refresh_token": rtToken})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	tokenHash := hashToken(rtToken)
	var rt models.RefreshToken
	db.Where("token_hash = ?", tokenHash).First(&rt)
	if rt.RevokedAt == nil {
		t.Error("refresh token should be revoked after logout")
	}
}

func TestLogout_InvalidToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{"refresh_token": "nonexistent-token"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMe_ValidToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "me@example.com")
	token := makeAccessToken(uid, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
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
	if data["email"] != "me@example.com" {
		t.Errorf("email: want me@example.com, got %v", data["email"])
	}
	if data["id"] != uid.String() {
		t.Errorf("id: want %s, got %v", uid, data["id"])
	}
}

func TestMe_NoToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestKeyring_ValidToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "keyring@example.com")
	db.Create(&models.UserKey{UserID: uid, KeyType: "dek_wrapped_by_kek", Payload: "wrapped-kek"})
	db.Create(&models.UserKey{UserID: uid, KeyType: "dek_wrapped_by_recovery", Payload: "wrapped-recovery"})
	db.Create(&models.UserKey{UserID: uid, KeyType: "private_key_wrapped_by_dek", Payload: "wrapped-priv"})
	token := makeAccessToken(uid, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/keyring", nil)
	req.Header.Set("Authorization", "Bearer "+token)
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
	if data["salt_cl"] != "test-salt-cl" {
		t.Errorf("salt_cl: want test-salt-cl, got %v", data["salt_cl"])
	}
	keyring, ok := data["keyring"].(map[string]any)
	if !ok {
		t.Fatalf("expected keyring object, got %v", data["keyring"])
	}
	if keyring["dek_wrapped_by_kek"] != "wrapped-kek" {
		t.Errorf("dek_wrapped_by_kek: want wrapped-kek, got %v", keyring["dek_wrapped_by_kek"])
	}
	if keyring["dek_wrapped_by_recovery"] != "wrapped-recovery" {
		t.Errorf("dek_wrapped_by_recovery: want wrapped-recovery, got %v", keyring["dek_wrapped_by_recovery"])
	}
	if keyring["private_key_wrapped_by_dek"] != "wrapped-priv" {
		t.Errorf("private_key_wrapped_by_dek: want wrapped-priv, got %v", keyring["private_key_wrapped_by_dek"])
	}
}

func TestKeyring_NoToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/keyring", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPasswordChange_ValidOldProof(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, verifier := seedUserWithVerifier(t, db, "pwchange@example.com")
	token := makeAccessToken(uid, cfg)

	nonce := []byte("old-nonce-for-pwchange")
	proof := GenerateProof(verifier, nonce)
	seedLoginNonce(t, db, "pwchange@example.com", base64.RawStdEncoding.EncodeToString(nonce))

	body, _ := json.Marshal(gin.H{
		"old_proof":       base64.RawStdEncoding.EncodeToString(proof),
		"old_nonce":       base64.RawStdEncoding.EncodeToString(nonce),
		"new_verifier":    "new-verifier-value",
		"new_server_salt": "new-server-salt",
		"new_salt_cl":     "new-salt-cl",
		"new_kdf":         gin.H{"m": 134217728, "t": 4, "p": 2},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var user models.User
	db.Where("id = ?", uid).First(&user)
	if user.AuthVerifier == nil || *user.AuthVerifier != "new-verifier-value" {
		t.Errorf("verifier not updated: got %v", user.AuthVerifier)
	}
	if user.AuthSalt == nil || *user.AuthSalt != "new-server-salt" {
		t.Errorf("auth_salt not updated: got %v", user.AuthSalt)
	}
	if user.SaltCL == nil || *user.SaltCL != "new-salt-cl" {
		t.Errorf("salt_cl not updated: got %v", user.SaltCL)
	}
	if user.KDFM != 134217728 {
		t.Errorf("kdf_m: want 134217728, got %d", user.KDFM)
	}
	if user.KDFT != 4 {
		t.Errorf("kdf_t: want 4, got %d", user.KDFT)
	}
	if user.KDFP != 2 {
		t.Errorf("kdf_p: want 2, got %d", user.KDFP)
	}
}

func TestPasswordChange_KeyringFailure_RollsBackUserUpdate(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, verifier := seedUserWithVerifier(t, db, "pwchange-rollback@example.com")
	db.Create(&models.UserKey{UserID: uid, KeyType: "dek_wrapped_by_kek", Payload: "wrapped-old"})
	token := makeAccessToken(uid, cfg)

	// Simulate a crash mid-transaction: any keyring write with this payload
	// fails. If the handler is atomic, the user row must roll back with it.
	db.Exec("CREATE TRIGGER boom_payload BEFORE UPDATE OF payload ON user_keys " +
		"WHEN NEW.payload = 'boom' BEGIN SELECT RAISE(ABORT, 'boom'); END")

	nonce := []byte("rollback-nonce")
	proof := GenerateProof(verifier, nonce)
	seedLoginNonce(t, db, "pwchange-rollback@example.com", base64.RawStdEncoding.EncodeToString(nonce))

	body, _ := json.Marshal(gin.H{
		"old_proof":         base64.RawStdEncoding.EncodeToString(proof),
		"old_nonce":         base64.RawStdEncoding.EncodeToString(nonce),
		"new_verifier":      "new-verifier-value",
		"new_encrypted_dek": "boom",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on keyring failure, got %d: %s", w.Code, w.Body.String())
	}

	var user models.User
	db.Where("id = ?", uid).First(&user)
	if user.AuthVerifier == nil || *user.AuthVerifier != base64.RawStdEncoding.EncodeToString(verifier) {
		t.Fatalf("verifier must be rolled back, got %v", user.AuthVerifier)
	}
	var uk models.UserKey
	db.Where("user_id = ? AND key_type = ?", uid, "dek_wrapped_by_kek").First(&uk)
	if uk.Payload != "wrapped-old" {
		t.Fatalf("keyring payload must be rolled back, got %q", uk.Payload)
	}
}

func TestPasswordChange_WrongOldProof(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "pwchange-wrong@example.com")
	token := makeAccessToken(uid, cfg)

	wrongProof := []byte("completely-wrong-proof")
	nonce := []byte("some-nonce")
	seedLoginNonce(t, db, "pwchange-wrong@example.com", base64.RawStdEncoding.EncodeToString(nonce))

	body, _ := json.Marshal(gin.H{
		"old_proof":    base64.RawStdEncoding.EncodeToString(wrongProof),
		"old_nonce":    base64.RawStdEncoding.EncodeToString(nonce),
		"new_verifier": "new-verifier-value",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPasswordChange_RevokesOtherSessions(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, verifier := seedUserWithVerifier(t, db, "pwchange-revoke@example.com")

	rt1, _ := createRefreshToken(db, uid, "device-1", cfg)
	rt2, _ := createRefreshToken(db, uid, "device-2", cfg)

	token := makeAccessTokenForDevice(uid, "device-1", cfg)
	nonce := []byte("revoke-nonce")
	proof := GenerateProof(verifier, nonce)
	seedLoginNonce(t, db, "pwchange-revoke@example.com", base64.RawStdEncoding.EncodeToString(nonce))

	body, _ := json.Marshal(gin.H{
		"old_proof":    base64.RawStdEncoding.EncodeToString(proof),
		"old_nonce":    base64.RawStdEncoding.EncodeToString(nonce),
		"new_verifier": "updated-verifier",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var revokedCount int64
	db.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NOT NULL", uid).Count(&revokedCount)
	if revokedCount != 1 {
		t.Errorf("expected exactly 1 revoked token (other device) after password change, got %d", revokedCount)
	}

	var rt1Row models.RefreshToken
	db.Where("token_hash = ?", hashToken(rt1)).First(&rt1Row)
	if rt1Row.RevokedAt != nil {
		t.Errorf("current device token should NOT be revoked after password change")
	}

	var rt2Row models.RefreshToken
	db.Where("token_hash = ?", hashToken(rt2)).First(&rt2Row)
	if rt2Row.RevokedAt == nil {
		t.Errorf("other device token should be revoked after password change")
	}
}

func TestPasswordChange_NoToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"old_proof":    "dGVzdA",
		"old_nonce":    "dGVzdA",
		"new_verifier": "new-v",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRecovery_ValidSignature(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "recovery@example.com")
	recoveryCode := "my-secret-recovery-code"
	seedRecoveryCode(db, uid, recoveryCode)

	nonce := base64.RawStdEncoding.EncodeToString([]byte("challenge-nonce"))
	newCode := "brand-new-recovery-code"
	body, _ := json.Marshal(gin.H{
		"recovery_code":               base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"signature":                   recoverySignature(t, nonce),
		"new_recovery_code":           base64.RawStdEncoding.EncodeToString([]byte(newCode)),
		"new_verifier":                "recovered-verifier",
		"new_encrypted_dek":           "new-dek-wrap",
		"new_dek_wrapped_by_recovery": "new-recovery-wrap",
		"new_server_salt":             "recovered-salt",
		"new_salt_cl":                 "recovered-salt-cl",
		"new_nonce":                   nonce,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var user models.User
	db.Where("id = ?", uid).First(&user)
	if user.AuthVerifier == nil || *user.AuthVerifier != "recovered-verifier" {
		t.Errorf("verifier not updated: got %v", user.AuthVerifier)
	}
	expectedNewHash := sha256.Sum256([]byte(newCode))
	expectedNewHashB64 := base64.RawStdEncoding.EncodeToString(expectedNewHash[:])
	if user.RecoveryHash == nil || *user.RecoveryHash != expectedNewHashB64 {
		t.Errorf("recovery_hash should rotate to the new code, got %v, want %s", user.RecoveryHash, expectedNewHashB64)
	}

	var uk models.UserKey
	if err := db.Where("user_id = ? AND key_type = ?", uid, "dek_wrapped_by_recovery").First(&uk).Error; err != nil {
		t.Errorf("dek_wrapped_by_recovery row should exist after rotation: %v", err)
	} else if uk.Payload != "new-recovery-wrap" {
		t.Errorf("dek_wrapped_by_recovery payload: want %q, got %q", "new-recovery-wrap", uk.Payload)
	}
}

func TestRecovery_NoNewCodeConsumesOld(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "recovery-consume@example.com")
	recoveryCode := "consume-me-code"
	seedRecoveryCode(db, uid, recoveryCode)

	nonce := base64.RawStdEncoding.EncodeToString([]byte("consume-nonce"))
	body, _ := json.Marshal(gin.H{
		"recovery_code": base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"signature":     recoverySignature(t, nonce),
		"new_verifier":  "recovered-verifier",
		"new_nonce":     nonce,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var user models.User
	db.Where("id = ?", uid).First(&user)
	if user.RecoveryHash != nil {
		t.Errorf("recovery_hash should be cleared when no new code is issued, got %v", user.RecoveryHash)
	}

	var uk models.UserKey
	if err := db.Where("user_id = ? AND key_type = ?", uid, "dek_wrapped_by_recovery").First(&uk).Error; err != gorm.ErrRecordNotFound {
		t.Errorf("expected no dek_wrapped_by_recovery row when not rotated, got %v", err)
	}
}

func TestRecovery_InvalidCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "recovery-invalid@example.com")
	realCode := "real-recovery-code"
	seedRecoveryCode(db, uid, realCode)

	nonce := base64.RawStdEncoding.EncodeToString([]byte("invalid-code-nonce"))
	wrongCode := base64.RawStdEncoding.EncodeToString([]byte("wrong-recovery-code"))
	body, _ := json.Marshal(gin.H{
		"recovery_code": wrongCode,
		"signature":     recoverySignature(t, nonce),
		"new_verifier":  "new-v",
		"new_nonce":     nonce,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRecovery_InvalidSignature(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "recovery-sig@example.com")
	recoveryCode := "valid-code"
	seedRecoveryCode(db, uid, recoveryCode)

	nonce := base64.RawStdEncoding.EncodeToString([]byte("bad-sig-nonce"))
	body, _ := json.Marshal(gin.H{
		"recovery_code": base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"signature":     base64.RawStdEncoding.EncodeToString([]byte("x")),
		"new_verifier":  "new-v",
		"new_nonce":     nonce,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRecovery_ReplacesKeyring(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "recovery-keyring@example.com")
	recoveryCode := "keyring-recovery"
	seedRecoveryCode(db, uid, recoveryCode)

	db.Create(&models.UserKey{
		UserID:  uid,
		KeyType: "dek_wrapped_by_kek",
		Payload: "old-dek-payload",
	})

	nonce := base64.RawStdEncoding.EncodeToString([]byte("keyring-nonce"))
	body, _ := json.Marshal(gin.H{
		"recovery_code":     base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"signature":         recoverySignature(t, nonce),
		"new_verifier":      "recovered-v",
		"new_encrypted_dek": "new-dek-payload",
		"new_nonce":         nonce,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var uk models.UserKey
	if db.Where("user_id = ? AND key_type = ?", uid, "dek_wrapped_by_kek").First(&uk).Error != nil {
		t.Fatal("dek_wrapped_by_kek key should exist after recovery")
	}
	if uk.Payload != "new-dek-payload" {
		t.Errorf("dek payload: want new-dek-payload, got %s", uk.Payload)
	}
}

func TestRecovery_RevokesAllSessions(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "recovery-revoke@example.com")
	recoveryCode := "revoke-all-code"
	seedRecoveryCode(db, uid, recoveryCode)

	createRefreshToken(db, uid, "device-1", cfg)
	createRefreshToken(db, uid, "device-2", cfg)

	nonce := base64.RawStdEncoding.EncodeToString([]byte("revoke-nonce"))
	body, _ := json.Marshal(gin.H{
		"recovery_code": base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"signature":     recoverySignature(t, nonce),
		"new_verifier":  "recovered-v",
		"new_nonce":     nonce,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var activeCount int64
	db.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", uid).Count(&activeCount)
	if activeCount != 0 {
		t.Errorf("expected 0 active tokens after recovery, got %d", activeCount)
	}
}

func TestLogin_Unverified_ReturnsVerificationRequired(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())

	userID, verifier := seedUserWithVerifier(t, db, "gate@example.com")
	var user models.User
	db.First(&user, "id = ?", userID)

	nonce := []byte("nonce-bytes")
	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)
	proof := base64.RawStdEncoding.EncodeToString(GenerateProof(verifier, nonce))
	seedLoginNonce(t, db, "gate@example.com", nonceB64)

	raw, _ := json.Marshal(map[string]string{
		"email": "gate@example.com", "proof": proof, "nonce": nonceB64,
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Error struct {
			Code  string `json:"code"`
			Email string `json:"email"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Code != "VERIFICATION_REQUIRED" {
		t.Fatalf("expected VERIFICATION_REQUIRED, got %s", resp.Error.Code)
	}
	if resp.Error.Email != "gate@example.com" {
		t.Fatalf("expected email in error payload, got %s", resp.Error.Email)
	}

	db.First(&user, "id = ?", userID)
	if user.LastLoginAt != nil {
		t.Fatal("last_login_at must not be updated for unverified user")
	}
	var rtCount int64
	db.Model(&models.RefreshToken{}).Where("user_id = ?", userID).Count(&rtCount)
	if rtCount != 0 {
		t.Fatalf("no refresh token should be created, got %d", rtCount)
	}
}

func TestLogin_Verified_Succeeds(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())

	userID, verifier := seedUserWithVerifier(t, db, "ok@example.com")
	now := time.Now()
	db.Model(&models.User{}).Where("id = ?", userID).Update("email_verified_at", &now)

	nonce := []byte("nonce-bytes")
	proof := base64.RawStdEncoding.EncodeToString(GenerateProof(verifier, nonce))
	seedLoginNonce(t, db, "ok@example.com", base64.RawStdEncoding.EncodeToString(nonce))
	raw, _ := json.Marshal(map[string]string{
		"email": "ok@example.com",
		"proof": proof,
		"nonce": base64.RawStdEncoding.EncodeToString(nonce),
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestResendVerification_ReplacesCode(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())
	userID, otp := seedUnverifiedUser(t, db, "resend@example.com")

	// wait out cooldown: backdate the existing row
	db.Model(&models.AuthCode{}).Where("user_id = ? AND purpose = ?", userID, emailVerifyPurpose).
		Update("created_at", time.Now().Add(-time.Minute))

	raw, _ := json.Marshal(map[string]string{"email": "resend@example.com"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	code, err := findEmailVerifyCode(db, userID)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(otp))
	if string(code.CodeHash) == string(hash[:]) {
		t.Fatal("expected old otp to be replaced")
	}
	var count int64
	db.Model(&models.AuthCode{}).Where("user_id = ? AND purpose = ?", userID, emailVerifyPurpose).Count(&count)
	if count != 1 {
		t.Fatalf("expected exactly 1 row, got %d", count)
	}
}

func TestResendVerification_Cooldown(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())
	seedUnverifiedUser(t, db, "cooldown@example.com")

	raw, _ := json.Marshal(map[string]string{"email": "cooldown@example.com"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", w.Code, w.Body.String())
	}
}

func TestResendVerification_UnknownEmail_Uniform(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfigWithVerification())

	raw, _ := json.Marshal(map[string]string{"email": "ghost@example.com"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (no enumeration), got %d", w.Code)
	}
}

func makeAttachRecoveryRequest(t *testing.T, token, recoveryCode string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(gin.H{
		"recovery_code":           base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"dek_wrapped_by_recovery": "wrapped-dek-blob",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery-material", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestAttachRecoveryMaterial_StoresRowAndHash(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "attach@example.com")
	now := time.Now()
	db.Model(&models.User{}).Where("id = ?", uid).Update("email_verified_at", &now)

	token := makeAccessToken(uid, cfg)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, makeAttachRecoveryRequest(t, token, "attach-code"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	codeHash := sha256.Sum256([]byte("attach-code"))
	expectedHash := base64.RawStdEncoding.EncodeToString(codeHash[:])
	var user models.User
	db.First(&user, "id = ?", uid)
	if user.RecoveryHash == nil || *user.RecoveryHash != expectedHash {
		t.Errorf("recovery_hash: want %q, got %v", expectedHash, user.RecoveryHash)
	}
	var uk models.UserKey
	if db.Where("user_id = ? AND key_type = ?", uid, "dek_wrapped_by_recovery").First(&uk).Error != nil {
		t.Fatal("dek_wrapped_by_recovery row should exist")
	}
	if uk.Payload != "wrapped-dek-blob" {
		t.Errorf("payload: want wrapped-dek-blob, got %q", uk.Payload)
	}
}

func TestAttachRecoveryMaterial_ConflictWhenAlreadySet(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "attach-conflict@example.com")
	now := time.Now()
	db.Model(&models.User{}).Where("id = ?", uid).Updates(map[string]any{
		"email_verified_at": &now,
	})
	seedRecoveryCode(db, uid, "existing-code")
	db.Create(&models.UserKey{
		UserID:  uid,
		KeyType: "dek_wrapped_by_recovery",
		Payload: "existing-blob",
	})

	token := makeAccessToken(uid, cfg)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, makeAttachRecoveryRequest(t, token, "attach-code"))

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAttachRecoveryMaterial_UnverifiedForbidden(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfigWithVerification()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "attach-unverified@example.com")

	token := makeAccessToken(uid, cfg)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, makeAttachRecoveryRequest(t, token, "attach-code"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAttachRecoveryMaterial_UnverifiedAllowedWhenVerificationOff(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "attach-ungated@example.com")

	token := makeAccessToken(uid, cfg)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, makeAttachRecoveryRequest(t, token, "attach-code"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var uk models.UserKey
	if db.Where("user_id = ? AND key_type = ?", uid, "dek_wrapped_by_recovery").First(&uk).Error != nil {
		t.Fatal("dek_wrapped_by_recovery row should exist")
	}
}

func TestAttachRecoveryMaterial_RequiresAuth(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, makeAttachRecoveryRequest(t, "", "attach-code"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAttachRecoveryMaterial_HealsMissingRow(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "attach-heal@example.com")
	now := time.Now()
	db.Model(&models.User{}).Where("id = ?", uid).Updates(map[string]any{
		"email_verified_at": &now,
	})
	seedRecoveryCode(db, uid, "stale-hash")

	token := makeAccessToken(uid, cfg)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, makeAttachRecoveryRequest(t, token, "attach-code"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (hash exists but row missing → heal), got %d: %s", w.Code, w.Body.String())
	}
	var uk models.UserKey
	if db.Where("user_id = ? AND key_type = ?", uid, "dek_wrapped_by_recovery").First(&uk).Error != nil {
		t.Fatal("dek_wrapped_by_recovery row should have been restored")
	}
}

func TestRegister_WeakKDF_Rejected(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"user_id":       uuid.New().String(),
		"email":         "weak-kdf@example.com",
		"full_name":     "weak-kdf@example.com",
		"password_hash": base64.RawStdEncoding.EncodeToString([]byte("verifier-bytes")),
		"keyring": map[string]string{
			"dek_wrapped_by_kek":         "kek",
			"dek_wrapped_by_recovery":    "rec",
			"private_key_wrapped_by_dek": "pk",
		},
		"kdf":         map[string]int{"m": 1024, "t": 1, "p": 1},
		"server_salt": "server-salt",
		"salt_cl":     "salt-cl",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var count int64
	db.Model(&models.User{}).Where("email = ?", "weak-kdf@example.com").Count(&count)
	if count != 0 {
		t.Error("user should not have been created with weak kdf")
	}
}

func TestPasswordChange_WeakKDF_Rejected(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, verifier := seedUserWithVerifier(t, db, "pwchange-weak-kdf@example.com")
	token := makeAccessToken(uid, cfg)

	nonce := []byte("nonce-for-weak-kdf")
	proof := GenerateProof(verifier, nonce)
	seedLoginNonce(t, db, "pwchange-weak-kdf@example.com", base64.RawStdEncoding.EncodeToString(nonce))

	body, _ := json.Marshal(gin.H{
		"old_proof":    base64.RawStdEncoding.EncodeToString(proof),
		"old_nonce":    base64.RawStdEncoding.EncodeToString(nonce),
		"new_verifier": "new-verifier-value",
		"new_kdf":      gin.H{"m": 1024, "t": 1, "p": 1},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
