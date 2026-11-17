package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
	"github.com/nhridoy/shetu-server/internal/models"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

// seedTwoFactor turns two-factor on directly in the database.
func seedTwoFactor(t *testing.T, db *gorm.DB, cfg *config.Config, uid uuid.UUID) (string, []string) {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Shetu", AccountName: "x"})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealSecret(cfg.TwoFactorKey, key.Secret())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.Create(&models.TwoFactor{UserID: uid, Secret: sealed, EnabledAt: &now}).Error; err != nil {
		t.Fatal(err)
	}
	codes, err := replaceBackupCodes(db, uid)
	if err != nil {
		t.Fatal(err)
	}
	return key.Secret(), codes
}

func loginRaw(t *testing.T, r *gin.Engine, db *gorm.DB, email string, verifier []byte, deviceID string) *httptest.ResponseRecorder {
	t.Helper()
	nonce := []byte("nonce-" + uuid.NewString())
	seedLoginNonce(t, db, email, base64.RawStdEncoding.EncodeToString(nonce))
	return postJSONTo(r, "/api/v1/auth/login", gin.H{
		"email":     email,
		"proof":     base64.RawStdEncoding.EncodeToString(GenerateProof(verifier, nonce)),
		"nonce":     base64.RawStdEncoding.EncodeToString(nonce),
		"device_id": deviceID,
	}, "")
}

func challengeOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Error struct {
			Code      string `json:"code"`
			Challenge string `json:"challenge"`
		} `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	// 403, not 401: the app's HTTP layer reads a 401 as an expired session and retries.
	if w.Code != http.StatusForbidden || env.Error.Code != "TWO_FACTOR_REQUIRED" || env.Error.Challenge == "" {
		t.Fatalf("want 403 TWO_FACTOR_REQUIRED with challenge, got %d %s", w.Code, w.Body.String())
	}
	return env.Error.Challenge
}

func verifyCode(r *gin.Engine, challenge, code, kind string) *httptest.ResponseRecorder {
	return postJSONTo(r, "/api/v1/auth/two-factor", gin.H{"challenge": challenge, "code": code, "kind": kind}, "")
}

func TestTwoFactor_LoginReturnsChallengeOnly(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	uid, verifier := seedUserWithVerifier(t, db, "gate@example.com")
	seedTwoFactor(t, db, cfg, uid)
	w := loginRaw(t, r, db, "gate@example.com", verifier, uuid.NewString())
	challengeOf(t, w)
	if bytes.Contains(w.Body.Bytes(), []byte("access_token")) || bytes.Contains(w.Body.Bytes(), []byte("keyring")) {
		t.Fatalf("leaked sign-in material: %s", w.Body.String())
	}
	var devices, tokens int64
	db.Model(&models.Device{}).Where("user_id = ?", uid).Count(&devices)
	db.Model(&models.RefreshToken{}).Where("user_id = ?", uid).Count(&tokens)
	if devices != 0 || tokens != 0 {
		t.Fatalf("recorded before the second factor: devices %d tokens %d", devices, tokens)
	}
}

func TestTwoFactor_VerifyIssuesSignIn(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	now := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "pass@example.com")
	secret, _ := seedTwoFactor(t, db, cfg, uid)
	device := uuid.NewString()
	ch := challengeOf(t, loginRaw(t, r, db, "pass@example.com", verifier, device))
	code, _ := totp.GenerateCode(secret, *now)
	w := verifyCode(r, ch, code, "totp")
	if w.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		AccessToken  string         `json:"access_token"`
		RefreshToken string         `json:"refresh_token"`
		User         map[string]any `json:"user"`
		Keyring      any            `json:"keyring"`
	}
	dataOf(t, w.Body.Bytes(), &out)
	if out.AccessToken == "" || out.RefreshToken == "" || out.User["id"] != uid.String() {
		t.Fatalf("sign-in response: %s", w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"keyring"`)) {
		t.Fatal("keyring missing")
	}
	if deviceRow(t, db, uid, device).DeviceID != device {
		t.Fatal("device not recorded")
	}
	if w := verifyCode(r, ch, code, "totp"); errCode(w.Body.Bytes()) != "TWO_FACTOR_EXPIRED" {
		t.Fatalf("challenge reused: %d %s", w.Code, w.Body.String())
	}
}

func TestTwoFactor_ChallengeLimits(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	now := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "limit@example.com")
	secret, _ := seedTwoFactor(t, db, cfg, uid)
	ch := challengeOf(t, loginRaw(t, r, db, "limit@example.com", verifier, uuid.NewString()))
	for i := 0; i < 5; i++ {
		if w := verifyCode(r, ch, "000000", "totp"); errCode(w.Body.Bytes()) != "TWO_FACTOR_INVALID" {
			t.Fatalf("attempt %d: %s", i, w.Body.String())
		}
	}
	code, _ := totp.GenerateCode(secret, *now)
	if w := verifyCode(r, ch, code, "totp"); errCode(w.Body.Bytes()) != "TWO_FACTOR_EXPIRED" {
		t.Fatalf("after 5 wrong codes: %s", w.Body.String())
	}

	ch = challengeOf(t, loginRaw(t, r, db, "limit@example.com", verifier, uuid.NewString()))
	db.Model(&models.TwoFactorChallenge{}).Where("token_hash = ?", hashToken(ch)).Update("expires_at", time.Now().Add(-time.Second))
	if w := verifyCode(r, ch, code, "totp"); errCode(w.Body.Bytes()) != "TWO_FACTOR_EXPIRED" {
		t.Fatalf("expired challenge: %s", w.Body.String())
	}
}

func TestTwoFactor_ChallengeSingleUseUnderRace(t *testing.T) {
	db := setupTestDB(t)
	// :memory: sqlite gives each new connection an empty database; share one.
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	now := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "race@example.com")
	secret, backup := seedTwoFactor(t, db, cfg, uid)
	ch := challengeOf(t, loginRaw(t, r, db, "race@example.com", verifier, uuid.NewString()))
	code, _ := totp.GenerateCode(secret, *now)
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, c := range []string{code, backup[0]} {
		wg.Add(1)
		go func(i int, c string) {
			defer wg.Done()
			codes[i] = verifyCode(r, ch, c, "totp").Code
		}(i, c)
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("want exactly one success, got statuses %v", codes)
	}
}

func TestTwoFactor_EmailKindRefusedOnLogin(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	uid, verifier := seedUserWithVerifier(t, db, "nomail@example.com")
	seedTwoFactor(t, db, cfg, uid)
	ch := challengeOf(t, loginRaw(t, r, db, "nomail@example.com", verifier, uuid.NewString()))
	if w := verifyCode(r, ch, "123456", "email"); errCode(w.Body.Bytes()) != "TWO_FACTOR_INVALID" {
		t.Fatalf("email kind on login: %d %s", w.Code, w.Body.String())
	}
	if w := postJSONTo(r, "/api/v1/auth/two-factor/email", gin.H{"challenge": ch}, ""); errCode(w.Body.Bytes()) != "TWO_FACTOR_INVALID" {
		t.Fatalf("email code on login challenge: %d %s", w.Code, w.Body.String())
	}
}

func TestTwoFactor_DisabledMidChallengeExpires(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	now := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "mid@example.com")
	secret, _ := seedTwoFactor(t, db, cfg, uid)
	ch := challengeOf(t, loginRaw(t, r, db, "mid@example.com", verifier, uuid.NewString()))
	db.Where("user_id = ?", uid).Delete(&models.TwoFactor{})
	code, _ := totp.GenerateCode(secret, *now)
	if w := verifyCode(r, ch, code, "totp"); errCode(w.Body.Bytes()) != "TWO_FACTOR_EXPIRED" {
		t.Fatalf("want TWO_FACTOR_EXPIRED, got %d %s", w.Code, w.Body.String())
	}
	if w := loginRaw(t, r, db, "mid@example.com", verifier, uuid.NewString()); w.Code != http.StatusOK {
		t.Fatalf("next login should need no code: %d %s", w.Code, w.Body.String())
	}
}

func TestTwoFactor_MissingKeyFailsClosed(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	uid, verifier := seedUserWithVerifier(t, db, "closed@example.com")
	now := pinClock(t, time.Unix(1_800_000_000, 0))
	secret, _ := seedTwoFactor(t, db, cfg, uid)
	r := setupHandlerRouter(db, testConfig()) // key gone
	ch := challengeOf(t, loginRaw(t, r, db, "closed@example.com", verifier, uuid.NewString()))
	code, _ := totp.GenerateCode(secret, *now)
	w := verifyCode(r, ch, code, "totp")
	if w.Code != http.StatusServiceUnavailable || errCode(w.Body.Bytes()) != "TWO_FACTOR_UNAVAILABLE" {
		t.Fatalf("want 503, got %d %s", w.Code, w.Body.String())
	}
}

func TestTwoFactor_OAuthCallbackRedirectsToCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	cfg.AppScheme = "shetu"
	uid := seedOAuthUser(t, db, "google", "sub-2fa", "oauth2fa@example.com", true)
	seedTwoFactor(t, db, cfg, uid)
	var user models.User
	db.First(&user, "id = ?", uid)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/cb", nil)
	finishOAuthCallback(c, db, cfg, &models.OAuthState{DeviceID: uuid.NewString()}, user)

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != http.StatusFound {
		t.Fatalf("redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
	q := loc.Query()
	if loc.Host != "auth" || loc.Path != "/two_factor" || q.Get("challenge") == "" || q.Get("user_id") != uid.String() || q.Get("access_token") != "" {
		t.Fatalf("want dest two_factor with challenge, got %s", loc)
	}
	var tokens int64
	db.Model(&models.RefreshToken{}).Where("user_id = ?", uid).Count(&tokens)
	if tokens != 0 {
		t.Fatal("refresh token issued before the second factor")
	}
}

func TestTwoFactor_OAuthExchangeAsksForCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := oauthRouter(db, cfg)
	uid := seedOAuthUser(t, db, "google", "sub-x", "exch2fa@example.com", true)
	seedTwoFactor(t, db, cfg, uid)
	seedAuthCode(t, db, "exchange-2fa", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), nil)
	challengeOf(t, postJSONTo(r, "/api/v1/auth/oauth/exchange", gin.H{"setup_code": "exchange-2fa", "user_id": uid.String()}, ""))
}

func TestTwoFactor_AccountLockoutAfterManyWrongCodes(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	uid, verifier := seedUserWithVerifier(t, db, "lockout@example.com")
	seedTwoFactor(t, db, cfg, uid)
	// Fresh challenges don't reset the count: 4 challenges x 5 wrong codes.
	for i := 0; i < 4; i++ {
		ch := challengeOf(t, loginRaw(t, r, db, "lockout@example.com", verifier, uuid.NewString()))
		for j := 0; j < 5; j++ {
			verifyCode(r, ch, "000000", "totp")
		}
	}
	w := loginRaw(t, r, db, "lockout@example.com", verifier, uuid.NewString())
	if w.Code != http.StatusTooManyRequests || errCode(w.Body.Bytes()) != "TWO_FACTOR_LOCKED" {
		t.Fatalf("want 429 TWO_FACTOR_LOCKED, got %d %s", w.Code, w.Body.String())
	}
	// Guesses count for up to 30 minutes (window + challenge lifetime); the message says so.
	if !bytes.Contains(w.Body.Bytes(), []byte("Try again in 30 minutes.")) {
		t.Fatalf("lockout message: %s", w.Body.String())
	}
	// An hour-old burst no longer counts.
	db.Model(&models.TwoFactorChallenge{}).Where("user_id = ?", uid).Update("created_at", time.Now().Add(-time.Hour))
	challengeOf(t, loginRaw(t, r, db, "lockout@example.com", verifier, uuid.NewString()))
}

func TestTwoFactor_LookupErrorFailsClosed(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	_, verifier := seedRecoverable(t, db, "lookup@example.com")
	if err := db.Migrator().DropTable(&models.TwoFactor{}); err != nil {
		t.Fatal(err)
	}
	if w := loginRaw(t, r, db, "lookup@example.com", verifier, uuid.NewString()); w.Code != http.StatusInternalServerError {
		t.Fatalf("login: want 500, got %d %s", w.Code, w.Body.String())
	}
	if w := prefetchRaw(r); w.Code != http.StatusInternalServerError {
		t.Fatalf("prefetch: want 500, got %d %s", w.Code, w.Body.String())
	}
}

func TestTwoFactor_AccountLimitCountsEveryGuess(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	uid, _ := seedRecoverable(t, db, "every@example.com")
	seedTwoFactor(t, db, cfg, uid)
	// Open every challenge before guessing, so issuance-time checks see no attempts.
	var chs []string
	for i := 0; i < 5; i++ {
		chs = append(chs, challengeOf(t, prefetchRaw(r)))
	}
	invalid, locked := 0, 0
	for _, ch := range chs {
		for j := 0; j < 5; j++ {
			switch errCode(verifyCode(r, ch, "000000", "totp").Body.Bytes()) {
			case "TWO_FACTOR_INVALID":
				invalid++
			case "TWO_FACTOR_LOCKED":
				locked++
			}
		}
	}
	if invalid != 20 || locked != 5 {
		t.Fatalf("want 20 checked and 5 locked, got %d checked %d locked", invalid, locked)
	}
}

func TestTwoFactor_OAuthSetupRaceCannotOverwriteASetUpAccount(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := oauthRouter(db, cfg)
	uid := seedOAuthUser(t, db, "google", "race-sub", "setuprace@example.com", false)
	seedAuthCode(t, db, "race-setup-token", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), nil)
	// Another request finishes setup (and turns two-factor on) right after this one reads the user.
	fired := false
	if err := db.Callback().Query().After("gorm:query").Register("test:finish-setup", func(tx *gorm.DB) {
		if fired || tx.Statement.Table != "users" {
			return
		}
		fired = true
		tx.Session(&gorm.Session{NewDB: true, SkipHooks: true}).Exec("UPDATE users SET initialized = ?, auth_verifier = ? WHERE id = ?", true, "winner", uid)
		seedTwoFactor(t, tx.Session(&gorm.Session{NewDB: true}), cfg, uid)
	}); err != nil {
		t.Fatal(err)
	}
	w := postJSONTo(r, "/api/v1/auth/oauth/setup", gin.H{
		"setup_token":   "race-setup-token",
		"auth_verifier": "loser",
		"keyring":       gin.H{"dek_wrapped_by_kek": "a", "dek_wrapped_by_recovery": "b", "private_key_wrapped_by_dek": "c"},
		"kdf":           gin.H{"m": 65536, "t": 3, "p": 2},
		"server_salt":   "s",
		"salt_cl":       "c",
	}, "")
	if !fired {
		t.Fatal("race hook never ran")
	}
	if w.Code != http.StatusConflict || errCode(w.Body.Bytes()) != "ALREADY_INITIALIZED" || bytes.Contains(w.Body.Bytes(), []byte("access_token")) {
		t.Fatalf("want 409 ALREADY_INITIALIZED without a session, got %d %s", w.Code, w.Body.String())
	}
	var tokens int64
	db.Model(&models.RefreshToken{}).Where("user_id = ?", uid).Count(&tokens)
	if tokens != 0 {
		t.Fatalf("refresh token issued to the losing setup: %d", tokens)
	}
	var user models.User
	db.First(&user, "id = ?", uid)
	if user.AuthVerifier == nil || *user.AuthVerifier != "winner" {
		t.Fatalf("setup data overwritten: %v", user.AuthVerifier)
	}
}

func TestTwoFactor_AccountLimitCoversAChallengesWholeLife(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	uid, verifier := seedRecoverable(t, db, "window@example.com")
	seedTwoFactor(t, db, cfg, uid)
	// 20 guesses made just now, on recovery challenges dated 16 minutes back.
	for i := 0; i < 4; i++ {
		ch := challengeOf(t, prefetchRaw(r))
		for j := 0; j < 5; j++ {
			verifyCode(r, ch, "000000", "totp")
		}
	}
	db.Model(&models.TwoFactorChallenge{}).Where("user_id = ?", uid).Update("created_at", time.Now().Add(-16*time.Minute))
	w := loginRaw(t, r, db, "window@example.com", verifier, uuid.NewString())
	if errCode(w.Body.Bytes()) != "TWO_FACTOR_LOCKED" {
		t.Fatalf("guesses on older challenges dropped out of the limit: %d %s", w.Code, w.Body.String())
	}
}

func TestTwoFactor_AccountLimitHoldsUnderConcurrentGuesses(t *testing.T) {
	db := setupTestDB(t)
	// :memory: sqlite gives each new connection an empty database; share one.
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	uid, _ := seedRecoverable(t, db, "parallel@example.com")
	seedTwoFactor(t, db, cfg, uid)
	var chs []string
	for i := 0; i < 6; i++ {
		chs = append(chs, challengeOf(t, prefetchRaw(r)))
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	checked := 0
	for _, ch := range chs {
		for j := 0; j < 5; j++ {
			wg.Add(1)
			go func(ch string) {
				defer wg.Done()
				if errCode(verifyCode(r, ch, "000000", "totp").Body.Bytes()) == "TWO_FACTOR_INVALID" {
					mu.Lock()
					checked++
					mu.Unlock()
				}
			}(ch)
		}
	}
	wg.Wait()
	if checked > 20 {
		t.Fatalf("%d of 30 concurrent guesses were checked, the account limit is 20", checked)
	}
}
