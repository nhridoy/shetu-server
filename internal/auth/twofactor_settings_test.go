package auth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
	"github.com/nhridoy/shetu-server/internal/models"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

func twoFactorConfig() *config.Config {
	cfg := testConfig()
	cfg.TwoFactorKey = testKey(7)
	return cfg
}

// pinClock fixes the two-factor clock; advance it to get a fresh TOTP step.
func pinClock(t *testing.T, at time.Time) *time.Time {
	t.Helper()
	now := at
	nowFunc = func() time.Time { return now }
	t.Cleanup(func() { nowFunc = time.Now })
	return &now
}

// captureOtps records the email codes two-factor sends, keyed by address.
func captureOtps(t *testing.T) map[string]string {
	t.Helper()
	sent := map[string]string{}
	prev := deliverOtp
	deliverOtp = func(_ *config.Config, to, code string) error { sent[to] = code; return nil }
	t.Cleanup(func() { deliverOtp = prev })
	return sent
}

func dataOf(t *testing.T, body []byte, out any) {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode: %v %s", err, body)
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		t.Fatalf("decode data: %v %s", err, env.Data)
	}
}

func errCode(body []byte) string {
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Error.Code
}

type setupView struct {
	OtpauthURL    string `json:"otpauth_url"`
	Secret        string `json:"secret"`
	EmailCodeSent bool   `json:"email_code_sent"`
}

type statusView struct {
	Enabled         bool `json:"enabled"`
	Available       bool `json:"available"`
	BackupCodesLeft int  `json:"backup_codes_left"`
	EmailVerified   bool `json:"email_verified"`
}

func markVerified(t *testing.T, db *gorm.DB, uid uuid.UUID) {
	t.Helper()
	now := time.Now()
	if err := db.Model(&models.User{}).Where("id = ?", uid).Update("email_verified_at", &now).Error; err != nil {
		t.Fatal(err)
	}
}

// enableTwoFactor turns two-factor on for a signed-in, verified account and returns the
// secret and backup codes. The clock must be pinned; it is advanced one step afterwards.
func enableTwoFactor(t *testing.T, r *gin.Engine, access string, clock *time.Time) (string, []string) {
	t.Helper()
	w := postJSONTo(r, "/api/v1/me/two-factor/setup", gin.H{}, access)
	if w.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}
	var s setupView
	dataOf(t, w.Body.Bytes(), &s)
	code, _ := totp.GenerateCode(s.Secret, *clock)
	w = postJSONTo(r, "/api/v1/me/two-factor/confirm", gin.H{"code": code}, access)
	if w.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		BackupCodes []string `json:"backup_codes"`
	}
	dataOf(t, w.Body.Bytes(), &out)
	*clock = clock.Add(30 * time.Second)
	return s.Secret, out.BackupCodes
}

func twoFactorStatus(t *testing.T, r *gin.Engine, access string) statusView {
	t.Helper()
	w := doJSON(r, http.MethodGet, "/api/v1/me/two-factor", nil, access)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	var s statusView
	dataOf(t, w.Body.Bytes(), &s)
	return s
}

func TestTwoFactor_SetupConfirmEnables(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, twoFactorConfig())
	clock := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "on@example.com")
	markVerified(t, db, uid)
	access, _ := loginWithDevice(t, r, db, "on@example.com", verifier, uuid.NewString())

	w := postJSONTo(r, "/api/v1/me/two-factor/setup", gin.H{}, access)
	var s setupView
	dataOf(t, w.Body.Bytes(), &s)
	u, err := url.Parse(s.OtpauthURL)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || !strings.HasPrefix(u.Path, "/Shetu:") || s.EmailCodeSent {
		t.Fatalf("setup view: %+v", s)
	}
	if st := twoFactorStatus(t, r, access); st.Enabled {
		t.Fatal("a started setup must not turn two-factor on")
	}
	code, _ := totp.GenerateCode(s.Secret, *clock)
	w = postJSONTo(r, "/api/v1/me/two-factor/confirm", gin.H{"code": code}, access)
	var out struct {
		BackupCodes []string `json:"backup_codes"`
	}
	dataOf(t, w.Body.Bytes(), &out)
	if len(out.BackupCodes) != 10 {
		t.Fatalf("backup codes: %v", out.BackupCodes)
	}
	if st := twoFactorStatus(t, r, access); !st.Enabled || st.BackupCodesLeft != 10 || !st.Available {
		t.Fatalf("status: %+v", st)
	}
	var row models.TwoFactor
	db.First(&row, "user_id = ?", uid)
	if row.Secret == "" || strings.Contains(row.Secret, s.Secret) || row.PendingSecret != "" {
		t.Fatalf("secret must be stored sealed: %+v", row)
	}
	if w := postJSONTo(r, "/api/v1/me/two-factor/setup", gin.H{}, access); w.Code != http.StatusConflict || errCode(w.Body.Bytes()) != "TWO_FACTOR_ENABLED" {
		t.Fatalf("setup when on: %d %s", w.Code, w.Body.String())
	}
}

func TestTwoFactor_ConfirmWrongCodeKeepsOff(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, twoFactorConfig())
	pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "wrong@example.com")
	markVerified(t, db, uid)
	access, _ := loginWithDevice(t, r, db, "wrong@example.com", verifier, uuid.NewString())
	postJSONTo(r, "/api/v1/me/two-factor/setup", gin.H{}, access)
	w := postJSONTo(r, "/api/v1/me/two-factor/confirm", gin.H{"code": "000000"}, access)
	// 400, not 401: a 401 on a signed-in call makes the app drop its session.
	if w.Code != http.StatusBadRequest || errCode(w.Body.Bytes()) != "TWO_FACTOR_INVALID" {
		t.Fatalf("want 400 TWO_FACTOR_INVALID, got %d %s", w.Code, w.Body.String())
	}
	if twoFactorStatus(t, r, access).Enabled {
		t.Fatal("a wrong code must keep two-factor off")
	}
}

func TestTwoFactor_UnverifiedEmailNeedsEmailCode(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, twoFactorConfig())
	clock := pinClock(t, time.Unix(1_800_000_000, 0))
	sent := captureOtps(t)
	_, verifier := seedUserWithVerifier(t, db, "unverified@example.com")
	access, _ := loginWithDevice(t, r, db, "unverified@example.com", verifier, uuid.NewString())

	w := postJSONTo(r, "/api/v1/me/two-factor/setup", gin.H{}, access)
	var s setupView
	dataOf(t, w.Body.Bytes(), &s)
	if !s.EmailCodeSent || sent["unverified@example.com"] == "" {
		t.Fatalf("setup must email a code to an unverified address: %+v %v", s, sent)
	}
	code, _ := totp.GenerateCode(s.Secret, *clock)
	if w := postJSONTo(r, "/api/v1/me/two-factor/confirm", gin.H{"code": code}, access); w.Code != http.StatusBadRequest {
		t.Fatalf("confirm without email code: %d %s", w.Code, w.Body.String())
	}
	w = postJSONTo(r, "/api/v1/me/two-factor/confirm", gin.H{"code": code, "email_code": sent["unverified@example.com"]}, access)
	if w.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
	if st := twoFactorStatus(t, r, access); !st.Enabled || !st.EmailVerified {
		t.Fatalf("status: %+v", st)
	}
}

func TestTwoFactor_UnavailableWithoutKey(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "nokey@example.com")
	markVerified(t, db, uid)
	access, _ := loginWithDevice(t, r, db, "nokey@example.com", verifier, uuid.NewString())
	w := postJSONTo(r, "/api/v1/me/two-factor/setup", gin.H{}, access)
	if w.Code != http.StatusServiceUnavailable || errCode(w.Body.Bytes()) != "TWO_FACTOR_UNAVAILABLE" {
		t.Fatalf("want 503 TWO_FACTOR_UNAVAILABLE, got %d %s", w.Code, w.Body.String())
	}
	if twoFactorStatus(t, r, access).Available {
		t.Fatal("status must report unavailable")
	}
}

func TestTwoFactor_DisableNeedsCode(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, twoFactorConfig())
	clock := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "off@example.com")
	markVerified(t, db, uid)
	access, _ := loginWithDevice(t, r, db, "off@example.com", verifier, uuid.NewString())
	_, backup := enableTwoFactor(t, r, access, clock)

	if w := postJSONTo(r, "/api/v1/me/two-factor/disable", gin.H{"code": "000000"}, access); w.Code != http.StatusBadRequest {
		t.Fatalf("wrong code: %d %s", w.Code, w.Body.String())
	}
	if !twoFactorStatus(t, r, access).Enabled {
		t.Fatal("still on after a wrong code")
	}
	if w := postJSONTo(r, "/api/v1/me/two-factor/disable", gin.H{"code": strings.ToUpper(backup[0])}, access); w.Code != http.StatusNoContent {
		t.Fatalf("backup code: %d %s", w.Code, w.Body.String())
	}
	if twoFactorStatus(t, r, access).Enabled {
		t.Fatal("still on after disable")
	}
	var n int64
	db.Model(&models.TwoFactorBackupCode{}).Where("user_id = ?", uid).Count(&n)
	if n != 0 {
		t.Fatalf("backup codes left behind: %d", n)
	}
}

func TestTwoFactor_RegenerateReplacesCodes(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, twoFactorConfig())
	clock := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "regen@example.com")
	markVerified(t, db, uid)
	access, _ := loginWithDevice(t, r, db, "regen@example.com", verifier, uuid.NewString())
	secret, old := enableTwoFactor(t, r, access, clock)

	code, _ := totp.GenerateCode(secret, *clock)
	w := postJSONTo(r, "/api/v1/me/two-factor/backup-codes", gin.H{"code": code}, access)
	if w.Code != http.StatusOK {
		t.Fatalf("regenerate: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		BackupCodes []string `json:"backup_codes"`
	}
	dataOf(t, w.Body.Bytes(), &out)
	if len(out.BackupCodes) != 10 || out.BackupCodes[0] == old[0] {
		t.Fatalf("new codes: %v", out.BackupCodes)
	}
	if w := postJSONTo(r, "/api/v1/me/two-factor/disable", gin.H{"code": old[1]}, access); w.Code != http.StatusBadRequest {
		t.Fatalf("an old backup code must stop working: %d", w.Code)
	}
	if st := twoFactorStatus(t, r, access); st.BackupCodesLeft != 10 {
		t.Fatalf("left: %+v", st)
	}
}

func TestTwoFactor_DoesNotSignOutOtherDevices(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, twoFactorConfig())
	clock := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "keep@example.com")
	markVerified(t, db, uid)
	access, _ := loginWithDevice(t, r, db, "keep@example.com", verifier, uuid.NewString())
	other, _ := loginWithDevice(t, r, db, "keep@example.com", verifier, uuid.NewString())
	enableTwoFactor(t, r, access, clock)
	if w := doJSON(r, http.MethodGet, "/api/v1/test-protected", nil, other); w.Code != http.StatusOK {
		t.Fatalf("other device signed out: %d", w.Code)
	}
}
