package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"github.com/pquerna/otp/totp"
)

func kinds(rows []models.SecurityEvent) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Kind
	}
	return out
}

func TestEvents_LoginRecordsSignIn(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "si@example.com")
	dev := uuid.NewString()
	loginWithDevice(t, r, db, "si@example.com", verifier, dev)
	rows := eventRows(t, db, uid)
	if len(rows) != 1 || rows[0].Kind != "sign_in" || rows[0].Detail != "password" || rows[0].DeviceID != dev || rows[0].IP == "" {
		t.Fatalf("sign-in event: %+v", rows)
	}
}

func TestEvents_FirstDeviceIsNotNew(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "first@example.com")
	loginWithDevice(t, r, db, "first@example.com", verifier, uuid.NewString())
	if k := kinds(eventRows(t, db, uid)); len(k) != 1 || k[0] != "sign_in" || len(*sent) != 0 {
		t.Fatalf("first device: %v, emails %+v", k, *sent)
	}
}

func TestEvents_NewDeviceEmailsOnce(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "newdev@example.com")
	loginWithDevice(t, r, db, "newdev@example.com", verifier, uuid.NewString())
	second := uuid.NewString()
	loginWithDevice(t, r, db, "newdev@example.com", verifier, second)
	loginWithDevice(t, r, db, "newdev@example.com", verifier, second)
	k := kinds(eventRows(t, db, uid))
	if len(k) != 3 || k[1] != "sign_in_new_device" || k[2] != "sign_in" {
		t.Fatalf("kinds: %v", k)
	}
	if len(*sent) != 1 || (*sent)[0].kind != "sign_in_new_device" || (*sent)[0].detail != "password" {
		t.Fatalf("emails: %+v", *sent)
	}
}

func TestEvents_NewDeviceIsPerAccount(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	_, va := seedUserWithVerifier(t, db, "a-per@example.com")
	ub, vb := seedUserWithVerifier(t, db, "b-per@example.com")
	shared := uuid.NewString()
	loginWithDevice(t, r, db, "a-per@example.com", va, shared)
	loginWithDevice(t, r, db, "b-per@example.com", vb, uuid.NewString())
	loginWithDevice(t, r, db, "b-per@example.com", vb, shared)
	if k := kinds(eventRows(t, db, ub)); len(k) != 2 || k[1] != "sign_in_new_device" {
		t.Fatalf("device known to another account must still be new here: %v", k)
	}
}

func TestEvents_MissingDeviceIdOnAKnownAccountIsNew(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "nodev@example.com")
	// An account's first sign-in without an id (older app) is not an alert.
	loginWithDevice(t, r, db, "nodev@example.com", verifier, "")
	if k := kinds(eventRows(t, db, uid)); len(k) != 1 || k[0] != "sign_in" || len(*sent) != 0 {
		t.Fatalf("first sign-in without id: %v emails %+v", k, *sent)
	}
	loginWithDevice(t, r, db, "nodev@example.com", verifier, uuid.NewString())
	*sent = nil
	// Leaving out the device id must not dodge the alert once the account has devices.
	loginWithDevice(t, r, db, "nodev@example.com", verifier, "")
	loginWithDevice(t, r, db, "nodev@example.com", verifier, "not-a-uuid")
	k := kinds(eventRows(t, db, uid))
	if k[len(k)-1] != "sign_in_new_device" || k[len(k)-2] != "sign_in_new_device" || len(*sent) != 2 {
		t.Fatalf("missing/invalid id on a known account: %v emails %+v", k, *sent)
	}
}

func TestEvents_OAuthSignInDetail(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	uid := seedOAuthUser(t, db, "google", "ev-sub", "oauth-ev@example.com", true)
	var user models.User
	db.First(&user, "id = ?", uid)
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/cb", nil)
	finishOAuthCallback(c, db, cfg, &models.OAuthState{DeviceID: uuid.NewString()}, user)

	r := oauthRouter(db, cfg)
	seedAuthCode(t, db, "ev-exchange", "oauth_setup", uid, uuid.NewString(), time.Now().Add(15*time.Minute), nil)
	if w := postJSONTo(r, "/api/v1/auth/oauth/exchange", gin.H{"setup_code": "ev-exchange", "user_id": uid.String()}, ""); w.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", w.Code, w.Body.String())
	}
	rows := eventRows(t, db, uid)
	if len(rows) != 2 || rows[0].Detail != "google" || rows[1].Detail != "google" {
		t.Fatalf("oauth events: %+v", rows)
	}
}

func TestEvents_TwoFactorVerifyRecordsSignIn(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	now := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "tfv@example.com")
	secret, _ := seedTwoFactor(t, db, cfg, uid)
	ch := challengeOf(t, loginRaw(t, r, db, "tfv@example.com", verifier, uuid.NewString()))
	if n := len(eventRows(t, db, uid)); n != 0 {
		t.Fatalf("events at challenge time: %d", n)
	}
	code, _ := totp.GenerateCode(secret, *now)
	verifyCode(r, ch, code, "totp")
	if rows := eventRows(t, db, uid); len(rows) != 1 || rows[0].Kind != "sign_in" || rows[0].Detail != "password" {
		t.Fatalf("after verify: %+v", rows)
	}
}

func TestEvents_FailedLoginGrouped(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	r := setupHandlerRouter(db, testConfig())
	uid, _ := seedUserWithVerifier(t, db, "wrongpw@example.com")
	for i := 0; i < 3; i++ {
		if w := loginRaw(t, r, db, "wrongpw@example.com", []byte("not-the-verifier"), uuid.NewString()); w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", w.Code)
		}
	}
	rows := eventRows(t, db, uid)
	if len(rows) != 1 || rows[0].Kind != "sign_in_failed" || rows[0].Count != 3 || len(*sent) != 0 {
		t.Fatalf("failed logins: %+v emails %+v", rows, *sent)
	}
}

func TestEvents_FailedLoginUnknownEmailRecordsNothing(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	seedUserWithVerifier(t, db, "known@example.com")
	w := loginRaw(t, r, db, "nobody@example.com", []byte("x"), uuid.NewString())
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown email: %d", w.Code)
	}
	w2 := postJSONTo(r, "/api/v1/auth/login", gin.H{"email": "known@example.com", "proof": "!!", "nonce": "!!"}, "")
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("malformed proof: %d", w2.Code)
	}
	var n int64
	db.Model(&models.SecurityEvent{}).Count(&n)
	if n != 0 {
		t.Fatalf("recorded %d events", n)
	}
}

func TestEvents_WrongTwoFactorCodeRecordedAndEmailed(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	uid, verifier := seedUserWithVerifier(t, db, "wrong2fa@example.com")
	seedTwoFactor(t, db, cfg, uid)
	ch := challengeOf(t, loginRaw(t, r, db, "wrong2fa@example.com", verifier, uuid.NewString()))
	verifyCode(r, ch, "000000", "totp")
	rows := eventRows(t, db, uid)
	if len(rows) != 1 || rows[0].Kind != "two_factor_failed" || rows[0].Detail != "login" {
		t.Fatalf("wrong code: %+v", rows)
	}
	if len(*sent) != 1 || (*sent)[0].kind != "two_factor_failed" || (*sent)[0].detail != "login" {
		t.Fatalf("emails: %+v", *sent)
	}
	db.Model(&models.TwoFactorChallenge{}).Where("token_hash = ?", hashToken(ch)).Update("expires_at", time.Now().Add(-time.Second))
	verifyCode(r, ch, "000000", "totp")
	if rows := eventRows(t, db, uid); rows[0].Count != 1 {
		t.Fatalf("expired challenge counted: %+v", rows)
	}
}

func TestEvents_RecordingFailureNeverBlocks(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	_, verifier := seedUserWithVerifier(t, db, "noblock@example.com")
	if err := db.Migrator().DropTable(&models.SecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	access, _ := loginWithDevice(t, r, db, "noblock@example.com", verifier, uuid.NewString())
	if access == "" {
		t.Fatal("sign-in failed because the event could not be recorded")
	}
}

func TestEvents_OwnReusedCodeIsNotAnAlarm(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	now := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedRecoverable(t, db, "reuse-ev@example.com")
	secret, _ := seedTwoFactor(t, db, cfg, uid)
	code, _ := totp.GenerateCode(secret, *now)
	verifyCode(r, challengeOf(t, prefetchRaw(r)), code, "totp")
	// The same person signs in right after, within the same 30 seconds.
	ch := challengeOf(t, loginRaw(t, r, db, "reuse-ev@example.com", verifier, uuid.NewString()))
	if w := verifyCode(r, ch, code, "totp"); errCode(w.Body.Bytes()) != "TWO_FACTOR_CODE_REUSED" {
		t.Fatalf("want reused, got %s", w.Body.String())
	}
	for _, e := range eventRows(t, db, uid) {
		if e.Kind == "two_factor_failed" {
			t.Fatalf("a replayed own code was recorded as a wrong code: %+v", e)
		}
	}
	if len(*sent) != 0 {
		t.Fatalf("alarm emails: %+v", *sent)
	}
}

func TestEvents_LateEmailedCodeIsNotAnAlarm(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	codes := captureOtps(t)
	uid, _ := seedRecoverable(t, db, "late-ev@example.com")
	seedTwoFactor(t, db, cfg, uid)
	ch := challengeOf(t, prefetchRaw(r))
	postJSONTo(r, "/api/v1/auth/two-factor/email", gin.H{"challenge": ch}, "")
	db.Model(&models.AuthCode{}).Where("user_id = ?", uid).Update("expires_at", time.Now().Add(-time.Second))
	w := verifyCode(r, ch, codes["late-ev@example.com"], "email")
	if errCode(w.Body.Bytes()) != "TWO_FACTOR_CODE_EXPIRED" {
		t.Fatalf("want TWO_FACTOR_CODE_EXPIRED, got %d %s", w.Code, w.Body.String())
	}
	for _, e := range eventRows(t, db, uid) {
		if e.Kind == "two_factor_failed" {
			t.Fatalf("an expired emailed code was recorded as a wrong code: %+v", e)
		}
	}
	if len(*sent) != 0 {
		t.Fatalf("alarm emails: %+v", *sent)
	}
}
