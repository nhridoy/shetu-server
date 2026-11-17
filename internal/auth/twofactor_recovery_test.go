package auth

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

const twoFactorRecoveryCode = "two-factor-recovery-code"

func seedRecoverable(t *testing.T, db *gorm.DB, email string) (uuid.UUID, []byte) {
	t.Helper()
	uid, verifier := seedUserWithVerifier(t, db, email)
	seedRecoveryCode(db, uid, twoFactorRecoveryCode)
	db.Create(&models.UserKey{UserID: uid, KeyType: "dek_wrapped_by_recovery", Payload: "wrapped-recovery-dek"})
	db.Create(&models.UserKey{UserID: uid, KeyType: "private_key_wrapped_by_dek", Payload: "wrapped-private-key"})
	return uid, verifier
}

func prefetchRaw(r *gin.Engine) *httptest.ResponseRecorder {
	return postJSONTo(r, "/api/v1/auth/recovery/prefetch", gin.H{
		"recovery_code": base64.RawStdEncoding.EncodeToString([]byte(twoFactorRecoveryCode)),
	}, "")
}

func recoverWith(t *testing.T, r *gin.Engine, proof string) *httptest.ResponseRecorder {
	t.Helper()
	nonce := base64.RawStdEncoding.EncodeToString([]byte("nonce-" + uuid.NewString()))
	return postJSONTo(r, "/api/v1/auth/recovery", gin.H{
		"recovery_code":    base64.RawStdEncoding.EncodeToString([]byte(twoFactorRecoveryCode)),
		"signature":        recoverySignature(t, nonce),
		"new_verifier":     "recovered-verifier",
		"new_nonce":        nonce,
		"two_factor_proof": proof,
	}, "")
}

type recoveryVerified struct {
	DekWrappedByRecovery string `json:"dek_wrapped_by_recovery"`
	TwoFactorProof       string `json:"two_factor_proof"`
}

func TestTwoFactor_PrefetchReturnsChallengeOnly(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	uid, _ := seedRecoverable(t, db, "pre@example.com")
	seedTwoFactor(t, db, cfg, uid)
	w := prefetchRaw(r)
	challengeOf(t, w)
	if bytes.Contains(w.Body.Bytes(), []byte("wrapped-recovery-dek")) {
		t.Fatalf("recovery-wrapped key leaked: %s", w.Body.String())
	}
}

func TestTwoFactor_RecoveryWithAuthenticator(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	now := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, _ := seedRecoverable(t, db, "auth@example.com")
	secret, _ := seedTwoFactor(t, db, cfg, uid)
	ch := challengeOf(t, prefetchRaw(r))
	code, _ := totp.GenerateCode(secret, *now)
	w := verifyCode(r, ch, code, "totp")
	if w.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}
	var v recoveryVerified
	dataOf(t, w.Body.Bytes(), &v)
	if v.DekWrappedByRecovery != "wrapped-recovery-dek" || v.TwoFactorProof == "" {
		t.Fatalf("recovery material: %s", w.Body.String())
	}
	if w := recoverWith(t, r, v.TwoFactorProof); w.Code != http.StatusNoContent {
		t.Fatalf("recovery: %d %s", w.Code, w.Body.String())
	}
	if _, on, _ := twoFactorOn(db, uid); !on {
		t.Fatal("an authenticator recovery must keep two-factor on")
	}
}

func TestTwoFactor_RecoveryNeedsProof(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	now := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, _ := seedRecoverable(t, db, "proof@example.com")
	secret, _ := seedTwoFactor(t, db, cfg, uid)
	if w := recoverWith(t, r, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no proof: %d %s", w.Code, w.Body.String())
	}
	ch := challengeOf(t, prefetchRaw(r))
	code, _ := totp.GenerateCode(secret, *now)
	var v recoveryVerified
	dataOf(t, verifyCode(r, ch, code, "totp").Body.Bytes(), &v)
	if w := recoverWith(t, r, v.TwoFactorProof); w.Code != http.StatusNoContent {
		t.Fatalf("first use: %d %s", w.Code, w.Body.String())
	}
	db.Model(&models.User{}).Where("id = ?", uid).Update("auth_verifier", "unchanged")
	seedRecoveryCode(db, uid, twoFactorRecoveryCode)
	if w := recoverWith(t, r, v.TwoFactorProof); w.Code != http.StatusUnauthorized {
		t.Fatalf("used proof: %d %s", w.Code, w.Body.String())
	}
	var user models.User
	db.First(&user, "id = ?", uid)
	if *user.AuthVerifier != "unchanged" {
		t.Fatal("password changed with a used proof")
	}
}

func TestTwoFactor_RecoveryEmailFallbackTurnsOff(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	sent := captureOtps(t)
	uid, _ := seedRecoverable(t, db, "lost@example.com")
	seedTwoFactor(t, db, cfg, uid)
	ch := challengeOf(t, prefetchRaw(r))
	if w := postJSONTo(r, "/api/v1/auth/two-factor/email", gin.H{"challenge": ch}, ""); w.Code != http.StatusNoContent {
		t.Fatalf("email: %d %s", w.Code, w.Body.String())
	}
	w := verifyCode(r, ch, sent["lost@example.com"], "email")
	if w.Code != http.StatusOK {
		t.Fatalf("verify email: %d %s", w.Code, w.Body.String())
	}
	var v recoveryVerified
	dataOf(t, w.Body.Bytes(), &v)
	if _, on, _ := twoFactorOn(db, uid); !on {
		t.Fatal("two-factor must stay on until the recovery completes")
	}
	if w := recoverWith(t, r, v.TwoFactorProof); w.Code != http.StatusNoContent {
		t.Fatalf("recovery: %d %s", w.Code, w.Body.String())
	}
	if _, on, _ := twoFactorOn(db, uid); on {
		t.Fatal("the email fallback must turn two-factor off")
	}
	var codes int64
	db.Model(&models.TwoFactorBackupCode{}).Where("user_id = ?", uid).Count(&codes)
	if codes != 0 {
		t.Fatalf("backup codes left: %d", codes)
	}
}

func TestTwoFactor_EmailFallbackWorksWithoutKey(t *testing.T) {
	db := setupTestDB(t)
	uid, _ := seedRecoverable(t, db, "nokeylost@example.com")
	seedTwoFactor(t, db, twoFactorConfig(), uid)
	r := setupHandlerRouter(db, testConfig()) // key gone
	sent := captureOtps(t)
	ch := challengeOf(t, prefetchRaw(r))
	postJSONTo(r, "/api/v1/auth/two-factor/email", gin.H{"challenge": ch}, "")
	w := verifyCode(r, ch, sent["nokeylost@example.com"], "email")
	if w.Code != http.StatusOK {
		t.Fatalf("verify email without key: %d %s", w.Code, w.Body.String())
	}
	var v recoveryVerified
	dataOf(t, w.Body.Bytes(), &v)
	if w := recoverWith(t, r, v.TwoFactorProof); w.Code != http.StatusNoContent {
		t.Fatalf("recovery: %d %s", w.Code, w.Body.String())
	}
	if _, on, _ := twoFactorOn(db, uid); on {
		t.Fatal("still on")
	}
}

func TestTwoFactor_LoginAfterRecoveryInSameStepIsReused(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	now := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedRecoverable(t, db, "twice@example.com")
	secret, _ := seedTwoFactor(t, db, cfg, uid)
	code, _ := totp.GenerateCode(secret, *now)
	if w := verifyCode(r, challengeOf(t, prefetchRaw(r)), code, "totp"); w.Code != http.StatusOK {
		t.Fatalf("recovery verify: %d %s", w.Code, w.Body.String())
	}
	ch := challengeOf(t, loginRaw(t, r, db, "twice@example.com", verifier, uuid.NewString()))
	if w := verifyCode(r, ch, code, "totp"); errCode(w.Body.Bytes()) != "TWO_FACTOR_CODE_REUSED" {
		t.Fatalf("want TWO_FACTOR_CODE_REUSED, got %d %s", w.Code, w.Body.String())
	}
}
