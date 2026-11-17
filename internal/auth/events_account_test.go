package auth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

// lastEvent returns the user's newest event, skipping sign-ins made by the test setup.
func lastEvent(t *testing.T, db *gorm.DB, uid uuid.UUID) models.SecurityEvent {
	t.Helper()
	var e models.SecurityEvent
	if err := db.Where("user_id = ? AND kind NOT IN ?", uid, []string{"sign_in", "sign_in_new_device"}).Order("id DESC").First(&e).Error; err != nil {
		t.Fatalf("no event: %v", err)
	}
	return e
}

func sentKinds(sent *[]sentNotice) []string {
	out := []string{}
	for _, n := range *sent {
		out = append(out, n.kind)
	}
	return out
}

func TestEvents_PasswordChanged(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "pwc@example.com")
	dev := uuid.NewString()
	access, _ := loginWithDevice(t, r, db, "pwc@example.com", verifier, dev)
	nonce := []byte("pwc-nonce")
	seedLoginNonce(t, db, "pwc@example.com", base64.RawStdEncoding.EncodeToString(nonce))
	w := postJSONTo(r, "/api/v1/auth/password-change", gin.H{
		"old_proof":    base64.RawStdEncoding.EncodeToString(GenerateProof(verifier, nonce)),
		"old_nonce":    base64.RawStdEncoding.EncodeToString(nonce),
		"new_verifier": "fresh",
	}, access)
	if w.Code != http.StatusNoContent {
		t.Fatalf("password change: %d %s", w.Code, w.Body.String())
	}
	if e := lastEvent(t, db, uid); e.Kind != "password_changed" || e.DeviceID != dev {
		t.Fatalf("event: %+v", e)
	}
	if k := sentKinds(sent); len(k) != 1 || k[0] != "password_changed" {
		t.Fatalf("emails: %v", k)
	}
}

func TestEvents_RecoveryUsed(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	r := setupHandlerRouter(db, testConfig())
	uid, _ := seedRecoverable(t, db, "recev@example.com")
	if w := recoverWith(t, r, ""); w.Code != http.StatusNoContent {
		t.Fatalf("recovery: %d %s", w.Code, w.Body.String())
	}
	if e := lastEvent(t, db, uid); e.Kind != "recovery_used" || e.Detail != "all devices signed out" || e.DeviceID != "" {
		t.Fatalf("event: %+v", e)
	}
	if k := sentKinds(sent); len(k) != 1 || k[0] != "recovery_used" {
		t.Fatalf("emails: %v", k)
	}
}

func TestEvents_TwoFactorEnabledDisabled(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	r := setupHandlerRouter(db, twoFactorConfig())
	clock := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "tfev@example.com")
	markVerified(t, db, uid)
	access, _ := loginWithDevice(t, r, db, "tfev@example.com", verifier, uuid.NewString())
	secret, _ := enableTwoFactor(t, r, access, clock)
	if e := lastEvent(t, db, uid); e.Kind != "two_factor_enabled" {
		t.Fatalf("enabled: %+v", e)
	}
	code, _ := totp.GenerateCode(secret, *clock)
	if w := postJSONTo(r, "/api/v1/me/two-factor/disable", gin.H{"code": code}, access); w.Code != http.StatusNoContent {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	if e := lastEvent(t, db, uid); e.Kind != "two_factor_disabled" || e.Detail != "" {
		t.Fatalf("disabled: %+v", e)
	}
	if k := strings.Join(sentKinds(sent), ","); k != "two_factor_enabled,two_factor_disabled" {
		t.Fatalf("emails: %s", k)
	}
}

func TestEvents_BackupCodeUsed(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	uid, verifier := seedUserWithVerifier(t, db, "bcu@example.com")
	_, backup := seedTwoFactor(t, db, cfg, uid)
	ch := challengeOf(t, loginRaw(t, r, db, "bcu@example.com", verifier, uuid.NewString()))
	if w := verifyCode(r, ch, backup[0], "backup"); w.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}
	if e := lastEvent(t, db, uid); e.Kind != "backup_code_used" {
		t.Fatalf("via sign-in: %+v", e)
	}
	if k := sentKinds(sent); len(k) == 0 || k[0] != "backup_code_used" {
		t.Fatalf("emails: %v", k)
	}
}

func TestEvents_BackupCodeUsedToDisable(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	uid, verifier := seedUserWithVerifier(t, db, "bcd@example.com")
	access, _ := loginWithDevice(t, r, db, "bcd@example.com", verifier, uuid.NewString())
	_, backup := seedTwoFactor(t, db, cfg, uid)
	if w := postJSONTo(r, "/api/v1/me/two-factor/disable", gin.H{"code": backup[0]}, access); w.Code != http.StatusNoContent {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	var used int64
	db.Model(&models.SecurityEvent{}).Where("user_id = ? AND kind = ?", uid, "backup_code_used").Count(&used)
	if used != 1 {
		t.Fatalf("backup_code_used events: %d", used)
	}
}

func TestEvents_RecoveryEmailFallbackDisables(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	codes := captureOtps(t)
	sent := captureNotices(t)
	uid, _ := seedRecoverable(t, db, "fallback-ev@example.com")
	seedTwoFactor(t, db, cfg, uid)
	ch := challengeOf(t, prefetchRaw(r))
	postJSONTo(r, "/api/v1/auth/two-factor/email", gin.H{"challenge": ch}, "")
	var v recoveryVerified
	dataOf(t, verifyCode(r, ch, codes["fallback-ev@example.com"], "email").Body.Bytes(), &v)
	if w := recoverWith(t, r, v.TwoFactorProof); w.Code != http.StatusNoContent {
		t.Fatalf("recovery: %d %s", w.Code, w.Body.String())
	}
	var off models.SecurityEvent
	db.Where("user_id = ? AND kind = ?", uid, "two_factor_disabled").First(&off)
	if off.Detail != "email" {
		t.Fatalf("two_factor_disabled via email: %+v", off)
	}
	if k := strings.Join(sentKinds(sent), ","); !strings.Contains(k, "two_factor_disabled") || !strings.Contains(k, "recovery_used") {
		t.Fatalf("emails: %s", k)
	}
}

func TestEvents_DeviceRevoked(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "rev-ev@example.com")
	here, named, unnamed := uuid.NewString(), uuid.NewString(), uuid.NewString()
	access, _ := loginWithDevice(t, r, db, "rev-ev@example.com", verifier, here)
	loginWithDevice(t, r, db, "rev-ev@example.com", verifier, named)
	loginWithDevice(t, r, db, "rev-ev@example.com", verifier, unnamed)
	db.Model(&models.Device{}).Where("user_id = ? AND device_id = ?", uid, named).Update("name", "Office PC")
	*sent = nil
	doJSON(r, http.MethodDelete, "/api/v1/me/devices/"+named, nil, access)
	if e := lastEvent(t, db, uid); e.Kind != "device_revoked" || e.Detail != "Office PC" || e.DeviceID != here {
		t.Fatalf("named: %+v", e)
	}
	doJSON(r, http.MethodDelete, "/api/v1/me/devices/"+unnamed, nil, access)
	if e := lastEvent(t, db, uid); e.Detail != "Unnamed device" {
		t.Fatalf("unnamed: %+v", e)
	}
	if k := strings.Join(sentKinds(sent), ","); k != "device_revoked,device_revoked" {
		t.Fatalf("emails: %s", k)
	}
}

func TestEvents_OthersRevoked(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "others-ev@example.com")
	access, _ := loginWithDevice(t, r, db, "others-ev@example.com", verifier, uuid.NewString())
	loginWithDevice(t, r, db, "others-ev@example.com", verifier, uuid.NewString())
	loginWithDevice(t, r, db, "others-ev@example.com", verifier, uuid.NewString())
	*sent = nil
	postJSONTo(r, "/api/v1/me/devices/revoke-others", gin.H{}, access)
	if e := lastEvent(t, db, uid); e.Kind != "devices_revoked_others" || e.Detail != "2" {
		t.Fatalf("event: %+v", e)
	}
	if k := sentKinds(sent); len(k) != 1 || k[0] != "devices_revoked_others" {
		t.Fatalf("emails: %v", k)
	}
}

func TestEvents_DeletionScheduledCancelled(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "del-ev@example.com")
	access, _ := loginWithDevice(t, r, db, "del-ev@example.com", verifier, uuid.NewString())
	if w := postDeletion(t, r, db, "del-ev@example.com", uid, verifier, access, "del-ev@example.com", []byte("del-ev-nonce"), true, false); w.Code != http.StatusOK {
		t.Fatalf("schedule: %d %s", w.Code, w.Body.String())
	}
	if e := lastEvent(t, db, uid); e.Kind != "deletion_scheduled" {
		t.Fatalf("scheduled: %+v", e)
	}
	if w := doJSON(r, http.MethodDelete, "/api/v1/me/deletion", nil, access); w.Code >= 300 {
		t.Fatalf("cancel: %d %s", w.Code, w.Body.String())
	}
	if e := lastEvent(t, db, uid); e.Kind != "deletion_cancelled" {
		t.Fatalf("cancelled: %+v", e)
	}
	if len(*sent) != 0 {
		t.Fatalf("deletion kinds must not send security emails: %+v", *sent)
	}
}

func TestEvents_RevokeCountsOnlyDevicesItChanged(t *testing.T) {
	db := setupTestDB(t)
	uid, _ := seedUserWithVerifier(t, db, "count-rev@example.com")
	a, b := uuid.NewString(), uuid.NewString()
	db.Create(&models.Device{UserID: uid, DeviceID: a, LastSeenAt: time.Now()})
	db.Create(&models.Device{UserID: uid, DeviceID: b, LastSeenAt: time.Now()})
	n, err := revokeDevices(db, uid, []string{a, b})
	if err != nil || n != 2 {
		t.Fatalf("first revoke: %d %v", n, err)
	}
	// A second request that selected the same devices changes nothing and reports nothing.
	if n, err := revokeDevices(db, uid, []string{a, b}); err != nil || n != 0 {
		t.Fatalf("second revoke: %d %v", n, err)
	}
}

func TestEvents_RecoveryReportsSignOutOnlyWhenItHappened(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	uid, _ := seedRecoverable(t, db, "rec-fail@example.com")
	if err := db.Callback().Update().Before("gorm:update").Register("test:fail-token-revoke", func(tx *gorm.DB) {
		if tx.Statement.Table == "refresh_tokens" {
			tx.AddError(errors.New("refresh token update failed"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	recoverWith(t, r, "")
	if e := lastEvent(t, db, uid); e.Kind != "recovery_used" || e.Detail != "" {
		t.Fatalf("event claims a sign-out that failed: %+v", e)
	}
}

func TestEvents_UsedBackupCodeIsNotAWrongGuess(t *testing.T) {
	db := setupTestDB(t)
	cfg := twoFactorConfig()
	r := setupHandlerRouter(db, cfg)
	uid, verifier := seedUserWithVerifier(t, db, "usedbc@example.com")
	_, backup := seedTwoFactor(t, db, cfg, uid)
	verifyCode(r, challengeOf(t, loginRaw(t, r, db, "usedbc@example.com", verifier, uuid.NewString())), backup[0], "backup")
	w := verifyCode(r, challengeOf(t, loginRaw(t, r, db, "usedbc@example.com", verifier, uuid.NewString())), backup[0], "backup")
	if errCode(w.Body.Bytes()) != "TWO_FACTOR_INVALID" {
		t.Fatalf("used backup code: %d %s", w.Code, w.Body.String())
	}
	var wrong int64
	db.Model(&models.SecurityEvent{}).Where("user_id = ? AND kind = ?", uid, "two_factor_failed").Count(&wrong)
	if wrong != 0 {
		t.Fatalf("a used backup code was reported as a wrong guess")
	}
}

func TestEvents_EmailCodeLookupFailureIsNotExpired(t *testing.T) {
	db := setupTestDB(t)
	uid, _ := seedUserWithVerifier(t, db, "dberr@example.com")
	if err := db.Migrator().DropTable(&models.AuthCode{}); err != nil {
		t.Fatal(err)
	}
	if err := consumeEmailCode(db, uid, twoFactorRecoveryPurpose, "123456"); err == nil || errors.Is(err, errEmailCodeExpired) {
		t.Fatalf("a database error must not read as an expired code: %v", err)
	}
}
