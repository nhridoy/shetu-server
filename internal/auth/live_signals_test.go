package auth

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/live"
	"github.com/nhridoy/shetu-server/internal/live/livetest"
	"github.com/pquerna/otp/totp"
)

func TestLive_RevokeSendsDeviceRevokedToThatDevice(t *testing.T) {
	db := setupTestDB(t)
	hub := livetest.UseHub(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "lrev@example.com")
	here, lost, kept := uuid.NewString(), uuid.NewString(), uuid.NewString()
	access, _ := loginWithDevice(t, r, db, "lrev@example.com", verifier, here)
	loginWithDevice(t, r, db, "lrev@example.com", verifier, lost)
	loginWithDevice(t, r, db, "lrev@example.com", verifier, kept)
	lostCh := livetest.Listen(t, hub, uid, lost)
	keptCh := livetest.Listen(t, hub, uid, kept)
	doJSON(r, http.MethodDelete, "/api/v1/me/devices/"+lost, nil, access)
	if k, closed := livetest.Received(lostCh); len(k) != 1 || k[0] != live.KindDeviceRevoked || !closed {
		t.Fatalf("revoked device: %v closed=%v", k, closed)
	}
	if k, _ := livetest.Received(keptCh); len(k) != 0 {
		t.Fatalf("other device: %v", k)
	}
}

func TestLive_PasswordChangeNotifiesOtherDevices(t *testing.T) {
	db := setupTestDB(t)
	hub := livetest.UseHub(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "lpw@example.com")
	here := uuid.NewString()
	access, _ := loginWithDevice(t, r, db, "lpw@example.com", verifier, here)
	self := livetest.Listen(t, hub, uid, here)
	other := livetest.Listen(t, hub, uid, uuid.NewString())
	nonce := []byte("lpw-nonce")
	seedLoginNonce(t, db, "lpw@example.com", base64.RawStdEncoding.EncodeToString(nonce))
	postJSONTo(r, "/api/v1/auth/password-change", gin.H{
		"old_proof":    base64.RawStdEncoding.EncodeToString(GenerateProof(verifier, nonce)),
		"old_nonce":    base64.RawStdEncoding.EncodeToString(nonce),
		"new_verifier": "fresh",
	}, access)
	if k, _ := livetest.Received(other); len(k) != 1 || k[0] != live.KindAccountChanged {
		t.Fatalf("other device: %v", k)
	}
	if k, _ := livetest.Received(self); len(k) != 0 {
		t.Fatalf("changing device: %v", k)
	}
}

func TestLive_TwoFactorChangeNotifiesAllDevices(t *testing.T) {
	db := setupTestDB(t)
	hub := livetest.UseHub(t)
	r := setupHandlerRouter(db, twoFactorConfig())
	clock := pinClock(t, time.Unix(1_800_000_000, 0))
	uid, verifier := seedUserWithVerifier(t, db, "l2fa@example.com")
	markVerified(t, db, uid)
	here := uuid.NewString()
	access, _ := loginWithDevice(t, r, db, "l2fa@example.com", verifier, here)
	self := livetest.Listen(t, hub, uid, here)
	secret, _ := enableTwoFactor(t, r, access, clock)
	if k, _ := livetest.Received(self); len(k) != 1 || k[0] != live.KindAccountChanged {
		t.Fatalf("after enable: %v", k)
	}
	code, _ := totp.GenerateCode(secret, *clock)
	postJSONTo(r, "/api/v1/me/two-factor/disable", gin.H{"code": code}, access)
	if k, _ := livetest.Received(self); len(k) != 1 || k[0] != live.KindAccountChanged {
		t.Fatalf("after disable: %v", k)
	}
}

func TestLive_DeletionScheduledNotifiesAndCloses(t *testing.T) {
	db := setupTestDB(t)
	hub := livetest.UseHub(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "ldel@example.com")
	access, _ := loginWithDevice(t, r, db, "ldel@example.com", verifier, uuid.NewString())
	other := livetest.Listen(t, hub, uid, uuid.NewString())
	if w := postDeletion(t, r, db, "ldel@example.com", uid, verifier, access, "ldel@example.com", []byte("ldel-nonce"), true, false); w.Code != http.StatusOK {
		t.Fatalf("schedule: %d %s", w.Code, w.Body.String())
	}
	if k, closed := livetest.Received(other); len(k) != 1 || k[0] != live.KindAccountChanged || !closed {
		t.Fatalf("deletion: %v closed=%v", k, closed)
	}
}
