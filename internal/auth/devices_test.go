package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/nhridoy/shetu-server/internal/models"
)

// loginWithDevice signs in as a seeded user from deviceID and returns the token pair.
func loginWithDevice(t *testing.T, r *gin.Engine, db *gorm.DB, email string, verifier []byte, deviceID string) (string, string) {
	t.Helper()
	nonce := []byte("nonce-" + deviceID + "-" + uuid.NewString())
	seedLoginNonce(t, db, email, base64.RawStdEncoding.EncodeToString(nonce))
	body, _ := json.Marshal(gin.H{
		"email":     email,
		"proof":     base64.RawStdEncoding.EncodeToString(GenerateProof(verifier, nonce)),
		"nonce":     base64.RawStdEncoding.EncodeToString(nonce),
		"device_id": deviceID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return resp.Data.AccessToken, resp.Data.RefreshToken
}

func postJSONTo(r *gin.Engine, path string, payload any, token string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func deviceRow(t *testing.T, db *gorm.DB, userID uuid.UUID, deviceID string) *models.Device {
	t.Helper()
	var d models.Device
	if err := db.Where("user_id = ? AND device_id = ?", userID, deviceID).First(&d).Error; err != nil {
		return nil
	}
	return &d
}

func TestDevice_LoginRecordsAndRefreshUpdatesLastSeen(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, verifier := seedUserWithVerifier(t, db, "dev@example.com")
	device := uuid.NewString()

	_, refresh := loginWithDevice(t, r, db, "dev@example.com", verifier, device)
	row := deviceRow(t, db, uid, device)
	if row == nil {
		t.Fatal("login should record the device")
	}
	before := row.LastSeenAt
	db.Model(row).Update("last_seen_at", before.Add(-time.Hour))

	if w := postJSONTo(r, "/api/v1/auth/refresh", gin.H{"refresh_token": refresh}, ""); w.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", w.Code, w.Body.String())
	}
	if after := deviceRow(t, db, uid, device).LastSeenAt; !after.After(before.Add(-time.Hour)) {
		t.Fatalf("refresh should update last_seen_at, got %v", after)
	}
}

func TestDevice_NonUUIDDeviceIDsNotRecorded(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	_, verifier := seedUserWithVerifier(t, db, "odd@example.com")
	for _, id := range []string{"", "default", "abc"} {
		loginWithDevice(t, r, db, "odd@example.com", verifier, id)
	}
	var n int64
	db.Model(&models.Device{}).Count(&n)
	if n != 0 {
		t.Fatalf("expected no devices, got %d", n)
	}
}

func TestDevice_FreshSignInClearsRevokedRefreshDoesNot(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, verifier := seedUserWithVerifier(t, db, "rev@example.com")
	device := uuid.NewString()
	loginWithDevice(t, r, db, "rev@example.com", verifier, device)

	now := time.Now()
	db.Model(&models.Device{}).Where("user_id = ? AND device_id = ?", uid, device).Update("revoked_at", now)
	loginWithDevice(t, r, db, "rev@example.com", verifier, device)
	if deviceRow(t, db, uid, device).RevokedAt != nil {
		t.Fatal("a fresh sign-in should clear revoked_at")
	}

	// A refresh that touches the device never un-revokes it.
	db.Model(&models.Device{}).Where("user_id = ? AND device_id = ?", uid, device).Update("revoked_at", now)
	if err := touchDevice(db, uid, device, false); err != nil {
		t.Fatal(err)
	}
	if deviceRow(t, db, uid, device).RevokedAt == nil {
		t.Fatal("refresh must not clear revoked_at")
	}
}

func TestDevice_AccountStatusDeviceRevokedOnlyForOwnDevice(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	alice, verifier := seedUserWithVerifier(t, db, "alice@example.com")
	bob, _ := seedUserWithVerifier(t, db, "bob@example.com")
	device := uuid.NewString()
	loginWithDevice(t, r, db, "alice@example.com", verifier, device)
	db.Model(&models.Device{}).Where("user_id = ? AND device_id = ?", alice, device).Update("revoked_at", time.Now())

	status := func(user uuid.UUID, dev string) map[string]any {
		w := postJSONTo(r, "/api/v1/auth/account-status", gin.H{"user_id": user.String(), "device_id": dev}, "")
		var resp struct {
			Data map[string]any `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return resp.Data
	}
	if status(alice, device)["device_revoked"] != true {
		t.Fatal("own revoked device should report device_revoked")
	}
	if _, ok := status(bob, device)["device_revoked"]; ok {
		t.Fatal("another user's device must not be reported")
	}
	if _, ok := status(alice, uuid.NewString())["device_revoked"]; ok {
		t.Fatal("unknown device must not be reported")
	}
}
