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

func doJSON(r *gin.Engine, method, path string, payload any, token string) *httptest.ResponseRecorder {
	var body *bytes.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

type listedDevice struct {
	DeviceID   string `json:"device_id"`
	Name       string `json:"name"`
	Platform   string `json:"platform"`
	AppVersion string `json:"app_version"`
	Current    bool   `json:"current"`
}

func listDevices(t *testing.T, r *gin.Engine, token string) []listedDevice {
	t.Helper()
	w := doJSON(r, http.MethodGet, "/api/v1/me/devices", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data []listedDevice `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return resp.Data
}

func TestDevice_MiddlewareRejectsRevokedDevice(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "mw@example.com")
	device := uuid.NewString()
	access, _ := loginWithDevice(t, r, db, "mw@example.com", verifier, device)
	db.Model(&models.Device{}).Where("user_id = ? AND device_id = ?", uid, device).Update("revoked_at", time.Now())

	w := doJSON(r, http.MethodGet, "/api/v1/test-protected", nil, access)
	if w.Code != http.StatusUnauthorized || !bytes.Contains(w.Body.Bytes(), []byte("DEVICE_REVOKED")) {
		t.Fatalf("expected 401 DEVICE_REVOKED, got %d %s", w.Code, w.Body.String())
	}
	// Tokens without a device id (older clients) are not checked.
	plain, _ := loginWithDevice(t, r, db, "mw@example.com", verifier, "")
	if w := doJSON(r, http.MethodGet, "/api/v1/test-protected", nil, plain); w.Code != http.StatusOK {
		t.Fatalf("no device id: %d", w.Code)
	}
}

func TestDevice_ListExcludesRevokedAndSignedOut(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "list@example.com")
	here, other, gone, out := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	access, _ := loginWithDevice(t, r, db, "list@example.com", verifier, here)
	loginWithDevice(t, r, db, "list@example.com", verifier, other)
	loginWithDevice(t, r, db, "list@example.com", verifier, gone)
	_, outRefresh := loginWithDevice(t, r, db, "list@example.com", verifier, out)
	db.Model(&models.Device{}).Where("user_id = ? AND device_id = ?", uid, gone).Update("revoked_at", time.Now())
	if w := postJSONTo(r, "/api/v1/auth/logout", gin.H{"refresh_token": outRefresh}, ""); w.Code >= 300 {
		t.Fatalf("logout: %d", w.Code)
	}
	db.Model(&models.Device{}).Where("user_id = ? AND device_id = ?", uid, other).Update("last_seen_at", time.Now().Add(time.Hour))

	got := listDevices(t, r, access)
	if len(got) != 2 || got[0].DeviceID != other || got[1].DeviceID != here {
		t.Fatalf("want [other, here] newest first, got %+v", got)
	}
	if got[0].Current || !got[1].Current {
		t.Fatalf("current flag wrong: %+v", got)
	}
}

func TestDevice_UpdateCurrentTrimsAndCaps(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	_, verifier := seedUserWithVerifier(t, db, "cur@example.com")
	access, _ := loginWithDevice(t, r, db, "cur@example.com", verifier, uuid.NewString())
	long := string(bytes.Repeat([]byte("x"), 150))
	w := doJSON(r, http.MethodPut, "/api/v1/me/devices/current", gin.H{"name": "  laptop  ", "platform": "linux", "app_version": long}, access)
	if w.Code != http.StatusNoContent {
		t.Fatalf("update current: %d %s", w.Code, w.Body.String())
	}
	d := listDevices(t, r, access)[0]
	if d.Name != "laptop" || d.Platform != "linux" || len(d.AppVersion) != 100 {
		t.Fatalf("got %+v", d)
	}
	noDevice, _ := loginWithDevice(t, r, db, "cur@example.com", verifier, "")
	if w := doJSON(r, http.MethodPut, "/api/v1/me/devices/current", gin.H{"name": "x"}, noDevice); w.Code != http.StatusBadRequest {
		t.Fatalf("no device id: %d", w.Code)
	}
}

func TestDevice_RenameValidates(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	_, verifier := seedUserWithVerifier(t, db, "ren@example.com")
	access, _ := loginWithDevice(t, r, db, "ren@example.com", verifier, uuid.NewString())
	other := uuid.NewString()
	loginWithDevice(t, r, db, "ren@example.com", verifier, other)
	path := "/api/v1/me/devices/" + other
	if w := doJSON(r, http.MethodPatch, path, gin.H{"name": "   "}, access); w.Code != http.StatusBadRequest {
		t.Fatalf("empty: %d", w.Code)
	}
	if w := doJSON(r, http.MethodPatch, path, gin.H{"name": string(bytes.Repeat([]byte("a"), 101))}, access); w.Code != http.StatusBadRequest {
		t.Fatalf("101 chars: %d", w.Code)
	}
	if w := doJSON(r, http.MethodPatch, path, gin.H{"name": " Work PC "}, access); w.Code != http.StatusNoContent {
		t.Fatalf("ok: %d %s", w.Code, w.Body.String())
	}
	for _, d := range listDevices(t, r, access) {
		if d.DeviceID == other && d.Name != "Work PC" {
			t.Fatalf("rename not saved: %+v", d)
		}
	}
}

func TestDevice_RevokeOneRevokesTokens(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	_, verifier := seedUserWithVerifier(t, db, "one@example.com")
	access, _ := loginWithDevice(t, r, db, "one@example.com", verifier, uuid.NewString())
	other := uuid.NewString()
	otherAccess, otherRefresh := loginWithDevice(t, r, db, "one@example.com", verifier, other)
	if w := doJSON(r, http.MethodDelete, "/api/v1/me/devices/"+other, nil, access); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if w := postJSONTo(r, "/api/v1/auth/refresh", gin.H{"refresh_token": otherRefresh}, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked refresh: %d", w.Code)
	}
	if w := doJSON(r, http.MethodGet, "/api/v1/test-protected", nil, otherAccess); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked access: %d", w.Code)
	}
}

func TestDevice_RevokeCurrentDeviceRefused(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	_, verifier := seedUserWithVerifier(t, db, "self@example.com")
	here := uuid.NewString()
	access, _ := loginWithDevice(t, r, db, "self@example.com", verifier, here)
	if w := doJSON(r, http.MethodDelete, "/api/v1/me/devices/"+here, nil, access); w.Code != http.StatusBadRequest {
		t.Fatalf("revoke self: %d", w.Code)
	}
}

func TestDevice_RevokeOtherUsersDeviceNotFound(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	_, va := seedUserWithVerifier(t, db, "a@example.com")
	bob, vb := seedUserWithVerifier(t, db, "b@example.com")
	access, _ := loginWithDevice(t, r, db, "a@example.com", va, uuid.NewString())
	bobDevice := uuid.NewString()
	loginWithDevice(t, r, db, "b@example.com", vb, bobDevice)
	if w := doJSON(r, http.MethodDelete, "/api/v1/me/devices/"+bobDevice, nil, access); w.Code != http.StatusNotFound {
		t.Fatalf("other user's device: %d", w.Code)
	}
	if w := doJSON(r, http.MethodPatch, "/api/v1/me/devices/"+bobDevice, gin.H{"name": "x"}, access); w.Code != http.StatusNotFound {
		t.Fatalf("rename other user's device: %d", w.Code)
	}
	if deviceRow(t, db, bob, bobDevice).RevokedAt != nil {
		t.Fatal("bob's device must stay active")
	}
}

func TestDevice_RevokeOthersKeepsCurrent(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "all@example.com")
	here := uuid.NewString()
	access, _ := loginWithDevice(t, r, db, "all@example.com", verifier, here)
	loginWithDevice(t, r, db, "all@example.com", verifier, uuid.NewString())
	loginWithDevice(t, r, db, "all@example.com", verifier, uuid.NewString())
	w := doJSON(r, http.MethodPost, "/api/v1/me/devices/revoke-others", nil, access)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"revoked":2`)) {
		t.Fatalf("revoke others: %d %s", w.Code, w.Body.String())
	}
	if deviceRow(t, db, uid, here).RevokedAt != nil {
		t.Fatal("current device must stay")
	}
	if got := listDevices(t, r, access); len(got) != 1 {
		t.Fatalf("only this device should remain: %+v", got)
	}
	noDevice, _ := loginWithDevice(t, r, db, "all@example.com", verifier, "")
	if w := doJSON(r, http.MethodPost, "/api/v1/me/devices/revoke-others", nil, noDevice); w.Code != http.StatusBadRequest {
		t.Fatalf("no device id: %d", w.Code)
	}
}

func TestDevice_RevokedDeviceRefreshDoesNotSignOutOthers(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	_, verifier := seedUserWithVerifier(t, db, "bys@example.com")
	access, mine := loginWithDevice(t, r, db, "bys@example.com", verifier, uuid.NewString())
	other := uuid.NewString()
	_, otherRefresh := loginWithDevice(t, r, db, "bys@example.com", verifier, other)
	if w := doJSON(r, http.MethodDelete, "/api/v1/me/devices/"+other, nil, access); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", w.Code)
	}
	// The revoked device comes online and tries to refresh: refused...
	if w := postJSONTo(r, "/api/v1/auth/refresh", gin.H{"refresh_token": otherRefresh}, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked refresh: %d", w.Code)
	}
	// ...without being taken as token reuse that signs everyone out.
	if w := postJSONTo(r, "/api/v1/auth/refresh", gin.H{"refresh_token": mine}, ""); w.Code != http.StatusOK {
		t.Fatalf("the revoking device must keep its session: %d %s", w.Code, w.Body.String())
	}
}

func TestDevice_ReportDoesNotOverwriteARename(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	_, verifier := seedUserWithVerifier(t, db, "keep@example.com")
	access, _ := loginWithDevice(t, r, db, "keep@example.com", verifier, uuid.NewString())
	other := uuid.NewString()
	otherAccess, _ := loginWithDevice(t, r, db, "keep@example.com", verifier, other)
	doJSON(r, http.MethodPut, "/api/v1/me/devices/current", gin.H{"name": "DESKTOP-7Q3", "platform": "windows", "app_version": "1"}, otherAccess)
	doJSON(r, http.MethodPatch, "/api/v1/me/devices/"+other, gin.H{"name": "Work PC"}, access)
	// The renamed device reconnects and reports its computer name again.
	doJSON(r, http.MethodPut, "/api/v1/me/devices/current", gin.H{"name": "DESKTOP-7Q3", "platform": "windows", "app_version": "2"}, otherAccess)
	for _, d := range listDevices(t, r, access) {
		if d.DeviceID == other && (d.Name != "Work PC" || d.AppVersion != "2") {
			t.Fatalf("rename lost or version not updated: %+v", d)
		}
	}
}
