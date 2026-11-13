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
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

// postDeletion seeds a nonce for the user and posts a deletion request.
// wrongProof sends a proof computed from a different nonce.
func postDeletion(t *testing.T, r *gin.Engine, db *gorm.DB, email string, uid uuid.UUID, verifier []byte, token, bodyEmail string, nonce []byte, seed, wrongProof bool) *httptest.ResponseRecorder {
	t.Helper()
	if seed {
		seedLoginNonce(t, db, email, base64.RawStdEncoding.EncodeToString(nonce))
	}
	proofNonce := nonce
	if wrongProof {
		proofNonce = []byte("some-other-nonce")
	}
	body, _ := json.Marshal(gin.H{
		"proof": base64.RawStdEncoding.EncodeToString(GenerateProof(verifier, proofNonce)),
		"nonce": base64.RawStdEncoding.EncodeToString(nonce),
		"email": bodyEmail,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func scheduledFor(db *gorm.DB, uid uuid.UUID) *time.Time {
	var u models.User
	db.First(&u, "id = ?", uid)
	return u.DeletionScheduledFor
}

func TestRequestDeletion_Valid(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, v := seedUserWithVerifier(t, db, "del@example.com")
	w := postDeletion(t, r, db, "del@example.com", uid, v, makeAccessToken(uid, cfg), "del@example.com", []byte("n1"), true, false)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			At string `json:"deletion_scheduled_for"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, err := time.Parse(time.RFC3339, resp.Data.At); err != nil {
		t.Fatalf("bad date %q", resp.Data.At)
	}
	if scheduledFor(db, uid) == nil {
		t.Fatal("date not stored")
	}
}

func TestRequestDeletion_WrongProof(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, v := seedUserWithVerifier(t, db, "del@example.com")
	w := postDeletion(t, r, db, "del@example.com", uid, v, makeAccessToken(uid, cfg), "del@example.com", []byte("n1"), true, true)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if scheduledFor(db, uid) != nil {
		t.Fatal("date must not be set")
	}
}

func TestRequestDeletion_EmailMismatch(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, v := seedUserWithVerifier(t, db, "del@example.com")
	tok := makeAccessToken(uid, cfg)
	w := postDeletion(t, r, db, "del@example.com", uid, v, tok, "other@example.com", []byte("n1"), true, false)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("VALIDATION_ERROR")) || !bytes.Contains(w.Body.Bytes(), []byte("email does not match")) {
		t.Fatalf("body: %s", w.Body.String())
	}
	if scheduledFor(db, uid) != nil {
		t.Fatal("date must not be set")
	}
	// nonce was not consumed: the same nonce still works with the right email
	w = postDeletion(t, r, db, "del@example.com", uid, v, tok, "del@example.com", []byte("n1"), false, false)
	if w.Code != http.StatusOK {
		t.Fatalf("nonce was consumed by mismatch: %d %s", w.Code, w.Body.String())
	}
}

func TestRequestDeletion_EmailCaseInsensitive(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, v := seedUserWithVerifier(t, db, "del@example.com")
	w := postDeletion(t, r, db, "del@example.com", uid, v, makeAccessToken(uid, cfg), "DEL@Example.COM", []byte("n1"), true, false)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestScheduleRejectsReusedNonce(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, v := seedUserWithVerifier(t, db, "del@example.com")
	tok := makeAccessToken(uid, cfg)
	postDeletion(t, r, db, "del@example.com", uid, v, tok, "del@example.com", []byte("n1"), true, false)
	// Cancel so the gate lets the replay reach the handler.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/deletion", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r.ServeHTTP(httptest.NewRecorder(), req)
	if scheduledFor(db, uid) != nil {
		t.Fatal("cancel did not clear the date")
	}
	w := postDeletion(t, r, db, "del@example.com", uid, v, tok, "del@example.com", []byte("n1"), false, false)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if scheduledFor(db, uid) != nil {
		t.Fatal("replayed nonce scheduled the deletion")
	}
}

func TestScheduledAccountCannotRerequestDeletion(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, v := seedUserWithVerifier(t, db, "del@example.com")
	tok := makeAccessToken(uid, cfg)
	postDeletion(t, r, db, "del@example.com", uid, v, tok, "del@example.com", []byte("n1"), true, false)
	w := postDeletion(t, r, db, "del@example.com", uid, v, tok, "del@example.com", []byte("n2"), true, false)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestCancelDeletion(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, _ := seedUserWithVerifier(t, db, "del@example.com")
	at := time.Now().Add(time.Hour)
	db.Model(&models.User{}).Where("id = ?", uid).Update("deletion_scheduled_for", at)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/deletion", nil)
	req.Header.Set("Authorization", "Bearer "+makeAccessToken(uid, cfg))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if scheduledFor(db, uid) != nil {
		t.Fatal("date not cleared")
	}
}

func TestCancelAfterPurgeReportsDeleted(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, _ := seedUserWithVerifier(t, db, "del@example.com")
	db.Model(&models.User{}).Where("id = ?", uid).Update("deletion_scheduled_for", time.Now())
	// The purge removed the row after the gate let the request through: no tombstone yet.
	db.Where("id = ?", uid).Delete(&models.User{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/deletion", nil)
	req.Header.Set("Authorization", "Bearer "+makeAccessToken(uid, cfg))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusGone || !bytes.Contains(w.Body.Bytes(), []byte("ACCOUNT_DELETED")) {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}
