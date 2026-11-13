package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/account"
	"github.com/nhridoy/shetu-server/internal/models"
)

func TestGateBlocksScheduledUser(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, _ := seedUserWithVerifier(t, db, "g1@example.com")
	at, _ := account.Schedule(db, uid, time.Now())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+makeAccessToken(uid, cfg))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Error struct {
			Code string `json:"code"`
			At   string `json:"deletion_scheduled_for"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error.Code != "ACCOUNT_DELETION_SCHEDULED" || resp.Error.At != at.UTC().Format(time.RFC3339) {
		t.Fatalf("body: %s", w.Body.String())
	}
}

func TestGateAllowsMeAndCancel(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	uid, _ := seedUserWithVerifier(t, db, "g2@example.com")
	account.Schedule(db, uid, time.Now())
	tok := makeAccessToken(uid, cfg)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "deletion_scheduled_for") {
		t.Fatalf("me: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/me/deletion", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("cancel: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("after cancel: %d %s", w.Code, w.Body.String())
	}
}

func TestGateOnlyBlocksTheScheduledUser(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	a, _ := seedUserWithVerifier(t, db, "g3a@example.com")
	b, _ := seedUserWithVerifier(t, db, "g3b@example.com")
	account.Schedule(db, a, time.Now())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+makeAccessToken(b, cfg))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestGateReportsDeletedAccount(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	gone := uuid.New()
	db.Create(&models.DeletedAccount{UserID: gone, DeletedAt: time.Now()})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test-protected", nil)
	req.Header.Set("Authorization", "Bearer "+makeAccessToken(gone, cfg))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "ACCOUNT_DELETED") {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestAccountStatus(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)
	active, _ := seedUserWithVerifier(t, db, "s1@example.com")
	sched, _ := seedUserWithVerifier(t, db, "s2@example.com")
	at, _ := account.Schedule(db, sched, time.Now())
	gone := uuid.New()
	db.Create(&models.DeletedAccount{UserID: gone, DeletedAt: time.Now()})

	cases := []struct {
		name, id, status, date string
		code                   int
	}{
		{"active", active.String(), "active", "", 200},
		{"scheduled", sched.String(), "deletion_scheduled", at.UTC().Format(time.RFC3339), 200},
		{"deleted", gone.String(), "deleted", "", 200},
		{"unknown", uuid.NewString(), "active", "", 200},
		{"bad uuid", "nope", "", "", 400},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/account-status", strings.NewReader(`{"user_id":"`+tc.id+`"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != tc.code {
			t.Fatalf("%s: got %d: %s", tc.name, w.Code, w.Body.String())
		}
		if tc.code != 200 {
			continue
		}
		var resp struct {
			Data struct {
				Status string `json:"status"`
				At     string `json:"deletion_scheduled_for"`
			} `json:"data"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Data.Status != tc.status || resp.Data.At != tc.date {
			t.Fatalf("%s: %s", tc.name, w.Body.String())
		}
	}
}
