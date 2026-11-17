package auth

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/live"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

func liveRouter(t *testing.T, db *gorm.DB) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := setupHandlerRouter(db, testConfig())
	r.GET("/api/v1/live", JWTMiddleware(testConfig(), db), live.HandleLive())
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func TestLive_StreamUsesTheTokenExpiry(t *testing.T) {
	db := setupTestDB(t)
	srv := liveRouter(t, db)
	_, verifier := seedUserWithVerifier(t, db, "live-ok@example.com")
	access, _ := loginWithDevice(t, setupHandlerRouter(db, testConfig()), db, "live-ok@example.com", verifier, uuid.NewString())
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/live", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("open: %v %v", err, res)
	}
	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)
	if !sc.Scan() || sc.Text() != "event: ready" {
		t.Fatalf("first line: %q", sc.Text())
	}
	// Without the token's expiry the stream would end at once; it must stay open.
	done := make(chan struct{})
	go func() {
		for sc.Scan() {
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("stream closed although the token is valid")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestLive_RevokedDeviceRefused(t *testing.T) {
	db := setupTestDB(t)
	srv := liveRouter(t, db)
	uid, verifier := seedUserWithVerifier(t, db, "live-rev@example.com")
	dev := uuid.NewString()
	access, _ := loginWithDevice(t, setupHandlerRouter(db, testConfig()), db, "live-rev@example.com", verifier, dev)
	db.Model(&models.Device{}).Where("user_id = ? AND device_id = ?", uid, dev).Update("revoked_at", time.Now())
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/live", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", res.StatusCode)
	}
}
