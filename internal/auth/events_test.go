package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

type sentNotice struct{ to, kind, detail, ip string }

// captureNotices records security emails instead of sending them.
func captureNotices(t *testing.T) *[]sentNotice {
	t.Helper()
	var mu sync.Mutex
	sent := &[]sentNotice{}
	prev := deliverSecurityNotice
	deliverSecurityNotice = func(_ *config.Config, to, kind, detail, ip string, _ time.Time) {
		mu.Lock()
		defer mu.Unlock()
		*sent = append(*sent, sentNotice{to, kind, detail, ip})
	}
	t.Cleanup(func() { deliverSecurityNotice = prev })
	return sent
}

// eventCtx is a request context from ip, signed in on deviceID.
func eventCtx(ip, deviceID string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Request.RemoteAddr = ip + ":4000"
	c.Set("device_id", deviceID)
	return c
}

type eventView struct {
	ID            uint      `json:"id"`
	Kind          string    `json:"kind"`
	Detail        string    `json:"detail"`
	DeviceName    string    `json:"device_name"`
	Platform      string    `json:"platform"`
	IP            string    `json:"ip"`
	Count         int       `json:"count"`
	IPCount       int       `json:"ip_count"`
	CreatedAt     time.Time `json:"created_at"`
	LastAt        time.Time `json:"last_at"`
	CurrentDevice bool      `json:"current_device"`
}

type eventPage struct {
	Events []eventView `json:"events"`
	Next   *uint       `json:"next"`
}

func listEvents(t *testing.T, r *gin.Engine, access, query string) eventPage {
	t.Helper()
	w := doJSON(r, http.MethodGet, "/api/v1/me/security-events"+query, nil, access)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var p eventPage
	dataOf(t, w.Body.Bytes(), &p)
	return p
}

func eventRows(t *testing.T, db *gorm.DB, uid uuid.UUID) []models.SecurityEvent {
	t.Helper()
	var rows []models.SecurityEvent
	db.Where("user_id = ?", uid).Order("id").Find(&rows)
	return rows
}

func TestEvents_RecordAndList(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "events@example.com")
	here := uuid.NewString()
	access, _ := loginWithDevice(t, r, db, "events@example.com", verifier, here)
	db.Where("user_id = ?", uid).Delete(&models.SecurityEvent{})
	recordEvent(eventCtx("203.0.113.7", here), db, testConfig(), uid, "sign_in", here, "password")
	recordEvent(eventCtx("203.0.113.8", ""), db, testConfig(), uid, "recovery_used", "", "all devices signed out")
	recordEvent(eventCtx("203.0.113.9", here), db, testConfig(), uid, "password_changed", here, "")
	p := listEvents(t, r, access, "")
	if len(p.Events) != 3 || p.Next != nil {
		t.Fatalf("want 3 events and no next, got %+v", p)
	}
	if p.Events[0].Kind != "password_changed" || p.Events[2].Kind != "sign_in" {
		t.Fatalf("not newest first: %+v", p.Events)
	}
	e := p.Events[2]
	if e.Detail != "password" || e.IP != "203.0.113.7" || e.Count != 1 || e.IPCount != 1 || !e.CurrentDevice {
		t.Fatalf("sign_in view: %+v", e)
	}
	if p.Events[1].CurrentDevice {
		t.Fatal("an event without a device is never this device")
	}
}

func TestEvents_Paging(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "paging@example.com")
	access, _ := loginWithDevice(t, r, db, "paging@example.com", verifier, uuid.NewString())
	db.Where("user_id = ?", uid).Delete(&models.SecurityEvent{})
	for i := 0; i < 120; i++ {
		db.Create(&models.SecurityEvent{UserID: uid, Kind: "sign_in", Detail: fmt.Sprint(i), Count: 1, IPCount: 1})
	}
	p := listEvents(t, r, access, "")
	if len(p.Events) != 50 || p.Next == nil || p.Events[0].Detail != "119" {
		t.Fatalf("first page: %d next=%v first=%s", len(p.Events), p.Next, p.Events[0].Detail)
	}
	p2 := listEvents(t, r, access, fmt.Sprintf("?before=%d", *p.Next))
	if len(p2.Events) != 50 || p2.Events[0].Detail != "69" {
		t.Fatalf("second page: %d first=%s", len(p2.Events), p2.Events[0].Detail)
	}
	if p3 := listEvents(t, r, access, "?limit=500"); len(p3.Events) != 100 {
		t.Fatalf("limit cap: %d", len(p3.Events))
	}
}

func TestEvents_GroupingWithinAnHour(t *testing.T) {
	db := setupTestDB(t)
	uid, _ := seedUserWithVerifier(t, db, "group@example.com")
	recordEvent(eventCtx("198.51.100.1", ""), db, testConfig(), uid, "sign_in_failed", "", "")
	recordEvent(eventCtx("198.51.100.2", ""), db, testConfig(), uid, "sign_in_failed", "", "")
	rows := eventRows(t, db, uid)
	if len(rows) != 1 || rows[0].Count != 2 || rows[0].IPCount != 2 || rows[0].IP != "198.51.100.2" {
		t.Fatalf("grouped row: %+v", rows)
	}
	db.Model(&models.SecurityEvent{}).Where("id = ?", rows[0].ID).Update("created_at", time.Now().Add(-61*time.Minute))
	recordEvent(eventCtx("198.51.100.1", ""), db, testConfig(), uid, "sign_in_failed", "", "")
	if rows := eventRows(t, db, uid); len(rows) != 2 || rows[1].Count != 1 {
		t.Fatalf("after an hour: %+v", rows)
	}
}

func TestEvents_GroupedIPsCapAt20(t *testing.T) {
	db := setupTestDB(t)
	uid, _ := seedUserWithVerifier(t, db, "cap@example.com")
	for i := 1; i <= 21; i++ {
		recordEvent(eventCtx(fmt.Sprintf("192.0.2.%d", i), ""), db, testConfig(), uid, "sign_in_failed", "", "")
	}
	rows := eventRows(t, db, uid)
	if len(rows) != 1 || rows[0].Count != 21 || rows[0].IPCount != 20 || rows[0].IP != "192.0.2.21" {
		t.Fatalf("capped row: %+v", rows)
	}
}

func TestEvents_TwoFactorFailedEmailsOncePerHour(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	uid, _ := seedUserWithVerifier(t, db, "tff@example.com")
	recordEvent(eventCtx("198.51.100.1", ""), db, testConfig(), uid, "two_factor_failed", "", "login")
	recordEvent(eventCtx("198.51.100.1", ""), db, testConfig(), uid, "two_factor_failed", "", "login")
	if len(*sent) != 1 || (*sent)[0].detail != "login" {
		t.Fatalf("want one email, got %+v", *sent)
	}
	db.Model(&models.SecurityEvent{}).Where("user_id = ?", uid).Update("created_at", time.Now().Add(-61*time.Minute))
	recordEvent(eventCtx("198.51.100.1", ""), db, testConfig(), uid, "two_factor_failed", "", "login")
	if len(*sent) != 2 {
		t.Fatalf("want a second email after an hour, got %d", len(*sent))
	}
}

func TestEvents_EmailingKindsOnly(t *testing.T) {
	db := setupTestDB(t)
	sent := captureNotices(t)
	uid, _ := seedUserWithVerifier(t, db, "mail@example.com")
	recordEvent(eventCtx("203.0.113.7", ""), db, testConfig(), uid, "sign_in", "", "password")
	recordEvent(eventCtx("203.0.113.7", ""), db, testConfig(), uid, "sign_in_failed", "", "")
	recordEvent(eventCtx("203.0.113.7", ""), db, testConfig(), uid, "deletion_scheduled", "", "")
	if len(*sent) != 0 {
		t.Fatalf("non-emailing kinds sent: %+v", *sent)
	}
	recordEvent(eventCtx("203.0.113.7", ""), db, testConfig(), uid, "password_changed", "", "")
	if len(*sent) != 1 || (*sent)[0] != (sentNotice{"mail@example.com", "password_changed", "", "203.0.113.7"}) {
		t.Fatalf("password_changed email: %+v", *sent)
	}
}

func TestEvents_ListJoinsCurrentDeviceName(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "join@example.com")
	dev, gone := uuid.NewString(), uuid.NewString()
	access, _ := loginWithDevice(t, r, db, "join@example.com", verifier, dev)
	db.Where("user_id = ?", uid).Delete(&models.SecurityEvent{})
	recordEvent(eventCtx("203.0.113.7", dev), db, testConfig(), uid, "sign_in", dev, "password")
	recordEvent(eventCtx("203.0.113.7", gone), db, testConfig(), uid, "sign_in", gone, "password")
	db.Model(&models.Device{}).Where("user_id = ? AND device_id = ?", uid, dev).Updates(map[string]any{"name": "Renamed", "platform": "linux"})
	p := listEvents(t, r, access, "")
	if p.Events[1].DeviceName != "Renamed" || p.Events[1].Platform != "linux" {
		t.Fatalf("joined name: %+v", p.Events[1])
	}
	if p.Events[0].DeviceName != "" {
		t.Fatalf("missing device row: %+v", p.Events[0])
	}
}

func TestEvents_OnlyOwnEvents(t *testing.T) {
	db := setupTestDB(t)
	r := setupHandlerRouter(db, testConfig())
	uid, verifier := seedUserWithVerifier(t, db, "own@example.com")
	other, _ := seedUserWithVerifier(t, db, "other@example.com")
	access, _ := loginWithDevice(t, r, db, "own@example.com", verifier, uuid.NewString())
	db.Where("user_id = ?", uid).Delete(&models.SecurityEvent{})
	recordEvent(eventCtx("203.0.113.7", ""), db, testConfig(), other, "password_changed", "", "")
	if p := listEvents(t, r, access, ""); len(p.Events) != 0 {
		t.Fatalf("another user's events listed: %+v", p.Events)
	}
	if !strings.Contains(fmt.Sprint(eventRows(t, db, other)), "password_changed") {
		t.Fatal("other user's event not stored")
	}
}
