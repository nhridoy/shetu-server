package account

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

func testDB(t *testing.T) (*gorm.DB, uuid.UUID) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if err := db.Create(&models.User{ID: id, Email: "a@example.com", FullName: "a", AuthProvider: "password"}).Error; err != nil {
		t.Fatal(err)
	}
	return db, id
}

func TestScheduleSetsDateAndRevokesTokens(t *testing.T) {
	db, id := testDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	for _, h := range []string{"h1", "h2"} {
		db.Create(&models.RefreshToken{UserID: id, TokenHash: h, DeviceID: "d", ExpiresAt: now.Add(time.Hour)})
	}
	got, err := Schedule(db, id, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(now.Add(Grace)) {
		t.Fatalf("date = %v, want %v", got, now.Add(Grace))
	}
	var u models.User
	db.First(&u, "id = ?", id)
	if u.DeletionScheduledFor == nil || !u.DeletionScheduledFor.Equal(got) {
		t.Fatalf("stored date = %v", u.DeletionScheduledFor)
	}
	var live int64
	db.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", id).Count(&live)
	if live != 0 {
		t.Fatalf("%d tokens still live", live)
	}
}

func TestScheduleIsIdempotent(t *testing.T) {
	db, id := testDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	first, _ := Schedule(db, id, now)
	second, err := Schedule(db, id, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !second.Equal(first) {
		t.Fatalf("second = %v, want %v", second, first)
	}
}

func TestCancelClearsDate(t *testing.T) {
	db, id := testDB(t)
	Schedule(db, id, time.Now())
	if err := Cancel(db, id); err != nil {
		t.Fatal(err)
	}
	var u models.User
	db.First(&u, "id = ?", id)
	if u.DeletionScheduledFor != nil {
		t.Fatalf("date not cleared: %v", u.DeletionScheduledFor)
	}
}
