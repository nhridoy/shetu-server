package models

import (
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestCanonicalUTCMillis(t *testing.T) {
	legacy := time.Date(2026, 9, 27, 6, 0, 0, 123456789, time.FixedZone("BDT", 6*3600))
	if got := CanonicalUTCMillis(legacy); got != "2026-09-27T00:00:00.123Z" {
		t.Fatalf("canonical timestamp = %q", got)
	}
}

type nonSQLiteDialector struct{ gorm.Dialector }

func (nonSQLiteDialector) Name() string { return "postgres" }

func TestTimestampMigrationSkipsNonSQLite(t *testing.T) {
	db := &gorm.DB{Config: &gorm.Config{Dialector: nonSQLiteDialector{}}}
	if err := MigrateTimestamps(db); err != nil {
		t.Fatalf("MigrateTimestamps() on non-SQLite error = %v", err)
	}
}

func TestTimestampMigrationPreservesCiphertext(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO hosts (id, vault_id, revision, name, data, created_at, updated_at) VALUES (?, ?, 1, 'Legacy', 'sealed-blob', '2026-09-27 06:00:00+06:00', '2026-09-27 06:00:01+06:00')", "h1", "v1").Error; err != nil {
		t.Fatal(err)
	}
	if err := MigrateTimestamps(db); err != nil {
		t.Fatal(err)
	}
	var created, updated, data string
	if err := db.Raw("SELECT created_at, updated_at, data FROM hosts WHERE id = 'h1'").Row().Scan(&created, &updated, &data); err != nil {
		t.Fatal(err)
	}
	if created != "2026-09-27T00:00:00.000Z" || updated != "2026-09-27T00:00:01.000Z" || data != "sealed-blob" {
		t.Fatalf("migration: %q %q %q", created, updated, data)
	}
}
