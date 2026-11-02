package models

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestExistingVaultGetsOneInitialSyncChange(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	ownerID := uuid.New()
	if err := db.Create(&User{ID: ownerID, Email: "bootstrap@example.test"}).Error; err != nil {
		t.Fatal(err)
	}
	vault := Vault{ID: uuid.New(), OwnerID: ownerID, Kind: "personal", Name: "Existing", Data: "{}"}
	if err := db.Create(&vault).Error; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := AutoMigrate(db); err != nil {
			t.Fatal(err)
		}
	}
	var changes []SyncChange
	if err := db.Where("vault_id = ? AND table_name = ?", vault.ID, "vaults").Find(&changes).Error; err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected one initial vault event, got %d", len(changes))
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(changes[0].Envelope), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["id"] != vault.ID.String() || envelope["name"] != "Existing" {
		t.Fatalf("bad vault envelope: %#v", envelope)
	}
}

func TestSeedPersonalVaultEmitsChange(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	ownerID := uuid.New()
	if err := db.Create(&User{ID: ownerID, Email: "seed@example.test"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := SeedPersonalVault(db, ownerID); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.Model(&SyncChange{}).Where("table_name = ?", "vaults").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected seeded vault event, got %d", count)
	}
}

// Mirrors the client's plaintext allowlist for vault records (client sync_db.rs);
// any other field makes every client pull fail.
var clientVaultFields = map[string]bool{
	"id": true, "vault_id": true, "revision": true, "created_at": true, "updated_at": true,
	"deleted_at": true, "edited_at": true, "device_id": true, "operation_id": true,
	"name": true, "sort_order": true, "data": true, "owner_id": true, "kind": true, "is_default": true,
}

func assertClientVaultFields(t *testing.T, envelope string) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal([]byte(envelope), &record); err != nil {
		t.Fatal(err)
	}
	for field := range record {
		if !clientVaultFields[field] {
			t.Fatalf("vault envelope has field %q that clients reject: %s", field, envelope)
		}
	}
	return record
}

func vaultEnvelopes(t *testing.T, db *gorm.DB) []SyncChange {
	t.Helper()
	var changes []SyncChange
	if err := db.Where("table_name = ?", "vaults").Find(&changes).Error; err != nil {
		t.Fatal(err)
	}
	if len(changes) == 0 {
		t.Fatal("expected a vault event")
	}
	return changes
}

func TestSeedAndBackfillVaultEnvelopesOnlyHaveClientFields(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	ownerID := uuid.New()
	if err := db.Create(&User{ID: ownerID, Email: "fields@example.test"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := SeedPersonalVault(db, ownerID); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&Vault{ID: uuid.New(), OwnerID: ownerID, Kind: "personal", Name: "Backfilled", Data: "{}"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	for _, change := range vaultEnvelopes(t, db) {
		record := assertClientVaultFields(t, change.Envelope)
		if record["id"] != change.RecordID.String() || record["vault_id"] != "" || record["owner_id"] != ownerID.String() {
			t.Fatalf("bad vault envelope: %s", change.Envelope)
		}
	}
}

func TestStartupRepairsStoredVaultEnvelopesWithServerFields(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	ownerID := uuid.New()
	if err := db.Create(&User{ID: ownerID, Email: "repair@example.test"}).Error; err != nil {
		t.Fatal(err)
	}
	vault := Vault{ID: uuid.New(), OwnerID: ownerID, Kind: "personal", Name: "Personal", IsDefault: true, Data: "{}", KeyEpoch: 0, RotationState: "ready"}
	if err := db.Create(&vault).Error; err != nil {
		t.Fatal(err)
	}
	// The envelope older servers stored: the whole model, server-only fields included.
	legacy, _ := json.Marshal(vault)
	if err := db.Create(&SyncChange{VaultID: vault.ID, TableName: "vaults", RecordID: vault.ID, Envelope: string(legacy)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	changes := vaultEnvelopes(t, db)
	if len(changes) != 1 {
		t.Fatalf("repair must rewrite in place, got %d events", len(changes))
	}
	record := assertClientVaultFields(t, changes[0].Envelope)
	if record["name"] != "Personal" || record["is_default"] != true || record["created_at"] != vault.CreatedAt {
		t.Fatalf("repair dropped client fields: %s", changes[0].Envelope)
	}
}
