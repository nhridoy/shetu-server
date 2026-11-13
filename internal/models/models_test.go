package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	gormsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	return db
}

func TestEmailVerificationColumns(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}
	if !db.Migrator().HasColumn("users", "email_verified_at") {
		t.Errorf("users.email_verified_at column missing after AutoMigrate")
	}
	if !db.Migrator().HasColumn("auth_codes", "attempts") {
		t.Errorf("auth_codes.attempts column missing after AutoMigrate")
	}
}

func TestAutoMigrate(t *testing.T) {
	db := setupTestDB(t)

	err := AutoMigrate(db)
	if err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	var tables []string
	db.Raw("SELECT name FROM sqlite_master WHERE type='table'").Pluck("name", &tables)

	t.Logf("tables created: %v", tables)

	expectedTables := map[string]bool{
		"users":          false,
		"user_keys":      false,
		"refresh_tokens": false,
		"oauth_states":   false,
		"auth_codes":     false,
		"vaults":         false,
		"groups":         false,
		"hosts":          false,
		"keys":           false,
		"snippets":       false,
	}

	for _, table := range tables {
		if _, ok := expectedTables[table]; ok {
			expectedTables[table] = true
		}
	}

	for table, found := range expectedTables {
		if !found {
			t.Errorf("expected table %s to exist", table)
		}
	}

	if db.Migrator().HasTable("records") {
		t.Errorf("expected obsolete table records to be dropped")
	}
}

func TestSeedPersonalVault(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	userID := uuid.New()
	err := SeedPersonalVault(db, userID)
	if err != nil {
		t.Fatalf("SeedPersonalVault failed: %v", err)
	}

	var vault Vault
	if err := db.Where("owner_id = ? AND kind = ?", userID, "personal").First(&vault).Error; err != nil {
		t.Fatalf("expected personal vault to exist: %v", err)
	}
	if vault.Name != "Personal" {
		t.Errorf("expected vault name 'Personal', got '%s'", vault.Name)
	}
	if vault.Revision != 1 || vault.SortOrder != 0 || vault.Data != "{}" {
		t.Errorf("expected seeded vault to carry the sync envelope, got %+v", vault)
	}
	if !vault.IsDefault {
		t.Errorf("expected seeded vault to be the default, got is_default false")
	}
	if vault.DeletedAt != nil {
		t.Errorf("expected seeded vault to be alive, got deleted_at %v", vault.DeletedAt)
	}

	err = SeedPersonalVault(db, userID)
	if err != nil {
		t.Fatalf("SeedPersonalVault idempotent call failed: %v", err)
	}

	var count int64
	db.Model(&Vault{}).Where("owner_id = ? AND kind = ?", userID, "personal").Count(&count)
	if count != 1 {
		t.Errorf("expected exactly 1 personal vault, got %d", count)
	}
}

func TestTypedModelsRoundtrip(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	vaultID := uuid.New()
	groupID := uuid.New()
	keyID := uuid.New()

	vault := Vault{
		ID:        vaultID,
		OwnerID:   uuid.New(),
		Revision:  3,
		Kind:      "personal",
		Name:      "Personal",
		SortOrder: 0,
		Data:      "enc",
	}
	if err := db.Create(&vault).Error; err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	group := Group{
		ID:        uuid.New(),
		VaultID:   vaultID,
		Revision:  1,
		Name:      "Prod",
		SortOrder: 0,
		Data:      "{}",
	}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("failed to create group: %v", err)
	}

	host := Host{
		ID:        uuid.New(),
		VaultID:   vaultID,
		Revision:  1,
		Name:      "web-01",
		OS:        "linux",
		AuthType:  "key",
		Tags:      "[\"web\",\"prod\"]",
		Color:     "#3b82f6",
		GroupID:   &groupID,
		KeyID:     &keyID,
		SortOrder: 1,
		Data:      "enc",
	}
	if err := db.Create(&host).Error; err != nil {
		t.Fatalf("failed to create host: %v", err)
	}

	key := Key{
		ID:          keyID,
		VaultID:     vaultID,
		Revision:    1,
		Name:        "work",
		Description: "GitHub",
		KeyType:     "ed25519",
		Fingerprint: "SHA256:abc",
		PublicKey:   "ssh-ed25519 AAAA",
		Data:        "enc",
	}
	if err := db.Create(&key).Error; err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	snippet := Snippet{
		ID:          uuid.New(),
		VaultID:     vaultID,
		Revision:    1,
		Name:        "restart nginx",
		Description: "quick restart",
		Tags:        "[\"ops\"]",
		Data:        "enc",
	}
	if err := db.Create(&snippet).Error; err != nil {
		t.Fatalf("failed to create snippet: %v", err)
	}

	var foundVault Vault
	if err := db.First(&foundVault, "id = ?", vaultID).Error; err != nil {
		t.Fatalf("failed to find vault: %v", err)
	}
	if foundVault.Revision != 3 || foundVault.Data != "enc" || foundVault.DeletedAt != nil {
		t.Errorf("vault sync envelope not persisted: %+v", foundVault)
	}

	var foundHost Host
	if err := db.First(&foundHost, "vault_id = ?", vaultID).Error; err != nil {
		t.Fatalf("failed to find host: %v", err)
	}
	if foundHost.OS != "linux" || foundHost.AuthType != "key" || foundHost.Tags != "[\"web\",\"prod\"]" {
		t.Errorf("host whitelist columns not persisted: %+v", foundHost)
	}

	var foundKey Key
	if err := db.First(&foundKey, "id = ?", keyID).Error; err != nil {
		t.Fatalf("failed to find key: %v", err)
	}
	if foundKey.KeyType != "ed25519" || foundKey.Fingerprint != "SHA256:abc" || foundKey.PublicKey != "ssh-ed25519 AAAA" {
		t.Errorf("key whitelist columns not persisted: %+v", foundKey)
	}

	var foundSnippet Snippet
	if err := db.First(&foundSnippet, "name = ?", "restart nginx").Error; err != nil {
		t.Fatalf("failed to find snippet: %v", err)
	}
	if foundSnippet.Tags != "[\"ops\"]" {
		t.Errorf("snippet whitelist columns not persisted: %+v", foundSnippet)
	}
}

func TestUserModel(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	user := User{
		ID:           uuid.New(),
		Email:        "test@example.com",
		FullName:     "Test User",
		AuthProvider: "password",
		Initialized:  true,
	}

	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	var found User
	if err := db.Where("email = ?", "test@example.com").First(&found).Error; err != nil {
		t.Fatalf("failed to find user: %v", err)
	}
	if found.FullName != "Test User" {
		t.Errorf("expected name 'Test User', got '%s'", found.FullName)
	}
}

func TestAutoMigrateCreatesDeletionSchema(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}
	if !db.Migrator().HasColumn(&User{}, "deletion_scheduled_for") {
		t.Errorf("users.deletion_scheduled_for column missing")
	}
	if !db.Migrator().HasTable(&DeletedAccount{}) {
		t.Errorf("deleted_accounts table missing")
	}

	when := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	u := User{ID: uuid.New(), Email: "d@example.com", FullName: "D", DeletionScheduledFor: &when}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	var got User
	if err := db.First(&got, "id = ?", u.ID).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	if got.DeletionScheduledFor == nil || !got.DeletionScheduledFor.Equal(when) {
		t.Errorf("DeletionScheduledFor round-trip = %v, want %v", got.DeletionScheduledFor, when)
	}

	b, err := json.Marshal(User{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "deletion_scheduled_for") {
		t.Errorf("unset field should be omitted from JSON: %s", b)
	}
}
