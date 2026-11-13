package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&User{},
		&UserKey{},
		&RefreshToken{},
		&OAuthState{},
		&AuthCode{},
		&LoginNonce{},
		&Vault{},
		&Team{},
		&TeamMember{},
		&TeamInvite{},
		&TeamSyncOperation{},
		&VaultKeyEnvelope{},
		&VaultRotation{},
		&Group{},
		&Host{},
		&Key{},
		&Snippet{},
		&Workspace{},
		&Preset{},
		&PortForward{},
		&SessionHistory{},
		&SessionOutputChunk{},
		&SessionPreferences{},
		&SyncChange{},
		&SyncOperation{},
		&DeletedAccount{},
	); err != nil {
		return err
	}
	// The pre-typed-schema `records` table is obsolete; drop it so its data
	// cannot shadow the typed tables (nothing ever read from it).
	if err := db.Migrator().DropTable("records"); err != nil {
		return err
	}
	if err := MigrateTimestamps(db); err != nil {
		return err
	}
	return bootstrapVaultChanges(db)
}

func SeedPersonalVault(db *gorm.DB, userID uuid.UUID) error {
	var count int64
	if err := db.Model(&Vault{}).Where("owner_id = ? AND kind = ? AND is_default = ? AND deleted_at IS NULL", userID, "personal", true).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	vault := Vault{
		ID:        uuid.New(),
		OwnerID:   userID,
		Kind:      "personal",
		Name:      "Personal",
		Revision:  1,
		SortOrder: 0,
		IsDefault: true,
		Data:      "{}",
		CreatedAt: CanonicalUTCMillis(time.Now()),
		UpdatedAt: CanonicalUTCMillis(time.Now()),
	}
	return createSeedVault(db, &vault)
}
