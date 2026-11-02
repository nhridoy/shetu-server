package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Backfill vault events so a newly enrolled device can discover vaults that
// existed before the change feed. The event is written once per vault.
func bootstrapVaultChanges(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := repairVaultEnvelopes(tx); err != nil {
			return err
		}
		var vaults []Vault
		if err := tx.Find(&vaults).Error; err != nil {
			return err
		}
		for _, vault := range vaults {
			var count int64
			if err := tx.Model(&SyncChange{}).Where("vault_id = ? AND table_name = ? AND record_id = ?", vault.ID, "vaults", vault.ID).Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				continue
			}
			if vault.EditedAt == "" {
				vault.EditedAt = vault.UpdatedAt
			}
			if vault.OperationID == uuid.Nil {
				vault.OperationID = uuid.New()
			}
			if err := tx.Model(&Vault{}).Where("id = ?", vault.ID).Updates(map[string]any{
				"edited_at": vault.EditedAt, "operation_id": vault.OperationID,
			}).Error; err != nil {
				return err
			}
			envelope, err := json.Marshal(vault.SyncRecord())
			if err != nil {
				return err
			}
			if err := tx.Create(&SyncChange{VaultID: vault.ID, TableName: "vaults", RecordID: vault.ID, Envelope: string(envelope)}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func createSeedVault(db *gorm.DB, vault *Vault) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if vault.EditedAt == "" {
			vault.EditedAt = CanonicalUTCMillis(time.Now())
		}
		if vault.OperationID == uuid.Nil {
			vault.OperationID = uuid.New()
		}
		if err := tx.Create(vault).Error; err != nil {
			return err
		}
		envelope, err := json.Marshal(vault.SyncRecord())
		if err != nil {
			return err
		}
		return tx.Create(&SyncChange{VaultID: vault.ID, TableName: "vaults", RecordID: vault.ID, Envelope: string(envelope)}).Error
	})
}

// Older servers stored the whole vault model as the change envelope, including
// server-only fields (key_epoch, rotation_*) that make every client pull fail.
// Strip them in place so existing feeds replay cleanly.
func repairVaultEnvelopes(tx *gorm.DB) error {
	var stale []SyncChange
	if err := tx.Where("table_name = ? AND envelope LIKE ?", "vaults", `%"key_epoch"%`).Find(&stale).Error; err != nil {
		return err
	}
	allowed := Vault{}.SyncRecord()
	for _, change := range stale {
		var record map[string]any
		if err := json.Unmarshal([]byte(change.Envelope), &record); err != nil {
			return err
		}
		for field := range record {
			if _, ok := allowed[field]; !ok {
				delete(record, field)
			}
		}
		if _, ok := record["vault_id"]; !ok {
			record["vault_id"] = ""
		}
		envelope, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if err := tx.Model(&SyncChange{}).Where("seq = ?", change.Seq).Update("envelope", string(envelope)).Error; err != nil {
			return err
		}
	}
	return nil
}
