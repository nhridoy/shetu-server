package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type StorageAccount struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID     uuid.UUID `gorm:"type:uuid;not null;index:idx_storage_accounts_vault_sort;constraint:OnDelete:CASCADE" json:"vault_id"`
	Revision    int       `gorm:"not null;default:1" json:"revision"`
	Name        string    `gorm:"not null" json:"name"`
	SortOrder   int       `gorm:"not null;default:0;index:idx_storage_accounts_vault_sort" json:"sort_order"`
	Data        string    `gorm:"not null" json:"data"`
	DeletedAt   *string   `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt   string    `json:"created_at"`
	UpdatedAt   string    `json:"updated_at"`
	EditedAt    string    `gorm:"not null;default:''" json:"edited_at"`
	DeviceID    uuid.UUID `gorm:"type:uuid" json:"device_id"`
	OperationID uuid.UUID `gorm:"type:uuid" json:"operation_id"`
}

func (StorageAccount) TableName() string {
	return "storage_accounts"
}

func (m *StorageAccount) BeforeCreate(_ *gorm.DB) error {
	now := CanonicalUTCMillis(time.Now())
	if m.CreatedAt == "" {
		m.CreatedAt = now
	}
	if m.UpdatedAt == "" {
		m.UpdatedAt = now
	}
	return nil
}
