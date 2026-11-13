package models

import (
	"time"

	"github.com/google/uuid"
)

// DeletedAccount records that a user's account was permanently deleted.
type DeletedAccount struct {
	UserID    uuid.UUID `gorm:"type:uuid;primaryKey" json:"user_id"`
	DeletedAt time.Time `json:"deleted_at"`
}

func (DeletedAccount) TableName() string {
	return "deleted_accounts"
}
