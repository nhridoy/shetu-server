package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TeamSyncOperation records the exact per-operation result so retries after a
// lost response cannot apply a team mutation twice.
type TeamSyncOperation struct {
	UserID      uuid.UUID `gorm:"type:uuid;primaryKey" json:"user_id"`
	OperationID uuid.UUID `gorm:"type:uuid;primaryKey" json:"operation_id"`
	Outcome     string    `gorm:"type:text;not null" json:"outcome"`
	CreatedAt   string    `gorm:"not null" json:"created_at"`
}

func (TeamSyncOperation) TableName() string { return "team_sync_operations" }

func (o *TeamSyncOperation) BeforeCreate(_ *gorm.DB) error {
	if o.CreatedAt == "" {
		o.CreatedAt = CanonicalUTCMillis(time.Now())
	}
	return nil
}
