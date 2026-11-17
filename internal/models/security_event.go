package models

import (
	"time"

	"github.com/google/uuid"
)

// SecurityEvent is one entry in an account's security history. Failed attempts are grouped:
// one row per account and kind per hour, with a count and the distinct addresses seen.
type SecurityEvent struct {
	ID       uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID   uuid.UUID `gorm:"type:uuid;not null;index:idx_security_events_user_created,priority:1;constraint:OnDelete:CASCADE" json:"-"`
	Kind     string    `gorm:"not null" json:"kind"`
	Detail   string    `gorm:"not null;default:''" json:"detail"`
	DeviceID string    `gorm:"not null;default:''" json:"-"`
	IP       string    `gorm:"not null;default:''" json:"ip"`
	// Comma list of the distinct addresses in a grouped row (at most 20).
	IPs       string    `gorm:"not null;default:''" json:"-"`
	IPCount   int       `gorm:"not null;default:1" json:"ip_count"`
	Count     int       `gorm:"not null;default:1" json:"count"`
	CreatedAt time.Time `gorm:"index:idx_security_events_user_created,priority:2" json:"created_at"`
	LastAt    time.Time `json:"last_at"`
}

func (SecurityEvent) TableName() string { return "security_events" }
