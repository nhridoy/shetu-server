package models

import (
	"time"

	"github.com/google/uuid"
)

// Device is one signed-in app installation, keyed by the client's device id.
type Device struct {
	ID         uint       `gorm:"primaryKey;autoIncrement" json:"-"`
	UserID     uuid.UUID  `gorm:"type:uuid;not null;uniqueIndex:idx_devices_user_device;constraint:OnDelete:CASCADE" json:"-"`
	DeviceID   string     `gorm:"not null;uniqueIndex:idx_devices_user_device" json:"device_id"`
	Name       string     `gorm:"not null;default:''" json:"name"`
	Platform   string     `gorm:"not null;default:''" json:"platform"`
	AppVersion string     `gorm:"not null;default:''" json:"app_version"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `gorm:"not null" json:"last_seen_at"`
	RevokedAt  *time.Time `json:"-"`
}

func (Device) TableName() string {
	return "devices"
}
