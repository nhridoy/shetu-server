package auth

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/nhridoy/shetu-server/internal/models"
)

// validDeviceID is true for the client-made UUID device ids; anything else (older clients, the
// OAuth fallback "default") is not tracked as a device.
func validDeviceID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

// touchDevice records that a device got tokens. A fresh sign-in (the person has the credentials
// again) clears a revoke; a refresh never does.
func touchDevice(db *gorm.DB, userID uuid.UUID, deviceID string, freshSignIn bool) error {
	if !validDeviceID(deviceID) {
		return nil
	}
	now := time.Now()
	updates := []string{"last_seen_at"}
	if freshSignIn {
		updates = append(updates, "revoked_at")
	}
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "device_id"}},
		DoUpdates: clause.AssignmentColumns(updates),
	}).Create(&models.Device{UserID: userID, DeviceID: deviceID, LastSeenAt: now}).Error
}

// recordDevice is touchDevice for sign-in paths: a failure is logged, never blocks the sign-in.
func recordDevice(db *gorm.DB, userID uuid.UUID, deviceID string, freshSignIn bool) {
	if err := touchDevice(db, userID, deviceID, freshSignIn); err != nil {
		slog.Warn("failed to record device", "error", err)
	}
}

// deviceRevoked reports whether the user's device has been signed out remotely.
func deviceRevoked(db *gorm.DB, userID uuid.UUID, deviceID string) bool {
	if !validDeviceID(deviceID) {
		return false
	}
	var n int64
	db.Model(&models.Device{}).
		Where("user_id = ? AND device_id = ? AND revoked_at IS NOT NULL", userID, deviceID).
		Count(&n)
	return n > 0
}
