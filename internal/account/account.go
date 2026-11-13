// Package account holds account-lifecycle operations (deletion scheduling).
package account

import (
	"time"

	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

const Grace = 30 * 24 * time.Hour

// Schedule marks the account for deletion at now+Grace and revokes all its
// refresh tokens. If a date is already set it is kept and returned.
func Schedule(db *gorm.DB, userID uuid.UUID, now time.Time) (time.Time, error) {
	var at time.Time
	err := db.Transaction(func(tx *gorm.DB) error {
		var u models.User
		if err := tx.First(&u, "id = ?", userID).Error; err != nil {
			return err
		}
		if u.DeletionScheduledFor != nil {
			at = *u.DeletionScheduledFor
		} else {
			at = now.Add(Grace)
			if err := tx.Model(&models.User{}).Where("id = ?", userID).Update("deletion_scheduled_for", at).Error; err != nil {
				return err
			}
		}
		return tx.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", userID).Update("revoked_at", now).Error
	})
	return at, err
}

// Cancel clears the scheduled deletion date.
func Cancel(db *gorm.DB, userID uuid.UUID) error {
	return db.Model(&models.User{}).Where("id = ?", userID).Update("deletion_scheduled_for", nil).Error
}
