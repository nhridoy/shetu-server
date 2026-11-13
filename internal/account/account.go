// Package account holds account-lifecycle operations (deletion scheduling).
package account

import (
	"errors"
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

// ErrAccountDeleted means the account was purged before the operation ran.
var ErrAccountDeleted = errors.New("account deleted")

// Cancel clears the scheduled deletion date. It returns ErrAccountDeleted
// when the user row is gone, so a cancel that lost the race to the purge is
// never reported as a success.
func Cancel(db *gorm.DB, userID uuid.UUID) error {
	res := db.Model(&models.User{}).Where("id = ?", userID).Update("deletion_scheduled_for", nil)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrAccountDeleted
	}
	return nil
}

type Status string

const (
	StatusActive    Status = "active"
	StatusScheduled Status = "deletion_scheduled"
	StatusDeleted   Status = "deleted"
)

// GetStatus reads the user's row first and consults deleted_accounts only
// when it is missing. Unknown IDs count as active.
func GetStatus(db *gorm.DB, userID uuid.UUID) (Status, *time.Time, error) {
	var users []models.User
	if err := db.Select("deletion_scheduled_for").Where("id = ?", userID).Limit(1).Find(&users).Error; err != nil {
		return "", nil, err
	}
	if len(users) == 1 {
		if at := users[0].DeletionScheduledFor; at != nil {
			return StatusScheduled, at, nil
		}
		return StatusActive, nil, nil
	}
	var n int64
	if err := db.Model(&models.DeletedAccount{}).Where("user_id = ?", userID).Count(&n).Error; err != nil {
		return "", nil, err
	}
	if n > 0 {
		return StatusDeleted, nil, nil
	}
	return StatusActive, nil, nil
}
