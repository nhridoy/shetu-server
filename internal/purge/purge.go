// Package purge permanently deletes accounts whose deletion grace period has ended.
package purge

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	teamsync "github.com/nhridoy/shetu-server/internal/sync"
	"github.com/nhridoy/shetu-server/internal/teams"
	"gorm.io/gorm"
)

// vaultScoped are the tables whose rows belong to a vault (vault_id column).
var vaultScoped = []any{
	&models.Group{}, &models.Host{}, &models.Key{}, &models.Snippet{}, &models.Workspace{},
	&models.Preset{}, &models.PortForward{}, &models.SessionHistory{}, &models.SessionOutputChunk{},
	&models.SessionPreferences{}, &models.SyncChange{}, &models.SyncOperation{},
	&models.VaultKeyEnvelope{}, &models.VaultRotation{},
}

// PurgeDue hard-deletes every user whose deletion date is at or before now,
// each in its own transaction. A failing user does not stop the others; their
// errors are returned joined.
func PurgeDue(db *gorm.DB, now time.Time) (int, error) {
	var scheduled []models.User
	if err := db.Select("id", "deletion_scheduled_for").Where("deletion_scheduled_for IS NOT NULL").Find(&scheduled).Error; err != nil {
		return 0, err
	}
	purged := 0
	var errs []error
	for _, u := range scheduled {
		// Compared in Go: SQLite stores times as strings, so a SQL <= breaks across time zones.
		if u.DeletionScheduledFor.After(now) {
			continue
		}
		var done bool
		err := teamsync.WithMutationBarrier(func() error {
			return db.Transaction(func(tx *gorm.DB) error {
				var err error
				done, err = purgeUser(tx, u.ID, now)
				return err
			})
		})
		if err != nil {
			errs = append(errs, err)
		} else if done {
			purged++
		}
	}
	return purged, errors.Join(errs...)
}

// purgeUser deletes the user and everything that references them. It returns
// false when the user is gone or no longer due (deletion cancelled meanwhile).
func purgeUser(tx *gorm.DB, userID uuid.UUID, now time.Time) (bool, error) {
	var users []models.User
	if err := tx.Select("id", "email", "deletion_scheduled_for").Where("id = ?", userID).Limit(1).Find(&users).Error; err != nil {
		return false, err
	}
	if len(users) == 0 || users[0].DeletionScheduledFor == nil || users[0].DeletionScheduledFor.After(now) {
		return false, nil
	}
	email := users[0].Email

	// 1. Teams the user owns, with their vaults.
	var ownedTeams []uuid.UUID
	if err := tx.Model(&models.Team{}).Where("owner_id = ?", userID).Pluck("id", &ownedTeams).Error; err != nil {
		return false, err
	}
	if len(ownedTeams) > 0 {
		var teamVaults []uuid.UUID
		if err := tx.Model(&models.Vault{}).Where("team_id IN ?", ownedTeams).Pluck("id", &teamVaults).Error; err != nil {
			return false, err
		}
		if err := deleteVaults(tx, teamVaults); err != nil {
			return false, err
		}
		for _, m := range []any{&models.VaultKeyEnvelope{}, &models.TeamMember{}, &models.TeamInvite{}} {
			if err := tx.Where("team_id IN ?", ownedTeams).Delete(m).Error; err != nil {
				return false, err
			}
		}
		if err := tx.Where("id IN ?", ownedTeams).Delete(&models.Team{}).Error; err != nil {
			return false, err
		}
	}

	// 2. Other teams: leave as a removed member so their vaults rotate keys.
	var memberOf []uuid.UUID
	if err := tx.Model(&models.TeamMember{}).Where("user_id = ? AND state = ?", userID, "active").Pluck("team_id", &memberOf).Error; err != nil {
		return false, err
	}
	stamp := models.CanonicalUTCMillis(now)
	for _, teamID := range memberOf {
		if err := teams.RemoveMemberTx(tx, teamID, userID, stamp); err != nil {
			return false, err
		}
	}
	if err := tx.Where("user_id = ?", userID).Delete(&models.TeamMember{}).Error; err != nil {
		return false, err
	}
	if err := tx.Where("recipient_user_id = ?", userID).Delete(&models.VaultKeyEnvelope{}).Error; err != nil {
		return false, err
	}

	// 3. The user's own vaults.
	var ownVaults []uuid.UUID
	if err := tx.Model(&models.Vault{}).Where("owner_id = ?", userID).Pluck("id", &ownVaults).Error; err != nil {
		return false, err
	}
	if err := deleteVaults(tx, ownVaults); err != nil {
		return false, err
	}

	// 4. Credentials and records keyed by the user.
	for _, m := range []any{&models.UserKey{}, &models.RefreshToken{}, &models.AuthCode{}, &models.TeamSyncOperation{}} {
		if err := tx.Where("user_id = ?", userID).Delete(m).Error; err != nil {
			return false, err
		}
	}
	if err := tx.Where("recipient_user_id = ? OR inviter_user_id = ?", userID, userID).Delete(&models.TeamInvite{}).Error; err != nil {
		return false, err
	}
	if err := tx.Where("email = ?", email).Delete(&models.LoginNonce{}).Error; err != nil {
		return false, err
	}

	// 5. The user row, replaced by a tombstone that keeps only the ID.
	if err := tx.Where("id = ?", userID).Delete(&models.User{}).Error; err != nil {
		return false, err
	}
	return true, tx.Create(&models.DeletedAccount{UserID: userID, DeletedAt: now}).Error
}

// deleteVaults hard-deletes the vaults and every vault-scoped row in them.
func deleteVaults(tx *gorm.DB, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	for _, m := range vaultScoped {
		if err := tx.Where("vault_id IN ?", ids).Delete(m).Error; err != nil {
			return err
		}
	}
	return tx.Where("id IN ?", ids).Delete(&models.Vault{}).Error
}

// RunPurgeLoop purges due accounts now and then every `every` until ctx is done.
func RunPurgeLoop(ctx context.Context, db *gorm.DB, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		n, err := PurgeDue(db, time.Now())
		if err != nil {
			slog.Error("account purge failed", "purged", n, "error", err)
		} else if n > 0 {
			slog.Info("account purge", "purged", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
