package teams

import (
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

// RemoveMemberTx marks the member removed and forces the team's live vaults to
// rotate keys. It does no permission check; callers do their own.
func RemoveMemberTx(tx *gorm.DB, teamID, userID uuid.UUID, now string) error {
	if err := tx.Model(&models.TeamMember{}).Where("team_id = ? AND user_id = ?", teamID, userID).
		Updates(map[string]any{"state": "removed", "updated_at": now}).Error; err != nil {
		return err
	}
	return tx.Model(&models.Vault{}).Where("team_id = ? AND deleted_at IS NULL", teamID).
		Updates(map[string]any{"rotation_state": "rotation_required", "revision": gorm.Expr("revision + 1"), "updated_at": now}).Error
}
