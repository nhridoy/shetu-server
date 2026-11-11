package teams

import (
	"errors"

	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

// RoleFor returns an empty role for a user who is not an active team member.
func RoleFor(db *gorm.DB, teamID, userID uuid.UUID) (string, error) {
	var member models.TeamMember
	err := db.Where("team_id = ? AND user_id = ? AND state = ?", teamID, userID, "active").Take(&member).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return member.Role, nil
}
