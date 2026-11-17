package teams

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/live"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

// teamAudience is everyone whose team sync could show something the actor changes: the actor,
// members of the teams the actor belongs to or is invited to, and those teams' pending invitees.
// It is broader than one team on purpose; an extra sync is cheap.
func teamAudience(db *gorm.DB, actor uuid.UUID) []uuid.UUID {
	var teamIDs []uuid.UUID
	db.Model(&models.TeamMember{}).Where("user_id = ? AND state = ?", actor, "active").Pluck("team_id", &teamIDs)
	var invited []uuid.UUID
	db.Model(&models.TeamInvite{}).Where("recipient_user_id = ? AND state = ?", actor, "pending").Pluck("team_id", &invited)
	teamIDs = append(teamIDs, invited...)
	users := []uuid.UUID{actor}
	if len(teamIDs) > 0 {
		var members, invitees []uuid.UUID
		db.Model(&models.TeamMember{}).Where("team_id IN ? AND state = ?", teamIDs, "active").Pluck("user_id", &members)
		db.Model(&models.TeamInvite{}).Where("team_id IN ? AND state = ?", teamIDs, "pending").Pluck("recipient_user_id", &invitees)
		users = append(append(users, members...), invitees...)
	}
	return users
}

func union(a, b []uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	out := make([]uuid.UUID, 0, len(a)+len(b))
	for _, u := range append(a, b...) {
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

// notifyAfterTeamWrite signals everyone affected by a successful team write. The audience is
// taken before and after the write, so people the write removes are told too.
func notifyAfterTeamWrite(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, ok := c.Get("user_id")
		actor, isID := value.(uuid.UUID)
		if c.Request.Method == http.MethodGet || !ok || !isID {
			c.Next()
			return
		}
		before := teamAudience(db, actor)
		c.Next()
		if c.Writer.Status() < http.StatusMultipleChoices {
			live.Default.Publish(union(before, teamAudience(db, actor)), live.KindChanged, c.GetString("device_id"))
		}
	}
}
