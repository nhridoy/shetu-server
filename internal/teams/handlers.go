package teams

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/auth"
	"github.com/nhridoy/shetu-server/internal/models"
	teamsync "github.com/nhridoy/shetu-server/internal/sync"
	"gorm.io/gorm"
)

func userID(c *gin.Context) (uuid.UUID, bool) {
	value, ok := c.Get("user_id")
	if !ok {
		return uuid.Nil, false
	}
	id, ok := value.(uuid.UUID)
	return id, ok && id != uuid.Nil
}

func RegisterRoutes(protected *gin.RouterGroup, db *gorm.DB) {
	registerTeamSyncRoute(protected, db)
	registerInviteRoutes(protected, db)
	registerVaultRoutes(protected, db)
	registerMemberRoutes(protected, db)
	registerRotationRoutes(protected, db)
	protected.PATCH("/teams/:id", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		teamID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team ID")
			return
		}
		role, err := RoleFor(db, teamID, actor)
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "TEAM_LOOKUP_FAILED", "team lookup failed")
			return
		}
		if role != "owner" && role != "admin" {
			auth.Error(c, http.StatusForbidden, "FORBIDDEN", "team management required")
			return
		}
		var request struct {
			Name string `json:"name"`
		}
		if err := c.ShouldBindJSON(&request); err != nil || strings.TrimSpace(request.Name) == "" || len(request.Name) > 120 {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team name")
			return
		}
		now := models.CanonicalUTCMillis(time.Now())
		if err := db.Model(&models.Team{}).Where("id = ? AND deleted_at IS NULL", teamID).
			Updates(map[string]any{"name": strings.TrimSpace(request.Name), "updated_at": now}).Error; err != nil {
			auth.Error(c, http.StatusInternalServerError, "TEAM_UPDATE_FAILED", "could not update team")
			return
		}
		var team models.Team
		if err := db.First(&team, "id = ?", teamID).Error; err != nil {
			auth.Error(c, http.StatusNotFound, "TEAM_NOT_FOUND", "team not found")
			return
		}
		auth.Success(c, http.StatusOK, team)
	})
	protected.DELETE("/teams/:id", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		teamID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team ID")
			return
		}
		role, err := RoleFor(db, teamID, actor)
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "TEAM_LOOKUP_FAILED", "team lookup failed")
			return
		}
		if role != "owner" {
			auth.Error(c, http.StatusForbidden, "FORBIDDEN", "only the owner can delete this team")
			return
		}
		now := models.CanonicalUTCMillis(time.Now())
		err = teamsync.WithMutationBarrier(func() error {
			return db.Transaction(func(tx *gorm.DB) error {
				if err := tx.Model(&models.Vault{}).Where("team_id = ? AND deleted_at IS NULL", teamID).Update("deleted_at", now).Error; err != nil {
					return err
				}
				if err := tx.Model(&models.TeamMember{}).Where("team_id = ?", teamID).Updates(map[string]any{"state": "removed", "updated_at": now}).Error; err != nil {
					return err
				}
				return tx.Model(&models.Team{}).Where("id = ? AND deleted_at IS NULL", teamID).
					Updates(map[string]any{"deleted_at": now, "updated_at": now}).Error
			})
		})
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "TEAM_DELETE_FAILED", "could not delete team")
			return
		}
		c.Status(http.StatusNoContent)
	})
	protected.GET("/teams/:id/members", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		teamID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team ID")
			return
		}
		role, err := RoleFor(db, teamID, actor)
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "TEAM_LOOKUP_FAILED", "team lookup failed")
			return
		}
		if role == "" {
			auth.Error(c, http.StatusForbidden, "FORBIDDEN", "team membership required")
			return
		}
		var members []models.TeamMember
		if err := db.Where("team_id = ? AND state = ?", teamID, "active").Order("created_at, id").Find(&members).Error; err != nil {
			auth.Error(c, http.StatusInternalServerError, "MEMBER_LIST_FAILED", "could not list members")
			return
		}
		type memberView struct {
			ID          uuid.UUID `json:"id"`
			UserID      uuid.UUID `json:"user_id"`
			Email       string    `json:"email"`
			Username    string    `json:"username"`
			Role        string    `json:"role"`
			JoinedAt    string    `json:"joined_at"`
			PublicKey   string    `json:"public_key"`
			Fingerprint string    `json:"fingerprint"`
		}
		result := make([]memberView, 0, len(members))
		for _, member := range members {
			var user models.User
			if err := db.Select("id", "email", "full_name", "public_key").First(&user, "id = ?", member.UserID).Error; err != nil {
				auth.Error(c, http.StatusInternalServerError, "MEMBER_LIST_FAILED", "could not list members")
				return
			}
			view := memberView{ID: member.ID, UserID: user.ID, Email: user.Email, Username: user.FullName,
				Role: member.Role, JoinedAt: member.CreatedAt}
			if user.PublicKey != nil {
				view.PublicKey = *user.PublicKey
				view.Fingerprint, _ = FingerprintPublicKey(*user.PublicKey)
			}
			result = append(result, view)
		}
		auth.Success(c, http.StatusOK, result)
	})
	protected.POST("/teams", func(c *gin.Context) {
		ownerID, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		var request struct {
			Name string `json:"name"`
		}
		if err := c.ShouldBindJSON(&request); err != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team name")
			return
		}
		name := strings.TrimSpace(request.Name)
		if name == "" || len(name) > 120 {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team name")
			return
		}
		team := models.Team{ID: uuid.New(), OwnerID: ownerID, Name: name}
		err := db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(&team).Error; err != nil {
				return err
			}
			member := models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: ownerID, Role: "owner", State: "active"}
			return tx.Create(&member).Error
		})
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "TEAM_CREATE_FAILED", "could not create team")
			return
		}
		auth.Success(c, http.StatusCreated, team)
	})
	protected.GET("/teams", func(c *gin.Context) {
		memberID, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		teams := make([]models.Team, 0)
		err := db.Model(&models.Team{}).Joins("JOIN team_members ON team_members.team_id = teams.id").
			Where("team_members.user_id = ? AND team_members.state = ? AND teams.deleted_at IS NULL", memberID, "active").
			Order("teams.name, teams.id").Find(&teams).Error
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "TEAM_LIST_FAILED", "could not list teams")
			return
		}
		auth.Success(c, http.StatusOK, teams)
	})
}
