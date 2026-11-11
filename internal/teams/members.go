package teams

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/auth"
	"github.com/nhridoy/shetu-server/internal/models"
	teamsync "github.com/nhridoy/shetu-server/internal/sync"
	"gorm.io/gorm"
)

var errMemberPermission = errors.New("member permission denied")
var errMemberUnavailable = errors.New("member unavailable")

func registerMemberRoutes(protected *gin.RouterGroup, db *gorm.DB) {
	protected.PATCH("/teams/:id/members/:userId", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		teamID, err1 := uuid.Parse(c.Param("id"))
		targetID, err2 := uuid.Parse(c.Param("userId"))
		if err1 != nil || err2 != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid member ID")
			return
		}
		role, err := RoleFor(db, teamID, actor)
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "TEAM_LOOKUP_FAILED", "team lookup failed")
			return
		}
		if role != "owner" {
			auth.Error(c, http.StatusForbidden, "FORBIDDEN", "only the owner can change roles")
			return
		}
		var request struct {
			Role string `json:"role"`
		}
		if err := c.ShouldBindJSON(&request); err != nil || (request.Role != "admin" && request.Role != "member") {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid member role")
			return
		}
		var member models.TeamMember
		err = db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Where("team_id = ? AND user_id = ? AND state = ?", teamID, targetID, "active").Take(&member).Error; err != nil {
				return err
			}
			if member.Role == "owner" {
				return errMemberPermission
			}
			now := models.CanonicalUTCMillis(time.Now())
			if err := tx.Model(&member).Updates(map[string]any{"role": request.Role, "updated_at": now}).Error; err != nil {
				return err
			}
			member.Role = request.Role
			member.UpdatedAt = now
			return nil
		})
		if err != nil {
			if errors.Is(err, errMemberPermission) {
				auth.Error(c, http.StatusForbidden, "FORBIDDEN", "cannot change owner role")
				return
			}
			if errors.Is(err, gorm.ErrRecordNotFound) {
				auth.Error(c, http.StatusNotFound, "MEMBER_NOT_FOUND", "member not found")
				return
			}
			auth.Error(c, http.StatusInternalServerError, "ROLE_UPDATE_FAILED", "could not change role")
			return
		}
		auth.Success(c, http.StatusOK, member)
	})
	protected.DELETE("/teams/:id/members/:userId", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		teamID, err1 := uuid.Parse(c.Param("id"))
		targetID, err2 := uuid.Parse(c.Param("userId"))
		if err1 != nil || err2 != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid member ID")
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
		err = teamsync.WithMutationBarrier(func() error {
			return db.Transaction(func(tx *gorm.DB) error {
				currentRole, err := RoleFor(tx, teamID, actor)
				if err != nil {
					return err
				}
				if currentRole == "" {
					return errMemberPermission
				}
				var member models.TeamMember
				if err := tx.Where("team_id = ? AND user_id = ? AND state = ?", teamID, targetID, "active").Take(&member).Error; err != nil {
					return err
				}
				if member.Role == "owner" || (actor != targetID && currentRole != "owner" && !(currentRole == "admin" && member.Role == "member")) {
					return errMemberPermission
				}
				now := models.CanonicalUTCMillis(time.Now())
				if err := tx.Model(&member).Updates(map[string]any{"state": "removed", "updated_at": now}).Error; err != nil {
					return err
				}
				return tx.Model(&models.Vault{}).Where("team_id = ? AND deleted_at IS NULL", teamID).
					Updates(map[string]any{"rotation_state": "rotation_required", "revision": gorm.Expr("revision + 1"), "updated_at": now}).Error
			})
		})
		if err != nil {
			if errors.Is(err, errMemberPermission) {
				auth.Error(c, http.StatusForbidden, "FORBIDDEN", "cannot remove this member")
				return
			}
			if errors.Is(err, gorm.ErrRecordNotFound) {
				auth.Error(c, http.StatusNotFound, "MEMBER_NOT_FOUND", "member not found")
				return
			}
			auth.Error(c, http.StatusInternalServerError, "MEMBER_REMOVE_FAILED", "could not remove member")
			return
		}
		c.Status(http.StatusNoContent)
	})
}
