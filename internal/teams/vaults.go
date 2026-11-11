package teams

import (
	"encoding/json"
	"errors"
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

var errInvalidGrantSet = errors.New("invalid grant set")

type createVaultRequest struct {
	ID        uuid.UUID                 `json:"id"`
	Name      string                    `json:"name"`
	Envelopes []models.VaultKeyEnvelope `json:"envelopes"`
}

func registerVaultRoutes(protected *gin.RouterGroup, db *gorm.DB) {
	protected.POST("/teams/:id/vaults", func(c *gin.Context) {
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
		var request createVaultRequest
		if err := c.ShouldBindJSON(&request); err != nil || request.ID == uuid.Nil || strings.TrimSpace(request.Name) == "" || len(request.Name) > 120 {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team vault")
			return
		}
		var created models.Vault
		err = db.Transaction(func(tx *gorm.DB) error {
			var team models.Team
			if err := tx.Where("id = ? AND deleted_at IS NULL", teamID).Take(&team).Error; err != nil {
				return err
			}
			var members []models.TeamMember
			if err := tx.Where("team_id = ? AND state = ?", teamID, "active").Find(&members).Error; err != nil {
				return err
			}
			if len(members) == 0 || len(members) != len(request.Envelopes) {
				return errInvalidGrantSet
			}
			grants := make(map[uuid.UUID]models.VaultKeyEnvelope, len(request.Envelopes))
			for _, envelope := range request.Envelopes {
				grants[envelope.RecipientUserID] = envelope
			}
			if len(grants) != len(members) {
				return errInvalidGrantSet
			}
			for _, member := range members {
				envelope, found := grants[member.UserID]
				if !found || envelope.VaultID != request.ID || envelope.TeamID != teamID || envelope.Epoch != 1 || envelope.Version != 1 ||
					envelope.EphemeralPublicKey == "" || envelope.Nonce == "" || envelope.Ciphertext == "" {
					return errInvalidGrantSet
				}
				var user models.User
				if err := tx.Select("id", "public_key").First(&user, "id = ?", member.UserID).Error; err != nil {
					return err
				}
				if user.PublicKey == nil {
					return errInvalidGrantSet
				}
				fingerprint, err := FingerprintPublicKey(*user.PublicKey)
				if err != nil || fingerprint != envelope.RecipientFingerprint {
					return errInvalidGrantSet
				}
			}
			created = models.Vault{ID: request.ID, OwnerID: team.OwnerID, TeamID: &teamID, KeyEpoch: 1,
				RotationState: "ready", Revision: 1, Kind: "team", Name: strings.TrimSpace(request.Name), Data: "{}"}
			if err := tx.Create(&created).Error; err != nil {
				return err
			}
			for _, member := range members {
				envelope := grants[member.UserID]
				envelope.ID = uuid.New()
				if err := tx.Create(&envelope).Error; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, errInvalidGrantSet) {
				auth.Error(c, http.StatusBadRequest, "INVALID_GRANTS", "one valid key grant per member is required")
				return
			}
			auth.Error(c, http.StatusInternalServerError, "VAULT_CREATE_FAILED", "could not create team vault")
			return
		}
		auth.Success(c, http.StatusCreated, created)
	})
	protected.GET("/teams/:id/vaults", func(c *gin.Context) {
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
		vaults := make([]models.Vault, 0)
		if err := db.Where("team_id = ? AND deleted_at IS NULL", teamID).Order("name, id").Find(&vaults).Error; err != nil {
			auth.Error(c, http.StatusInternalServerError, "VAULT_LIST_FAILED", "could not list team vaults")
			return
		}
		auth.Success(c, http.StatusOK, vaults)
	})
	protected.PATCH("/teams/:id/vaults/:vaultId", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		teamID, err1 := uuid.Parse(c.Param("id"))
		vaultID, err2 := uuid.Parse(c.Param("vaultId"))
		if err1 != nil || err2 != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team vault ID")
			return
		}
		var request struct {
			Name string `json:"name"`
		}
		if c.ShouldBindJSON(&request) != nil || strings.TrimSpace(request.Name) == "" || len(strings.TrimSpace(request.Name)) > 120 {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid shared vault name")
			return
		}
		var updated models.Vault
		err := db.Transaction(func(tx *gorm.DB) error {
			role, err := RoleFor(tx, teamID, actor)
			if err != nil {
				return err
			}
			if role != "owner" && role != "admin" {
				return errMemberPermission
			}
			if err := tx.Where("id = ? AND team_id = ? AND deleted_at IS NULL", vaultID, teamID).Take(&updated).Error; err != nil {
				return err
			}
			now := models.CanonicalUTCMillis(time.Now())
			opID := uuid.New()
			if err := tx.Model(&updated).Updates(map[string]any{"name": strings.TrimSpace(request.Name), "revision": gorm.Expr("revision + 1"), "updated_at": now, "edited_at": now, "device_id": uuid.Nil, "operation_id": opID}).Error; err != nil {
				return err
			}
			if err := tx.First(&updated, "id = ?", vaultID).Error; err != nil {
				return err
			}
			encoded, err := json.Marshal(updated.SyncRecord())
			if err != nil {
				return err
			}
			return tx.Create(&models.SyncChange{VaultID: vaultID, TableName: "vaults", RecordID: vaultID, Envelope: string(encoded)}).Error
		})
		if err != nil {
			if errors.Is(err, errMemberPermission) {
				auth.Error(c, http.StatusForbidden, "FORBIDDEN", "team management required")
				return
			}
			if errors.Is(err, gorm.ErrRecordNotFound) {
				auth.Error(c, http.StatusNotFound, "VAULT_NOT_FOUND", "shared vault not found")
				return
			}
			auth.Error(c, http.StatusInternalServerError, "VAULT_RENAME_FAILED", "could not rename shared vault")
			return
		}
		auth.Success(c, http.StatusOK, updated)
	})
	protected.DELETE("/teams/:id/vaults/:vaultId", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		teamID, err1 := uuid.Parse(c.Param("id"))
		vaultID, err2 := uuid.Parse(c.Param("vaultId"))
		if err1 != nil || err2 != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team vault ID")
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
		now := models.CanonicalUTCMillis(time.Now())
		var changed *gorm.DB
		err = teamsync.WithMutationBarrier(func() error {
			changed = db.Model(&models.Vault{}).Where("id = ? AND team_id = ? AND deleted_at IS NULL", vaultID, teamID).
				Updates(map[string]any{"deleted_at": now, "updated_at": now})
			return changed.Error
		})
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "VAULT_DELETE_FAILED", "could not delete shared vault")
			return
		}
		if changed.RowsAffected == 0 {
			auth.Error(c, http.StatusNotFound, "VAULT_NOT_FOUND", "shared vault not found")
			return
		}
		c.Status(http.StatusNoContent)
	})
	protected.GET("/vaults/:id/key-envelope", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		vaultID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid vault ID")
			return
		}
		var vault models.Vault
		if err := db.Where("id = ? AND deleted_at IS NULL", vaultID).Take(&vault).Error; err != nil || vault.TeamID == nil {
			auth.Error(c, http.StatusForbidden, "FORBIDDEN", "vault access denied")
			return
		}
		role, err := RoleFor(db, *vault.TeamID, actor)
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "TEAM_LOOKUP_FAILED", "team lookup failed")
			return
		}
		if role == "" {
			auth.Error(c, http.StatusForbidden, "FORBIDDEN", "vault access denied")
			return
		}
		var envelope models.VaultKeyEnvelope
		if err := db.Where("vault_id = ? AND epoch = ? AND recipient_user_id = ?", vaultID, vault.KeyEpoch, actor).Take(&envelope).Error; err != nil {
			auth.Error(c, http.StatusNotFound, "KEY_UNAVAILABLE", "vault key grant unavailable")
			return
		}
		auth.Success(c, http.StatusOK, envelope)
	})
}
