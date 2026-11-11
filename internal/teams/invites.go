package teams

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/auth"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

func FingerprintPublicKey(publicKey string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(publicKey)
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid identity key")
	}
	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", errors.New("invalid identity key")
	}
	sum := sha256.Sum256(raw)
	return base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

type inviteRequest struct {
	Email                string                    `json:"email"`
	Role                 string                    `json:"role"`
	RecipientFingerprint string                    `json:"recipient_fingerprint"`
	Envelopes            []models.VaultKeyEnvelope `json:"envelopes"`
}

func expirePendingInvites(tx *gorm.DB, recipient uuid.UUID) error {
	now := models.CanonicalUTCMillis(time.Now())
	var expired []models.TeamInvite
	if err := tx.Where("recipient_user_id = ? AND state = ? AND expires_at <= ?", recipient, "pending", now).Find(&expired).Error; err != nil {
		return err
	}
	for _, invite := range expired {
		if err := tx.Model(&invite).Updates(map[string]any{"state": "expired", "updated_at": now}).Error; err != nil {
			return err
		}
		if err := tx.Where("team_id = ? AND recipient_user_id = ?", invite.TeamID, recipient).Delete(&models.VaultKeyEnvelope{}).Error; err != nil {
			return err
		}
	}
	return nil
}

func registerInviteRoutes(protected *gin.RouterGroup, db *gorm.DB) {
	protected.GET("/teams/:id/recipient-key", func(c *gin.Context) {
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
		email := strings.ToLower(strings.TrimSpace(c.Query("email")))
		var user models.User
		if email == "" || db.Select("id", "public_key").Where("email = ?", email).Take(&user).Error != nil || user.PublicKey == nil {
			auth.Error(c, http.StatusNotFound, "RECIPIENT_NOT_FOUND", "existing account with identity key required")
			return
		}
		fingerprint, err := FingerprintPublicKey(*user.PublicKey)
		if err != nil {
			auth.Error(c, http.StatusNotFound, "RECIPIENT_NOT_FOUND", "existing account with identity key required")
			return
		}
		auth.Success(c, http.StatusOK, gin.H{"user_id": user.ID, "public_key": *user.PublicKey, "fingerprint": fingerprint})
	})
	protected.POST("/teams/:id/invites", func(c *gin.Context) {
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
		var request inviteRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid invitation")
			return
		}
		email := strings.ToLower(strings.TrimSpace(request.Email))
		if email == "" || (request.Role != "member" && request.Role != "admin") || (request.Role == "admin" && role != "owner") {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid invitation")
			return
		}
		var recipient models.User
		if err := db.Where("email = ?", email).Take(&recipient).Error; err != nil || recipient.PublicKey == nil {
			auth.Error(c, http.StatusNotFound, "RECIPIENT_NOT_FOUND", "existing account with identity key required")
			return
		}
		if recipient.ID == actor {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "cannot invite yourself")
			return
		}
		fingerprint, err := FingerprintPublicKey(*recipient.PublicKey)
		if err != nil || fingerprint != request.RecipientFingerprint {
			auth.Error(c, http.StatusConflict, "KEY_CHANGED", "recipient identity key changed")
			return
		}
		invite := models.TeamInvite{ID: uuid.New(), TeamID: teamID, RecipientUserID: recipient.ID,
			RecipientEmail: email, RecipientFingerprint: fingerprint, Role: request.Role, State: "pending", InviterUserID: actor}
		err = db.Transaction(func(tx *gorm.DB) error {
			if err := expirePendingInvites(tx, recipient.ID); err != nil {
				return err
			}
			var existing int64
			if err := tx.Model(&models.TeamMember{}).Where("team_id = ? AND user_id = ? AND state = ?", teamID, recipient.ID, "active").Count(&existing).Error; err != nil {
				return err
			}
			if existing > 0 {
				return errAlreadyMember
			}
			if err := tx.Model(&models.TeamInvite{}).Where("team_id = ? AND recipient_user_id = ? AND state = ?", teamID, recipient.ID, "pending").Count(&existing).Error; err != nil {
				return err
			}
			if existing > 0 {
				return errPendingInvite
			}
			var vaults []models.Vault
			if err := tx.Where("team_id = ? AND deleted_at IS NULL", teamID).Find(&vaults).Error; err != nil {
				return err
			}
			for _, vault := range vaults {
				if vault.RotationState != "ready" {
					return errRotationPending
				}
			}
			if len(vaults) != len(request.Envelopes) {
				return errMissingEnvelope
			}
			envelopes := make(map[uuid.UUID]models.VaultKeyEnvelope, len(request.Envelopes))
			for _, envelope := range request.Envelopes {
				envelopes[envelope.VaultID] = envelope
			}
			if len(envelopes) != len(vaults) {
				return errMissingEnvelope
			}
			for _, vault := range vaults {
				envelope, found := envelopes[vault.ID]
				if !found || envelope.TeamID != teamID || envelope.Epoch != vault.KeyEpoch || envelope.RecipientUserID != recipient.ID ||
					envelope.RecipientFingerprint != fingerprint || envelope.Version != 1 || envelope.EphemeralPublicKey == "" || envelope.Nonce == "" || envelope.Ciphertext == "" {
					return errMissingEnvelope
				}
			}
			if err := tx.Create(&invite).Error; err != nil {
				return err
			}
			for _, vault := range vaults {
				envelope := envelopes[vault.ID]
				envelope.ID = uuid.New()
				if err := tx.Create(&envelope).Error; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, errAlreadyMember) || errors.Is(err, errPendingInvite) {
				auth.Error(c, http.StatusConflict, "INVITE_CONFLICT", "membership or invitation already exists")
				return
			}
			if errors.Is(err, errRotationPending) {
				auth.Error(c, http.StatusConflict, "ROTATION_REQUIRED", "rotate shared vault keys before inviting")
				return
			}
			if errors.Is(err, errMissingEnvelope) {
				auth.Error(c, http.StatusBadRequest, "MISSING_ENVELOPE", "one envelope per team vault is required")
				return
			}
			auth.Error(c, http.StatusInternalServerError, "INVITE_FAILED", "could not create invitation")
			return
		}
		auth.Success(c, http.StatusCreated, invite)
	})
	protected.GET("/teams/invites/mine", func(c *gin.Context) {
		recipient, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		invites := make([]models.TeamInvite, 0)
		err := db.Transaction(func(tx *gorm.DB) error {
			if err := expirePendingInvites(tx, recipient); err != nil {
				return err
			}
			return tx.Where("recipient_user_id = ? AND state = ?", recipient, "pending").Order("created_at DESC").Find(&invites).Error
		})
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "INVITE_LIST_FAILED", "could not list invitations")
			return
		}
		auth.Success(c, http.StatusOK, invites)
	})
	protected.POST("/teams/invites/:id/decline", func(c *gin.Context) {
		recipient, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		inviteID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid invitation ID")
			return
		}
		var invite models.TeamInvite
		err = db.Transaction(func(tx *gorm.DB) error {
			if err := tx.First(&invite, "id = ?", inviteID).Error; err != nil {
				return err
			}
			if invite.RecipientUserID != recipient {
				return errWrongRecipient
			}
			if invite.State != "pending" {
				return errInviteUnavailable
			}
			if err := tx.Model(&invite).Updates(map[string]any{"state": "declined", "updated_at": models.CanonicalUTCMillis(time.Now())}).Error; err != nil {
				return err
			}
			return tx.Where("team_id = ? AND recipient_user_id = ?", invite.TeamID, invite.RecipientUserID).Delete(&models.VaultKeyEnvelope{}).Error
		})
		if err != nil {
			if errors.Is(err, errWrongRecipient) || errors.Is(err, gorm.ErrRecordNotFound) {
				auth.Error(c, http.StatusForbidden, "FORBIDDEN", "invitation unavailable")
				return
			}
			if errors.Is(err, errInviteUnavailable) {
				auth.Error(c, http.StatusConflict, "INVITE_UNAVAILABLE", "invitation already handled")
				return
			}
			auth.Error(c, http.StatusInternalServerError, "INVITE_DECLINE_FAILED", "could not decline invitation")
			return
		}
		auth.Success(c, http.StatusOK, invite)
	})
	protected.DELETE("/teams/:id/invites/:inviteId", func(c *gin.Context) {
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
		inviteID, err := uuid.Parse(c.Param("inviteId"))
		if err != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid invitation ID")
			return
		}
		err = db.Transaction(func(tx *gorm.DB) error {
			var invite models.TeamInvite
			if err := tx.Where("id = ? AND team_id = ?", inviteID, teamID).Take(&invite).Error; err != nil {
				return err
			}
			if invite.State != "pending" {
				return errInviteUnavailable
			}
			if err := tx.Model(&invite).Updates(map[string]any{"state": "cancelled", "updated_at": models.CanonicalUTCMillis(time.Now())}).Error; err != nil {
				return err
			}
			return tx.Where("team_id = ? AND recipient_user_id = ?", teamID, invite.RecipientUserID).Delete(&models.VaultKeyEnvelope{}).Error
		})
		if err != nil {
			if errors.Is(err, errInviteUnavailable) {
				auth.Error(c, http.StatusConflict, "INVITE_UNAVAILABLE", "invitation already handled")
				return
			}
			if errors.Is(err, gorm.ErrRecordNotFound) {
				auth.Error(c, http.StatusNotFound, "INVITE_NOT_FOUND", "invitation not found")
				return
			}
			auth.Error(c, http.StatusInternalServerError, "INVITE_CANCEL_FAILED", "could not cancel invitation")
			return
		}
		c.Status(http.StatusNoContent)
	})
	protected.POST("/teams/invites/:id/accept", func(c *gin.Context) {
		recipient, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		inviteID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid invitation ID")
			return
		}
		var invite models.TeamInvite
		err = db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Where("id = ?", inviteID).Take(&invite).Error; err != nil {
				return err
			}
			if invite.RecipientUserID != recipient {
				return errWrongRecipient
			}
			if invite.State != "pending" || invite.ExpiresAt <= models.CanonicalUTCMillis(time.Now()) {
				return errInviteUnavailable
			}
			var user models.User
			if err := tx.First(&user, "id = ?", recipient).Error; err != nil {
				return err
			}
			if user.PublicKey == nil {
				return errKeyChanged
			}
			fingerprint, err := FingerprintPublicKey(*user.PublicKey)
			if err != nil || fingerprint != invite.RecipientFingerprint {
				return errKeyChanged
			}
			var vaults []models.Vault
			if err := tx.Where("team_id = ? AND deleted_at IS NULL", invite.TeamID).Find(&vaults).Error; err != nil {
				return err
			}
			for _, vault := range vaults {
				if vault.RotationState != "ready" {
					return errRotationPending
				}
				var count int64
				if err := tx.Model(&models.VaultKeyEnvelope{}).Where("vault_id = ? AND epoch = ? AND recipient_user_id = ?", vault.ID, vault.KeyEpoch, recipient).Count(&count).Error; err != nil {
					return err
				}
				if count != 1 {
					return errInviteUnavailable
				}
				// An invite accepted during key rotation must invalidate the
				// rotation's member snapshot. The compare-and-swap also rejects
				// acceptance if the cutover committed first.
				updated := tx.Model(&models.Vault{}).
					Where("id = ? AND key_epoch = ? AND revision = ? AND rotation_state = ?", vault.ID, vault.KeyEpoch, vault.Revision, "ready").
					Update("revision", gorm.Expr("revision + 1"))
				if updated.Error != nil {
					return updated.Error
				}
				if updated.RowsAffected != 1 {
					return errRotationPending
				}
			}
			member := models.TeamMember{ID: uuid.New(), TeamID: invite.TeamID, UserID: recipient, Role: invite.Role, State: "active"}
			if err := tx.Create(&member).Error; err != nil {
				return err
			}
			return tx.Model(&invite).Updates(map[string]any{"state": "accepted", "updated_at": models.CanonicalUTCMillis(time.Now())}).Error
		})
		if err != nil {
			if errors.Is(err, errWrongRecipient) || errors.Is(err, gorm.ErrRecordNotFound) {
				auth.Error(c, http.StatusForbidden, "FORBIDDEN", "invitation unavailable")
				return
			}
			if errors.Is(err, errInviteUnavailable) {
				auth.Error(c, http.StatusConflict, "INVITE_UNAVAILABLE", "invitation expired or already used")
				return
			}
			if errors.Is(err, errRotationPending) {
				auth.Error(c, http.StatusConflict, "ROTATION_REQUIRED", "rotate shared vault keys before accepting")
				return
			}
			if errors.Is(err, errKeyChanged) {
				auth.Error(c, http.StatusConflict, "KEY_CHANGED", "recipient identity key changed")
				return
			}
			auth.Error(c, http.StatusInternalServerError, "INVITE_ACCEPT_FAILED", "could not accept invitation")
			return
		}
		auth.Success(c, http.StatusOK, invite)
	})
}

var (
	errAlreadyMember     = errors.New("already a member")
	errPendingInvite     = errors.New("pending invitation")
	errMissingEnvelope   = errors.New("missing envelope")
	errWrongRecipient    = errors.New("wrong recipient")
	errInviteUnavailable = errors.New("invitation unavailable")
	errKeyChanged        = errors.New("identity key changed")
	errRotationPending   = errors.New("team vault key rotation required")
)
