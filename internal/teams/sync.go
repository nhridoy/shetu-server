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
	"gorm.io/gorm"
)

const (
	teamSyncMaxBody       = 256 * 1024
	teamSyncMaxOperation  = 32 * 1024
	teamSyncMaxOperations = 50
)

type teamSyncOperation struct {
	OperationID uuid.UUID       `json:"operation_id"`
	Type        string          `json:"type"`
	Payload     json.RawMessage `json:"payload"`
}

type teamSyncRequest struct {
	Cursor           *string `json:"cursor"`
	KnownVaultEpochs []struct {
		VaultID  uuid.UUID `json:"vault_id"`
		KeyEpoch int       `json:"key_epoch"`
	} `json:"known_vault_epochs"`
	Operations []teamSyncOperation `json:"operations"`
}

type teamSyncResult struct {
	OperationID  uuid.UUID `json:"operation_id"`
	Status       string    `json:"status"`
	ErrorCode    *string   `json:"error_code"`
	ErrorMessage *string   `json:"error_message"`
}

type teamSyncResponse struct {
	Results    []teamSyncResult          `json:"results"`
	Snapshot   map[string]any            `json:"snapshot"`
	Envelopes  []models.VaultKeyEnvelope `json:"envelopes"`
	NextCursor *string                   `json:"next_cursor"`
	HasMore    bool                      `json:"has_more"`
}

func registerTeamSyncRoute(protected *gin.RouterGroup, db *gorm.DB) {
	protected.POST("/teams/sync", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			auth.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "login required")
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, teamSyncMaxBody)
		var request teamSyncRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				auth.Error(c, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "team sync request exceeds 256 KiB")
				return
			}
			auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team sync request")
			return
		}
		if len(request.Operations) > teamSyncMaxOperations || len(request.KnownVaultEpochs) > 100 {
			auth.Error(c, http.StatusBadRequest, "BATCH_TOO_LARGE", "team sync batch exceeds its operation or vault limit")
			return
		}
		for _, epoch := range request.KnownVaultEpochs {
			if epoch.VaultID == uuid.Nil || epoch.KeyEpoch < 0 {
				auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid known vault epoch")
				return
			}
		}
		response := teamSyncResponse{Results: make([]teamSyncResult, 0, len(request.Operations)), Snapshot: map[string]any{}, Envelopes: []models.VaultKeyEnvelope{}, HasMore: false}
		for _, operation := range request.Operations {
			if operation.OperationID == uuid.Nil || len(operation.Payload) == 0 || len(operation.Payload) > teamSyncMaxOperation || !json.Valid(operation.Payload) {
				auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team operation")
				return
			}
			result, err := applyTeamSyncOperation(db, actor, operation)
			if err != nil {
				auth.Error(c, http.StatusInternalServerError, "TEAM_SYNC_FAILED", "could not apply team sync operation")
				return
			}
			response.Results = append(response.Results, result)
		}
		var cursor *uuid.UUID
		if request.Cursor != nil && *request.Cursor != "" {
			id, err := uuid.Parse(*request.Cursor)
			if err != nil {
				auth.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid team snapshot cursor")
				return
			}
			cursor = &id
		}
		snapshot, nextCursor, hasMore, err := teamSyncSnapshot(db, actor, cursor)
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "TEAM_SYNC_FAILED", "could not read team snapshot")
			return
		}
		response.Snapshot = snapshot
		if nextCursor != uuid.Nil {
			value := nextCursor.String()
			response.NextCursor = &value
		}
		response.HasMore = hasMore
		response.Envelopes, err = staleTeamEnvelopes(db, actor, request.KnownVaultEpochs)
		if err != nil {
			auth.Error(c, http.StatusInternalServerError, "TEAM_SYNC_FAILED", "could not read team key envelopes")
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": response})
	})
}

func applyTeamSyncOperation(db *gorm.DB, actor uuid.UUID, operation teamSyncOperation) (teamSyncResult, error) {
	result := teamSyncResult{OperationID: operation.OperationID}
	err := db.Transaction(func(tx *gorm.DB) error {
		var previous models.TeamSyncOperation
		if err := tx.Where("user_id = ? AND operation_id = ?", actor, operation.OperationID).Take(&previous).Error; err == nil {
			return json.Unmarshal([]byte(previous.Outcome), &result)
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		message, code := applyTeamSyncMutation(tx, actor, operation)
		if code == "" {
			result.Status = "accepted"
		} else {
			result.Status, result.ErrorCode, result.ErrorMessage = "rejected", &code, &message
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		return tx.Create(&models.TeamSyncOperation{UserID: actor, OperationID: operation.OperationID, Outcome: string(encoded)}).Error
	})
	if err != nil {
		var previous models.TeamSyncOperation
		if lookupErr := db.Where("user_id = ? AND operation_id = ?", actor, operation.OperationID).Take(&previous).Error; lookupErr == nil {
			if decodeErr := json.Unmarshal([]byte(previous.Outcome), &result); decodeErr == nil {
				return result, nil
			}
		}
	}
	return result, err
}

func applyTeamSyncMutation(tx *gorm.DB, actor uuid.UUID, operation teamSyncOperation) (string, string) {
	var payload map[string]json.RawMessage
	if json.Unmarshal(operation.Payload, &payload) != nil {
		return "invalid operation payload", "VALIDATION_ERROR"
	}
	readID := func(key string) (uuid.UUID, bool) {
		var value string
		if json.Unmarshal(payload[key], &value) != nil {
			return uuid.Nil, false
		}
		id, err := uuid.Parse(value)
		return id, err == nil && id != uuid.Nil
	}
	readName := func() (string, bool) {
		var value string
		if json.Unmarshal(payload["name"], &value) != nil {
			return "", false
		}
		value = strings.TrimSpace(value)
		return value, value != "" && len(value) <= 120
	}
	now := models.CanonicalUTCMillis(time.Now())
	switch operation.Type {
	case "team.create":
		id, ok := readID("team_id")
		name, nameOK := readName()
		if !ok || !nameOK {
			return "invalid team ID or name", "VALIDATION_ERROR"
		}
		team := models.Team{ID: id, OwnerID: actor, Name: name, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&team).Error; err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") || strings.Contains(strings.ToLower(err.Error()), "primary key") {
				return "team ID already exists", "CONFLICT"
			}
			return "could not create team", "INTERNAL_ERROR"
		}
		member := models.TeamMember{ID: uuid.New(), TeamID: id, UserID: actor, Role: "owner", State: "active", CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&member).Error; err != nil {
			return "could not create owner membership", "INTERNAL_ERROR"
		}
	case "team.rename":
		id, ok := readID("team_id")
		name, nameOK := readName()
		if !ok || !nameOK {
			return "invalid team ID or name", "VALIDATION_ERROR"
		}
		role, err := RoleFor(tx, id, actor)
		if err != nil {
			return "could not verify membership", "INTERNAL_ERROR"
		}
		if role != "owner" && role != "admin" {
			return "team management required", "FORBIDDEN"
		}
		if err := tx.Model(&models.Team{}).Where("id = ? AND deleted_at IS NULL", id).Updates(map[string]any{"name": name, "updated_at": now}).Error; err != nil {
			return "could not rename team", "INTERNAL_ERROR"
		}
	case "team.delete":
		id, ok := readID("team_id")
		if !ok {
			return "invalid team ID", "VALIDATION_ERROR"
		}
		role, err := RoleFor(tx, id, actor)
		if err != nil {
			return "could not verify membership", "INTERNAL_ERROR"
		}
		if role != "owner" {
			return "only the owner can delete this team", "FORBIDDEN"
		}
		if err := tx.Model(&models.Vault{}).Where("team_id = ? AND deleted_at IS NULL", id).Update("deleted_at", now).Error; err != nil {
			return "could not delete team vaults", "INTERNAL_ERROR"
		}
		if err := tx.Model(&models.TeamMember{}).Where("team_id = ?", id).Updates(map[string]any{"state": "removed", "updated_at": now}).Error; err != nil {
			return "could not remove team members", "INTERNAL_ERROR"
		}
		if err := tx.Model(&models.Team{}).Where("id = ? AND deleted_at IS NULL", id).Updates(map[string]any{"deleted_at": now, "updated_at": now}).Error; err != nil {
			return "could not delete team", "INTERNAL_ERROR"
		}
	case "member.remove", "member.role":
		teamID, ok := readID("team_id")
		userID, userOK := readID("user_id")
		if !ok || !userOK {
			return "invalid team or user ID", "VALIDATION_ERROR"
		}
		var member models.TeamMember
		if err := tx.Where("team_id = ? AND user_id = ? AND state = ?", teamID, userID, "active").Take(&member).Error; err != nil {
			return "member not found", "MEMBER_NOT_FOUND"
		}
		actorRole, err := RoleFor(tx, teamID, actor)
		if err != nil {
			return "could not verify membership", "INTERNAL_ERROR"
		}
		if operation.Type == "member.role" {
			var role string
			if json.Unmarshal(payload["role"], &role) != nil || (role != "admin" && role != "member") {
				return "invalid member role", "VALIDATION_ERROR"
			}
			if actorRole != "owner" || member.Role == "owner" {
				return "only the owner can change a member role", "FORBIDDEN"
			}
			if err := tx.Model(&member).Updates(map[string]any{"role": role, "updated_at": now}).Error; err != nil {
				return "could not change member role", "INTERNAL_ERROR"
			}
		} else {
			allowed := actorRole == "owner" || (actorRole == "admin" && member.Role == "member") || (actor == userID && member.Role != "owner")
			if !allowed || member.Role == "owner" {
				return "cannot remove this team member", "FORBIDDEN"
			}
			if err := RemoveMemberTx(tx, teamID, userID, now); err != nil {
				return "could not remove member", "INTERNAL_ERROR"
			}
		}
	case "vault.rename", "vault.delete":
		vaultID, ok := readID("vault_id")
		if !ok {
			return "invalid shared vault ID", "VALIDATION_ERROR"
		}
		var vault models.Vault
		if err := tx.Where("id = ? AND deleted_at IS NULL", vaultID).Take(&vault).Error; err != nil {
			return "shared vault not found", "VAULT_NOT_FOUND"
		}
		if vault.TeamID == nil {
			return "not a team vault", "VALIDATION_ERROR"
		}
		role, err := RoleFor(tx, *vault.TeamID, actor)
		if err != nil {
			return "could not verify team membership", "INTERNAL_ERROR"
		}
		if role != "owner" && role != "admin" {
			return "team management required", "FORBIDDEN"
		}
		if operation.Type == "vault.rename" {
			name, valid := readName()
			if !valid {
				return "invalid shared vault name", "VALIDATION_ERROR"
			}
			if err := tx.Model(&vault).Updates(map[string]any{"name": name, "revision": gorm.Expr("revision + 1"), "updated_at": now, "edited_at": now, "device_id": uuid.Nil, "operation_id": operation.OperationID}).Error; err != nil {
				return "could not rename shared vault", "INTERNAL_ERROR"
			}
			var updated models.Vault
			if err := tx.First(&updated, "id = ?", vaultID).Error; err != nil {
				return "could not reload shared vault", "INTERNAL_ERROR"
			}
			encoded, _ := json.Marshal(updated.SyncRecord())
			if err := tx.Create(&models.SyncChange{VaultID: vaultID, TableName: "vaults", RecordID: vaultID, Envelope: string(encoded)}).Error; err != nil {
				return "could not publish vault rename", "INTERNAL_ERROR"
			}
		} else if err := tx.Model(&vault).Updates(map[string]any{"deleted_at": now, "updated_at": now}).Error; err != nil {
			return "could not delete shared vault", "INTERNAL_ERROR"
		}
	case "vault.create":
		vaultID, vaultOK := readID("vault_id")
		teamID, teamOK := readID("team_id")
		name, nameOK := readName()
		var envelopes []models.VaultKeyEnvelope
		if !vaultOK || !teamOK || !nameOK || json.Unmarshal(payload["envelopes"], &envelopes) != nil {
			return "invalid shared vault payload", "VALIDATION_ERROR"
		}
		role, err := RoleFor(tx, teamID, actor)
		if err != nil {
			return "could not verify membership", "INTERNAL_ERROR"
		}
		if role != "owner" && role != "admin" {
			return "team management required", "FORBIDDEN"
		}
		var team models.Team
		if err := tx.Where("id = ? AND deleted_at IS NULL", teamID).Take(&team).Error; err != nil {
			return "team not found", "TEAM_NOT_FOUND"
		}
		var members []models.TeamMember
		if err := tx.Where("team_id = ? AND state = ?", teamID, "active").Find(&members).Error; err != nil {
			return "could not read team members", "INTERNAL_ERROR"
		}
		grants := make(map[uuid.UUID]models.VaultKeyEnvelope, len(envelopes))
		for _, g := range envelopes {
			grants[g.RecipientUserID] = g
		}
		if len(members) == 0 || len(grants) != len(members) {
			return "one key envelope per active member is required", "MISSING_ENVELOPE"
		}
		for _, member := range members {
			g, found := grants[member.UserID]
			if !found || g.VaultID != vaultID || g.TeamID != teamID || g.Epoch != 1 || g.Version != 1 || g.EphemeralPublicKey == "" || g.Nonce == "" || g.Ciphertext == "" {
				return "invalid team key envelopes", "MISSING_ENVELOPE"
			}
			var user models.User
			if tx.Select("id", "public_key").First(&user, "id = ?", member.UserID).Error != nil || user.PublicKey == nil {
				return "member identity key unavailable", "MISSING_ENVELOPE"
			}
			fp, err := FingerprintPublicKey(*user.PublicKey)
			if err != nil || fp != g.RecipientFingerprint {
				return "member identity key changed", "KEY_CHANGED"
			}
		}
		vault := models.Vault{ID: vaultID, OwnerID: team.OwnerID, TeamID: &teamID, KeyEpoch: 1, RotationState: "ready", Revision: 1, Kind: "team", Name: name, Data: "{}"}
		if err := tx.Create(&vault).Error; err != nil {
			return "shared vault already exists", "CONFLICT"
		}
		for _, member := range members {
			g := grants[member.UserID]
			g.ID = uuid.New()
			if err := tx.Create(&g).Error; err != nil {
				return "could not store key envelope", "INTERNAL_ERROR"
			}
		}
	case "invite.create":
		teamID, ok := readID("team_id")
		var email, requestedRole, fingerprint string
		json.Unmarshal(payload["email"], &email)
		json.Unmarshal(payload["role"], &requestedRole)
		json.Unmarshal(payload["recipient_fingerprint"], &fingerprint)
		var envelopes []models.VaultKeyEnvelope
		if !ok || json.Unmarshal(payload["envelopes"], &envelopes) != nil {
			return "invalid invitation payload", "VALIDATION_ERROR"
		}
		email = strings.ToLower(strings.TrimSpace(email))
		role, err := RoleFor(tx, teamID, actor)
		if err != nil {
			return "could not verify membership", "INTERNAL_ERROR"
		}
		if (role != "owner" && role != "admin") || (requestedRole != "member" && requestedRole != "admin") || (requestedRole == "admin" && role != "owner") {
			return "team management required", "FORBIDDEN"
		}
		var recipient models.User
		if email == "" || tx.Where("email = ?", email).Take(&recipient).Error != nil || recipient.PublicKey == nil {
			return "existing account with identity key required", "RECIPIENT_NOT_FOUND"
		}
		if recipient.ID == actor {
			return "cannot invite yourself", "VALIDATION_ERROR"
		}
		fp, err := FingerprintPublicKey(*recipient.PublicKey)
		if err != nil || fp != fingerprint {
			return "recipient identity key changed", "KEY_CHANGED"
		}
		if err := expirePendingInvites(tx, recipient.ID); err != nil {
			return "could not expire stale invitations", "INTERNAL_ERROR"
		}
		var existing int64
		if err := tx.Model(&models.TeamMember{}).Where("team_id = ? AND user_id = ? AND state = ?", teamID, recipient.ID, "active").Count(&existing).Error; err != nil {
			return "could not inspect membership", "INTERNAL_ERROR"
		}
		if existing > 0 {
			return "account is already a team member", "INVITE_CONFLICT"
		}
		if err := tx.Model(&models.TeamInvite{}).Where("team_id = ? AND recipient_user_id = ? AND state = ?", teamID, recipient.ID, "pending").Count(&existing).Error; err != nil {
			return "could not inspect existing invitation", "INTERNAL_ERROR"
		}
		if existing > 0 {
			return "an invitation is already pending", "INVITE_CONFLICT"
		}
		var vaults []models.Vault
		if err := tx.Where("team_id = ? AND deleted_at IS NULL", teamID).Find(&vaults).Error; err != nil {
			return "could not read shared vaults", "INTERNAL_ERROR"
		}
		if len(vaults) != len(envelopes) {
			return "one envelope per shared vault is required", "MISSING_ENVELOPE"
		}
		for _, vault := range vaults {
			if vault.RotationState != "ready" {
				return "rotate shared vault keys before inviting", "ROTATION_REQUIRED"
			}
		}
		byVault := make(map[uuid.UUID]models.VaultKeyEnvelope, len(envelopes))
		for _, g := range envelopes {
			if _, duplicate := byVault[g.VaultID]; duplicate {
				return "duplicate vault key envelope", "MISSING_ENVELOPE"
			}
			byVault[g.VaultID] = g
		}
		if len(byVault) != len(vaults) {
			return "one envelope per shared vault is required", "MISSING_ENVELOPE"
		}
		for _, v := range vaults {
			g, found := byVault[v.ID]
			if !found || v.RotationState != "ready" || g.TeamID != teamID || g.Epoch != v.KeyEpoch || g.RecipientUserID != recipient.ID || g.RecipientFingerprint != fp || g.Version != 1 || g.EphemeralPublicKey == "" || g.Nonce == "" || g.Ciphertext == "" {
				return "invalid invitation envelopes", "MISSING_ENVELOPE"
			}
		}
		inviteID, inviteOK := readID("invite_id")
		if !inviteOK {
			return "invalid invitation ID", "VALIDATION_ERROR"
		}
		invite := models.TeamInvite{ID: inviteID, TeamID: teamID, RecipientUserID: recipient.ID, RecipientEmail: email, RecipientFingerprint: fp, Role: requestedRole, State: "pending", InviterUserID: actor}
		if err := tx.Create(&invite).Error; err != nil {
			return "invitation already exists", "CONFLICT"
		}
		for _, v := range vaults {
			g := byVault[v.ID]
			g.ID = uuid.New()
			if err := tx.Create(&g).Error; err != nil {
				return "could not store invitation envelope", "INTERNAL_ERROR"
			}
		}
	case "invite.accept", "invite.decline":
		inviteID, ok := readID("invite_id")
		if !ok {
			return "invalid invitation ID", "VALIDATION_ERROR"
		}
		var invite models.TeamInvite
		if err := tx.Where("id = ?", inviteID).Take(&invite).Error; err != nil {
			return "invitation not found", "INVITE_NOT_FOUND"
		}
		if invite.RecipientUserID != actor || invite.State != "pending" {
			return "invitation unavailable", "FORBIDDEN"
		}
		if invite.ExpiresAt <= now {
			if tx.Model(&invite).Updates(map[string]any{"state": "expired", "updated_at": now}).Error != nil {
				return "could not expire invitation", "INTERNAL_ERROR"
			}
			if tx.Where("team_id = ? AND recipient_user_id = ?", invite.TeamID, actor).Delete(&models.VaultKeyEnvelope{}).Error != nil {
				return "could not discard expired invitation key", "INTERNAL_ERROR"
			}
			return "invitation expired", "INVITE_EXPIRED"
		}
		if operation.Type == "invite.accept" {
			var user models.User
			if tx.First(&user, "id = ?", actor).Error != nil || user.PublicKey == nil {
				return "identity key unavailable", "KEY_CHANGED"
			}
			fp, err := FingerprintPublicKey(*user.PublicKey)
			if err != nil || fp != invite.RecipientFingerprint {
				return "identity key changed", "KEY_CHANGED"
			}
			var vaults []models.Vault
			if err := tx.Where("team_id = ? AND deleted_at IS NULL", invite.TeamID).Find(&vaults).Error; err != nil {
				return "could not read shared vaults", "INTERNAL_ERROR"
			}
			for _, v := range vaults {
				var count int64
				if tx.Model(&models.VaultKeyEnvelope{}).Where("vault_id = ? AND epoch = ? AND recipient_user_id = ?", v.ID, v.KeyEpoch, actor).Count(&count).Error != nil || count != 1 {
					return "invitation key envelope missing", "MISSING_ENVELOPE"
				}
				res := tx.Model(&models.Vault{}).Where("id = ? AND key_epoch = ? AND revision = ? AND rotation_state = ?", v.ID, v.KeyEpoch, v.Revision, "ready").Update("revision", gorm.Expr("revision + 1"))
				if res.Error != nil || res.RowsAffected != 1 {
					return "vault changed during invitation acceptance", "ROTATION_REQUIRED"
				}
			}
			member := models.TeamMember{ID: uuid.New(), TeamID: invite.TeamID, UserID: actor, Role: invite.Role, State: "active"}
			if tx.Create(&member).Error != nil {
				return "already a team member", "CONFLICT"
			}
			if tx.Model(&invite).Updates(map[string]any{"state": "accepted", "updated_at": now}).Error != nil {
				return "could not accept invitation", "INTERNAL_ERROR"
			}
		} else {
			if tx.Model(&invite).Updates(map[string]any{"state": "declined", "updated_at": now}).Error != nil {
				return "could not decline invitation", "INTERNAL_ERROR"
			}
			if tx.Where("team_id = ? AND recipient_user_id = ?", invite.TeamID, actor).Delete(&models.VaultKeyEnvelope{}).Error != nil {
				return "could not discard invitation key", "INTERNAL_ERROR"
			}
		}
	case "vault.rotate":
		return applyTeamVaultRotation(tx, actor, operation, payload, readID, now)
	default:
		return "operation is not supported by this sync version", "UNSUPPORTED_OPERATION"
	}
	return "", ""
}

func applyTeamVaultRotation(tx *gorm.DB, actor uuid.UUID, operation teamSyncOperation, payload map[string]json.RawMessage, readID func(string) (uuid.UUID, bool), now string) (string, string) {
	vaultID, ok := readID("vault_id")
	if !ok {
		return "invalid shared vault ID", "VALIDATION_ERROR"
	}
	var expectedEpoch, expectedRevision, newEpoch int
	var envelopes []models.VaultKeyEnvelope
	var rows []rotationRow
	if json.Unmarshal(payload["expected_key_epoch"], &expectedEpoch) != nil || json.Unmarshal(payload["expected_revision"], &expectedRevision) != nil || json.Unmarshal(payload["new_key_epoch"], &newEpoch) != nil || json.Unmarshal(payload["envelopes"], &envelopes) != nil || json.Unmarshal(payload["rows"], &rows) != nil {
		return "invalid rotation payload", "VALIDATION_ERROR"
	}
	rotationID, ok := readID("rotation_id")
	if !ok {
		return "invalid rotation ID", "VALIDATION_ERROR"
	}
	vault, err := rotationVault(tx, vaultID, actor)
	if err != nil {
		return "team management required", "FORBIDDEN"
	}
	if vault.KeyEpoch != expectedEpoch || vault.Revision != expectedRevision || vault.RotationState != "rotation_required" || newEpoch != expectedEpoch+1 {
		return "rotation snapshot changed", "ROTATION_CONFLICT"
	}
	if err := validRotationGrants(tx, vault, envelopes, newEpoch); err != nil {
		return "invalid rotation envelopes", "INVALID_ROTATION"
	}
	inventory, err := rotationInventory(tx, vaultID)
	if err != nil {
		return "could not inspect vault rows", "INTERNAL_ERROR"
	}
	if len(inventory) != len(rows) {
		return "rotation row inventory changed", "ROTATION_CONFLICT"
	}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		key := rotationRowKey(row.Table, row.ID)
		if revision, exists := inventory[key]; !exists || revision != row.Revision || seen[key] || !validRotationData(row, vaultID, newEpoch) {
			return "invalid or stale encrypted rotation row", "ROTATION_CONFLICT"
		}
		seen[key] = true
	}
	for _, grant := range envelopes {
		grant.ID = uuid.New()
		if err := tx.Create(&grant).Error; err != nil {
			return "could not store rotation key envelope", "INTERNAL_ERROR"
		}
	}
	for _, row := range rows {
		result := tx.Table(row.Table).Where("id = ? AND vault_id = ? AND revision = ? AND deleted_at IS NULL", row.ID, vaultID, row.Revision).Updates(map[string]any{"data": row.Data, "revision": row.Revision + 1, "updated_at": now})
		if result.Error != nil || result.RowsAffected != 1 {
			return "vault row changed during rotation", "ROTATION_CONFLICT"
		}
		record, err := rotationRecord(tx, row.Table, row.ID)
		if err != nil {
			return "could not read rotated row", "INTERNAL_ERROR"
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return "could not encode rotated row", "INTERNAL_ERROR"
		}
		if err := tx.Create(&models.SyncChange{VaultID: vaultID, TableName: row.Table, RecordID: row.ID, Envelope: string(encoded)}).Error; err != nil {
			return "could not publish rotated row", "INTERNAL_ERROR"
		}
	}
	markerRecord := map[string]any{"id": vault.ID.String(), "vault_id": "", "revision": vault.Revision + 1, "created_at": vault.CreatedAt, "updated_at": now, "deleted_at": nil, "edited_at": now, "device_id": uuid.Nil.String(), "operation_id": rotationID.String(), "name": vault.Name, "owner_id": vault.OwnerID.String(), "kind": vault.Kind, "sort_order": vault.SortOrder, "is_default": vault.IsDefault, "data": "{}"}
	markerJSON, err := json.Marshal(markerRecord)
	if err != nil {
		return "could not encode rotation marker", "INTERNAL_ERROR"
	}
	marker := models.SyncChange{VaultID: vaultID, TableName: "vaults", RecordID: vaultID, Envelope: string(markerJSON)}
	if err := tx.Create(&marker).Error; err != nil {
		return "could not publish rotation marker", "INTERNAL_ERROR"
	}
	if err := tx.Model(&vault).Updates(map[string]any{"key_epoch": newEpoch, "rotation_cursor": marker.Seq, "rotation_state": "ready", "revision": expectedRevision + 1, "updated_at": now}).Error; err != nil {
		return "could not finalize rotation", "INTERNAL_ERROR"
	}
	if vault.TeamID != nil {
		var pending []models.TeamInvite
		if err := tx.Where("team_id = ? AND state = ?", *vault.TeamID, "pending").Find(&pending).Error; err != nil {
			return "could not inspect pending invitations", "INTERNAL_ERROR"
		}
		for _, invite := range pending {
			if err := tx.Model(&invite).Updates(map[string]any{"state": "cancelled", "updated_at": now}).Error; err != nil {
				return "could not cancel stale invitation", "INTERNAL_ERROR"
			}
			if err := tx.Where("team_id = ? AND recipient_user_id = ?", *vault.TeamID, invite.RecipientUserID).Delete(&models.VaultKeyEnvelope{}).Error; err != nil {
				return "could not remove stale invitation key", "INTERNAL_ERROR"
			}
		}
	}
	return "", ""
}

func teamSyncSnapshot(db *gorm.DB, actor uuid.UUID, cursor *uuid.UUID) (map[string]any, uuid.UUID, bool, error) {
	var memberships []models.TeamMember
	if err := db.Where("user_id = ? AND state = ?", actor, "active").Find(&memberships).Error; err != nil {
		return nil, uuid.Nil, false, err
	}
	teamIDs := make([]uuid.UUID, 0, len(memberships))
	for _, member := range memberships {
		teamIDs = append(teamIDs, member.TeamID)
	}
	allTeamIDs := append([]uuid.UUID(nil), teamIDs...)
	teams := make([]models.Team, 0)
	members := make([]map[string]any, 0)
	vaults := make([]models.Vault, 0)
	nextCursor := uuid.Nil
	hasMore := false
	if len(teamIDs) > 0 {
		query := db.Where("id IN ? AND deleted_at IS NULL", teamIDs)
		if cursor != nil {
			query = query.Where("id > ?", *cursor)
		}
		var page []models.Team
		if err := query.Order("id").Limit(101).Find(&page).Error; err != nil {
			return nil, uuid.Nil, false, err
		}
		if len(page) > 100 {
			hasMore = true
			page = page[:100]
			nextCursor = page[len(page)-1].ID
		}
		teams = page
		pageIDs := make([]uuid.UUID, 0, len(teams))
		for _, team := range teams {
			pageIDs = append(pageIDs, team.ID)
		}
		if len(pageIDs) == 0 {
			teamIDs = nil
		} else {
			teamIDs = pageIDs
		}
		var teamMembers []models.TeamMember
		if len(teamIDs) > 0 {
			if err := db.Where("team_id IN ? AND state = ?", teamIDs, "active").Order("team_id, created_at, id").Find(&teamMembers).Error; err != nil {
				return nil, uuid.Nil, false, err
			}
			for _, member := range teamMembers {
				var user models.User
				if err := db.Select("id", "email", "full_name", "avatar_url", "public_key").First(&user, "id = ?", member.UserID).Error; err != nil {
					return nil, uuid.Nil, false, err
				}
				publicKey := ""
				fingerprint := ""
				if user.PublicKey != nil {
					publicKey = *user.PublicKey
					fingerprint, _ = FingerprintPublicKey(publicKey)
				}
				members = append(members, map[string]any{"id": member.ID, "team_id": member.TeamID, "user_id": member.UserID, "email": user.Email, "full_name": user.FullName, "avatar_url": user.AvatarURL, "role": member.Role, "created_at": member.CreatedAt, "public_key": publicKey, "fingerprint": fingerprint})
			}
		}
		if len(teamIDs) > 0 {
			if err := db.Where("team_id IN ? AND deleted_at IS NULL", teamIDs).Order("id").Find(&vaults).Error; err != nil {
				return nil, uuid.Nil, false, err
			}
		}
	}
	invites := make([]models.TeamInvite, 0)
	if err := db.Where("recipient_user_id = ? AND state = ?", actor, "pending").Order("created_at,id").Find(&invites).Error; err != nil {
		return nil, uuid.Nil, false, err
	}
	var removedMemberships []models.TeamMember
	if err := db.Where("user_id = ? AND state = ? AND NOT EXISTS (SELECT 1 FROM team_members active_member WHERE active_member.team_id = team_members.team_id AND active_member.user_id = ? AND active_member.state = ?)", actor, "removed", actor, "active").Find(&removedMemberships).Error; err != nil {
		return nil, uuid.Nil, false, err
	}
	revokedTeamIDs := make([]uuid.UUID, 0, len(removedMemberships))
	for _, item := range removedMemberships {
		revokedTeamIDs = append(revokedTeamIDs, item.TeamID)
	}
	deletedVaultIDs := make([]uuid.UUID, 0)
	if len(allTeamIDs) > 0 {
		var deleted []models.Vault
		if err := db.Select("id").Where("team_id IN ? AND deleted_at IS NOT NULL", allTeamIDs).Find(&deleted).Error; err != nil {
			return nil, uuid.Nil, false, err
		}
		for _, vault := range deleted {
			deletedVaultIDs = append(deletedVaultIDs, vault.ID)
		}
	}
	return map[string]any{"teams": teams, "members": members, "invites": invites, "vaults": vaults, "revoked_team_ids": revokedTeamIDs, "deleted_vault_ids": deletedVaultIDs}, nextCursor, hasMore, nil
}

func staleTeamEnvelopes(db *gorm.DB, actor uuid.UUID, known []struct {
	VaultID  uuid.UUID `json:"vault_id"`
	KeyEpoch int       `json:"key_epoch"`
}) ([]models.VaultKeyEnvelope, error) {
	knownEpoch := make(map[uuid.UUID]int, len(known))
	for _, item := range known {
		knownEpoch[item.VaultID] = item.KeyEpoch
	}
	var memberships []models.TeamMember
	if err := db.Where("user_id = ? AND state = ?", actor, "active").Find(&memberships).Error; err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(memberships))
	for _, member := range memberships {
		ids = append(ids, member.TeamID)
	}
	if len(ids) == 0 {
		return []models.VaultKeyEnvelope{}, nil
	}
	var vaults []models.Vault
	if err := db.Where("team_id IN ? AND deleted_at IS NULL", ids).Find(&vaults).Error; err != nil {
		return nil, err
	}
	result := make([]models.VaultKeyEnvelope, 0)
	for _, vault := range vaults {
		if knownEpoch[vault.ID] >= vault.KeyEpoch {
			continue
		}
		var envelope models.VaultKeyEnvelope
		err := db.Where("vault_id = ? AND epoch = ? AND recipient_user_id = ?", vault.ID, vault.KeyEpoch, actor).Take(&envelope).Error
		if err == nil {
			result = append(result, envelope)
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}
	return result, nil
}
