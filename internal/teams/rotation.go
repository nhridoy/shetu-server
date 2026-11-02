package teams

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/terra-server/internal/auth"
	"github.com/nhridoy/terra-server/internal/models"
	teamsync "github.com/nhridoy/terra-server/internal/sync"
	"gorm.io/gorm"
	"net/http"
	"slices"
	"sort"
	"time"
)

var errRotationConflict = errors.New("rotation state or snapshot changed")
var errRotationInvalid = errors.New("invalid rotation payload")
var rotationTables = []string{"groups", "hosts", "keys", "snippets", "workspaces", "presets", "port_forwards"}

type rotationRow struct {
	Table    string    `json:"table"`
	ID       uuid.UUID `json:"id"`
	Revision int       `json:"revision"`
	Data     string    `json:"data"`
}
type rotationManifest struct {
	Rows      map[string]rotationRow    `json:"rows"`
	Envelopes []models.VaultKeyEnvelope `json:"envelopes"`
}
type rotationStageRequest struct {
	OperationID      uuid.UUID                 `json:"operation_id"`
	ExpectedEpoch    int                       `json:"expected_epoch"`
	ExpectedRevision int                       `json:"expected_revision"`
	Rows             []rotationRow             `json:"rows"`
	Envelopes        []models.VaultKeyEnvelope `json:"envelopes"`
}

func rotationRowKey(table string, id uuid.UUID) string { return table + ":" + id.String() }
func rotationTableAllowed(name string) bool {
	return slices.Contains(rotationTables, name)
}
func validRotationData(row rotationRow, vaultID uuid.UUID, epoch int) bool {
	if !rotationTableAllowed(row.Table) || row.ID == uuid.Nil || row.Revision < 1 {
		return false
	}
	var p struct {
		V     int    `json:"v"`
		Alg   string `json:"alg"`
		Nonce string `json:"nonce"`
		CT    string `json:"ct"`
		Vault string `json:"vault_id"`
		Table string `json:"record_type"`
		Epoch int    `json:"epoch"`
	}
	if json.Unmarshal([]byte(row.Data), &p) != nil || p.V != 2 || p.Alg != "xchacha20poly1305" || p.Vault != vaultID.String() || p.Table != row.Table || p.Epoch != epoch {
		return false
	}
	nonce, e1 := base64.RawStdEncoding.DecodeString(p.Nonce)
	ct, e2 := base64.RawStdEncoding.DecodeString(p.CT)
	return e1 == nil && e2 == nil && len(nonce) == 24 && len(ct) >= 16
}
func validRotationGrants(tx *gorm.DB, vault models.Vault, grants []models.VaultKeyEnvelope, epoch int) error {
	var members []models.TeamMember
	if err := tx.Where("team_id = ? AND state = ?", *vault.TeamID, "active").Find(&members).Error; err != nil {
		return err
	}
	if len(members) == 0 || len(members) != len(grants) {
		return errRotationInvalid
	}
	byUser := make(map[uuid.UUID]models.VaultKeyEnvelope, len(grants))
	for _, g := range grants {
		if g.VaultID != vault.ID || g.TeamID != *vault.TeamID || g.Epoch != epoch || g.Version != 1 || g.RecipientUserID == uuid.Nil || g.EphemeralPublicKey == "" || g.Nonce == "" || g.Ciphertext == "" {
			return errRotationInvalid
		}
		if _, ok := byUser[g.RecipientUserID]; ok {
			return errRotationInvalid
		}
		byUser[g.RecipientUserID] = g
	}
	for _, m := range members {
		g, ok := byUser[m.UserID]
		if !ok {
			return errRotationInvalid
		}
		var u models.User
		if err := tx.Select("id", "public_key").First(&u, "id = ?", m.UserID).Error; err != nil {
			return err
		}
		if u.PublicKey == nil {
			return errRotationInvalid
		}
		fp, err := FingerprintPublicKey(*u.PublicKey)
		if err != nil || fp != g.RecipientFingerprint {
			return errRotationInvalid
		}
	}
	return nil
}
func rotationInventory(tx *gorm.DB, vaultID uuid.UUID) (map[string]int, error) {
	result := make(map[string]int)
	for _, table := range rotationTables {
		var rows []struct {
			ID       uuid.UUID `gorm:"column:id"`
			Revision int       `gorm:"column:revision"`
		}
		if err := tx.Table(table).Select("id, revision").Where("vault_id = ? AND deleted_at IS NULL", vaultID).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			result[rotationRowKey(table, row.ID)] = row.Revision
		}
	}
	return result, nil
}
func rotationRecord(tx *gorm.DB, table string, id uuid.UUID) (map[string]any, error) {
	var model any
	switch table {
	case "groups":
		model = &models.Group{}
	case "hosts":
		model = &models.Host{}
	case "keys":
		model = &models.Key{}
	case "snippets":
		model = &models.Snippet{}
	case "workspaces":
		model = &models.Workspace{}
	case "presets":
		model = &models.Preset{}
	case "port_forwards":
		model = &models.PortForward{}
	default:
		return nil, errRotationInvalid
	}
	if err := tx.First(model, "id = ?", id).Error; err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(model)
	if err != nil {
		return nil, err
	}
	var record map[string]any
	err = json.Unmarshal(encoded, &record)
	return record, err
}
func rotationVault(tx *gorm.DB, vaultID, actor uuid.UUID) (models.Vault, error) {
	var vault models.Vault
	if err := tx.Where("id = ? AND deleted_at IS NULL", vaultID).Take(&vault).Error; err != nil {
		return vault, err
	}
	if vault.TeamID == nil {
		return vault, errRotationConflict
	}
	role, err := RoleFor(tx, *vault.TeamID, actor)
	if err != nil {
		return vault, err
	}
	if role != "owner" && role != "admin" {
		return vault, errMemberPermission
	}
	return vault, nil
}
func rotationError(c *gin.Context, err error) {
	status, code := http.StatusInternalServerError, "ROTATION_FAILED"
	switch {
	case errors.Is(err, errMemberPermission):
		status, code = http.StatusForbidden, "FORBIDDEN"
	case errors.Is(err, gorm.ErrRecordNotFound):
		status, code = http.StatusNotFound, "VAULT_NOT_FOUND"
	case errors.Is(err, errRotationInvalid):
		status, code = http.StatusBadRequest, "INVALID_ROTATION"
	case errors.Is(err, errRotationConflict):
		status, code = http.StatusConflict, "ROTATION_CONFLICT"
	}
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": err.Error()}})
}
func registerRotationRoutes(protected *gin.RouterGroup, db *gorm.DB) {
	protected.GET("/vaults/:id/rotation/snapshot", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			c.Status(http.StatusUnauthorized)
			return
		}
		vaultID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		vault, err := rotationVault(db, vaultID, actor)
		if err != nil {
			rotationError(c, err)
			return
		}
		if vault.RotationState != "rotation_required" {
			rotationError(c, errRotationConflict)
			return
		}
		rows := make([]rotationRow, 0)
		for _, table := range rotationTables {
			var found []rotationRow
			if err := db.Table(table).Select("id, revision, data").Where("vault_id = ? AND deleted_at IS NULL", vaultID).Find(&found).Error; err != nil {
				rotationError(c, err)
				return
			}
			for i := range found {
				found[i].Table = table
			}
			rows = append(rows, found...)
		}
		sort.Slice(rows, func(i, j int) bool {
			return rotationRowKey(rows[i].Table, rows[i].ID) < rotationRowKey(rows[j].Table, rows[j].ID)
		})
		after := c.Query("after")
		start := sort.Search(len(rows), func(i int) bool { return rotationRowKey(rows[i].Table, rows[i].ID) > after })
		end := min(start+100, len(rows))
		page := rows[start:end]
		next := ""
		if end < len(rows) {
			next = rotationRowKey(rows[end-1].Table, rows[end-1].ID)
		}
		auth.Success(c, http.StatusOK, gin.H{"vault_id": vaultID, "team_id": vault.TeamID, "epoch": vault.KeyEpoch, "revision": vault.Revision, "rows": page, "next": next, "has_more": end < len(rows)})
	})
	protected.POST("/vaults/:id/rotation/stage", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			c.Status(http.StatusUnauthorized)
			return
		}
		vaultID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var req rotationStageRequest
		if c.ShouldBindJSON(&req) != nil || req.OperationID == uuid.Nil || req.ExpectedEpoch < 1 || req.ExpectedRevision < 1 || len(req.Rows) > 100 {
			c.Status(http.StatusBadRequest)
			return
		}
		err = db.Transaction(func(tx *gorm.DB) error {
			vault, err := rotationVault(tx, vaultID, actor)
			if err != nil {
				return err
			}
			if vault.KeyEpoch != req.ExpectedEpoch || vault.Revision != req.ExpectedRevision || vault.RotationState != "rotation_required" {
				return errRotationConflict
			}
			if err := validRotationGrants(tx, vault, req.Envelopes, req.ExpectedEpoch+1); err != nil {
				return err
			}
			var stage models.VaultRotation
			err = tx.Where("operation_id = ?", req.OperationID).Take(&stage).Error
			manifest := rotationManifest{Rows: make(map[string]rotationRow), Envelopes: req.Envelopes}
			if err == nil {
				if stage.VaultID != vaultID || stage.OldEpoch != req.ExpectedEpoch || stage.ExpectedRevision != req.ExpectedRevision || stage.State != "staged" {
					return errRotationConflict
				}
				if json.Unmarshal([]byte(stage.Manifest), &manifest) != nil {
					return errRotationConflict
				}
				old, _ := json.Marshal(manifest.Envelopes)
				next, _ := json.Marshal(req.Envelopes)
				if string(old) != string(next) {
					return errRotationConflict
				}
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			for _, row := range req.Rows {
				if !validRotationData(row, vaultID, req.ExpectedEpoch+1) {
					return errRotationInvalid
				}
				key := rotationRowKey(row.Table, row.ID)
				if previous, ok := manifest.Rows[key]; ok && previous != row {
					return errRotationConflict
				}
				manifest.Rows[key] = row
			}
			encoded, err := json.Marshal(manifest)
			if err != nil {
				return err
			}
			if stage.ID == uuid.Nil {
				stage = models.VaultRotation{ID: uuid.New(), VaultID: vaultID, OperationID: req.OperationID, OldEpoch: req.ExpectedEpoch, NewEpoch: req.ExpectedEpoch + 1, ExpectedRevision: req.ExpectedRevision, State: "staged", Manifest: string(encoded)}
				return tx.Create(&stage).Error
			}
			return tx.Model(&stage).Updates(map[string]any{"manifest": string(encoded), "updated_at": models.CanonicalUTCMillis(time.Now())}).Error
		})
		if err != nil {
			rotationError(c, err)
			return
		}
		auth.Success(c, http.StatusOK, gin.H{"operation_id": req.OperationID, "state": "staged"})
	})
	protected.POST("/vaults/:id/rotation/commit", func(c *gin.Context) {
		actor, ok := userID(c)
		if !ok {
			c.Status(http.StatusUnauthorized)
			return
		}
		vaultID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var req struct {
			OperationID uuid.UUID `json:"operation_id"`
		}
		if c.ShouldBindJSON(&req) != nil || req.OperationID == uuid.Nil {
			c.Status(http.StatusBadRequest)
			return
		}
		err = teamsync.WithMutationBarrier(func() error {
			return db.Transaction(func(tx *gorm.DB) error {
				vault, err := rotationVault(tx, vaultID, actor)
				if err != nil {
					return err
				}
				var stage models.VaultRotation
				if err := tx.Where("operation_id = ? AND vault_id = ?", req.OperationID, vaultID).Take(&stage).Error; err != nil {
					return err
				}
				if stage.State == "committed" {
					return nil
				}
				if stage.State != "staged" || vault.RotationState != "rotation_required" || vault.KeyEpoch != stage.OldEpoch || vault.Revision != stage.ExpectedRevision {
					return errRotationConflict
				}
				var manifest rotationManifest
				if json.Unmarshal([]byte(stage.Manifest), &manifest) != nil {
					return errRotationConflict
				}
				if err := validRotationGrants(tx, vault, manifest.Envelopes, stage.NewEpoch); err != nil {
					return err
				}
				inventory, err := rotationInventory(tx, vaultID)
				if err != nil {
					return err
				}
				if len(inventory) != len(manifest.Rows) {
					return errRotationConflict
				}
				for key, revision := range inventory {
					row, ok := manifest.Rows[key]
					if !ok || row.Revision != revision || !validRotationData(row, vaultID, stage.NewEpoch) {
						return errRotationConflict
					}
				}
				now := models.CanonicalUTCMillis(time.Now())
				markerRecord := map[string]any{"id": vault.ID.String(), "vault_id": "", "revision": vault.Revision + 1,
					"created_at": vault.CreatedAt, "updated_at": now, "deleted_at": nil, "edited_at": now,
					"device_id": uuid.Nil.String(), "operation_id": req.OperationID.String(), "name": vault.Name,
					"owner_id": vault.OwnerID.String(), "kind": vault.Kind, "sort_order": vault.SortOrder,
					"is_default": vault.IsDefault, "data": "{}"}
				markerJSON, err := json.Marshal(markerRecord)
				if err != nil {
					return err
				}
				marker := models.SyncChange{VaultID: vaultID, TableName: "vaults", RecordID: vaultID, Envelope: string(markerJSON)}
				if err := tx.Create(&marker).Error; err != nil {
					return err
				}
				for _, g := range manifest.Envelopes {
					g.ID = uuid.New()
					if err := tx.Create(&g).Error; err != nil {
						return err
					}
				}
				for _, row := range manifest.Rows {
					result := tx.Table(row.Table).Where("id = ? AND vault_id = ? AND revision = ? AND deleted_at IS NULL", row.ID, vaultID, row.Revision).Updates(map[string]any{"data": row.Data, "revision": row.Revision + 1, "updated_at": now})
					if result.Error != nil {
						return result.Error
					}
					if result.RowsAffected != 1 {
						return errRotationConflict
					}
					record, err := rotationRecord(tx, row.Table, row.ID)
					if err != nil {
						return err
					}
					encoded, err := json.Marshal(record)
					if err != nil {
						return err
					}
					if err := tx.Create(&models.SyncChange{VaultID: vaultID, TableName: row.Table, RecordID: row.ID, Envelope: string(encoded)}).Error; err != nil {
						return err
					}
				}
				result := tx.Model(&models.Vault{}).Where("id = ? AND key_epoch = ? AND revision = ?", vaultID, stage.OldEpoch, stage.ExpectedRevision).Updates(map[string]any{"key_epoch": stage.NewEpoch, "rotation_cursor": marker.Seq, "rotation_state": "ready", "revision": stage.ExpectedRevision + 1, "updated_at": now})
				if result.Error != nil {
					return result.Error
				}
				if result.RowsAffected != 1 {
					return errRotationConflict
				}
				var pendingInvites []models.TeamInvite
				if err := tx.Where("team_id = ? AND state = ?", *vault.TeamID, "pending").Find(&pendingInvites).Error; err != nil {
					return err
				}
				for _, invite := range pendingInvites {
					if err := tx.Model(&invite).Updates(map[string]any{"state": "cancelled", "updated_at": now}).Error; err != nil {
						return err
					}
					if err := tx.Where("team_id = ? AND recipient_user_id = ?", *vault.TeamID, invite.RecipientUserID).Delete(&models.VaultKeyEnvelope{}).Error; err != nil {
						return err
					}
				}
				return tx.Model(&stage).Updates(map[string]any{"state": "committed", "updated_at": now}).Error
			})
		})
		if err != nil {
			rotationError(c, err)
			return
		}
		auth.Success(c, http.StatusOK, gin.H{"operation_id": req.OperationID, "state": "committed"})
	})
}
