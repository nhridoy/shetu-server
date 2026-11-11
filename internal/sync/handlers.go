package sync

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SQLite writes are serialized so a committed cursor never points past an
// uncommitted earlier event. The database transaction keeps row/event/ledger
// updates indivisible.
var pushMu sync.Mutex

// WithMutationBarrier serializes a team-key cutover with sync pushes in this process.
// The rotation transaction still uses revision checks for other server instances.
func WithMutationBarrier(fn func() error) error {
	pushMu.Lock()
	defer pushMu.Unlock()
	return fn()
}

var errVaultHasLiveRecords = errors.New("vault still has live records")
var errVaultDeleted = errors.New("vault is deleted")
var errRelationshipLookup = errors.New("relationship lookup failed")

func isHistoryTable(table string) bool {
	return table == "session_history" || table == "session_output_chunks" || table == "session_preferences"
}

func requestUser(c *gin.Context) (uuid.UUID, bool) {
	user, ok := c.Get("user_id")
	if !ok {
		return uuid.Nil, false
	}
	id, ok := user.(uuid.UUID)
	return id, ok
}

func accessibleVault(tx *gorm.DB, vaultID, userID uuid.UUID) (models.Vault, bool, bool, error) {
	var vault models.Vault
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", vaultID).Take(&vault).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return vault, false, false, nil
	}
	if err != nil {
		return vault, false, false, err
	}
	if vault.TeamID == nil {
		return vault, true, vault.OwnerID == userID, nil
	}
	if vault.DeletedAt != nil {
		return vault, true, false, nil
	}
	var member models.TeamMember
	err = tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("team_id = ? AND user_id = ? AND state = ?", *vault.TeamID, userID, "active").Take(&member).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return vault, true, false, nil
	}
	return vault, true, err == nil, err
}

func payloadVersionAndEpoch(data any) (int, int, error) {
	raw, ok := data.(string)
	if !ok {
		return 0, 0, errors.New("missing ciphertext")
	}
	if raw == "{}" {
		return 0, 0, nil
	}
	var payload struct {
		Version int `json:"v"`
		Epoch   int `json:"epoch"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return 0, 0, err
	}
	return payload.Version, payload.Epoch, nil
}

func editOrder(record map[string]any) string {
	str := func(field string) string { value, _ := record[field].(string); return value }
	return str("edited_at") + "\x00" + str("device_id") + "\x00" + str("operation_id")
}

func storedRecord(tx *gorm.DB, table, id string, vaultID uuid.UUID) (map[string]any, bool, error) {
	var row map[string]any
	query := tx.Table(table).Where("id = ?", id)
	if table != "vaults" {
		query = query.Where("vault_id = ?", vaultID)
	}
	result := query.Take(&row)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if result.Error != nil {
		return nil, false, result.Error
	}
	// The current typed row's JSON representation is what the client receives.
	// GORM map scans can expose UUIDs and bytes in driver-specific forms, so
	// decode through JSON before comparing the tuple.
	encoded, err := json.Marshal(row)
	if err != nil {
		return nil, false, err
	}
	var normalized map[string]any
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		return nil, false, err
	}
	return normalized, true, nil
}

func canonicalWinner(tx *gorm.DB, table, id string, vaultID uuid.UUID) (map[string]any, error) {
	var event models.SyncChange
	if err := tx.Where("vault_id = ? AND table_name = ? AND record_id = ?", vaultID, table, id).Order("seq DESC").First(&event).Error; err == nil {
		var row map[string]any
		if err := json.Unmarshal([]byte(event.Envelope), &row); err != nil {
			return nil, err
		}
		return row, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	row, found, err := storedRecord(tx, table, id, vaultID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("missing current row")
	}
	return row, nil
}

func validateRelationships(tx *gorm.DB, vaultID uuid.UUID, operation PushOperation, pending map[string]map[string]bool) error {
	if operation.Record["deleted_at"] != nil {
		return nil
	}
	refs := map[string][2]string{}
	switch operation.Table {
	case "groups":
		refs["parent_id"] = [2]string{"groups", "optional"}
	case "hosts":
		refs["group_id"] = [2]string{"groups", "optional"}
		refs["key_id"] = [2]string{"keys", "optional"}
	case "port_forwards":
		refs["host_id"] = [2]string{"hosts", "required"}
		mode, ok := operation.Record["mode"].(string)
		if !ok || (mode != "local" && mode != "remote" && mode != "dynamic") {
			return errors.New("invalid port forward mode")
		}
	}
	for field, target := range refs {
		raw := operation.Record[field]
		if raw == nil || raw == "" {
			if target[1] == "required" {
				return errors.New("missing relationship " + field)
			}
			continue
		}
		id, ok := raw.(string)
		if !ok {
			return errors.New("invalid relationship " + field)
		}
		if _, err := uuid.Parse(id); err != nil {
			return errors.New("invalid relationship " + field)
		}
		if id == operation.Record["id"] {
			return errors.New("self-referential relationship")
		}
		if pending[target[0]][id] {
			continue
		}
		var count int64
		if err := tx.Table(target[0]).Where("id = ? AND vault_id = ? AND deleted_at IS NULL", id, vaultID).Count(&count).Error; err != nil {
			return fmt.Errorf("%w: %w", errRelationshipLookup, err)
		}
		if count == 0 {
			return errors.New("relationship outside vault or missing: " + field)
		}
	}
	return nil
}

func applyOperation(tx *gorm.DB, vaultID uuid.UUID, operation PushOperation, deviceID uuid.UUID) (PushResult, error) {
	if operation.Table != "vaults" && operation.Record["deleted_at"] == nil {
		var vault models.Vault
		if err := tx.First(&vault, "id = ?", vaultID).Error; err != nil {
			return PushResult{}, err
		}
		if vault.DeletedAt != nil {
			return PushResult{}, errVaultDeleted
		}
	}
	if operation.Table == "vaults" && operation.Record["deleted_at"] != nil {
		for _, table := range []string{"port_forwards", "hosts", "groups", "keys", "snippets", "workspaces", "presets", "session_history", "session_output_chunks", "session_preferences"} {
			var count int64
			if err := tx.Table(table).Where("vault_id = ? AND deleted_at IS NULL", vaultID).Count(&count).Error; err != nil {
				return PushResult{}, err
			}
			if count != 0 {
				return PushResult{}, errVaultHasLiveRecords
			}
		}
	}
	opID, _ := uuid.Parse(operation.OperationID)
	var prior models.SyncOperation
	err := tx.Where("device_id = ? AND operation_id = ?", deviceID, opID).First(&prior).Error
	if err == nil {
		if prior.VaultID != vaultID {
			return PushResult{}, errors.New("operation ID reused for another vault")
		}
		var result PushResult
		if err := json.Unmarshal([]byte(prior.Outcome), &result); err != nil {
			return PushResult{}, err
		}
		result.Fate = "duplicate"
		return result, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return PushResult{}, err
	}

	recordID := operation.Record["id"].(string)
	existing, found, err := storedRecord(tx, operation.Table, recordID, vaultID)
	if err != nil {
		return PushResult{}, err
	}
	result := PushResult{OperationID: operation.OperationID}
	if found && ((isHistoryTable(operation.Table) && existing["deleted_at"] != nil && operation.Record["deleted_at"] == nil) || editOrder(existing) >= editOrder(operation.Record)) {
		result.Fate = "superseded"
		result.CanonicalRecord, err = canonicalWinner(tx, operation.Table, recordID, vaultID)
		if err != nil {
			return PushResult{}, err
		}
	} else {
		canonical := make(map[string]any, len(operation.Record)+1)
		maps.Copy(canonical, operation.Record)
		revision := 1
		if found {
			if old, ok := existing["revision"].(float64); ok {
				revision = int(old) + 1
			}
		}
		canonical["revision"] = revision
		if operation.Table == "vaults" {
			canonical["vault_id"] = ""
		}
		columns := make(map[string]any, len(canonical))
		for key, value := range canonical {
			if key == "vault_id" && operation.Table == "vaults" {
				continue
			}
			columns[key] = value
		}
		if found {
			query := tx.Table(operation.Table).Where("id = ?", recordID)
			if operation.Table != "vaults" {
				query = query.Where("vault_id = ?", vaultID)
			}
			if err := query.Updates(columns).Error; err != nil {
				return PushResult{}, err
			}
		} else {
			if err := tx.Table(operation.Table).Create(columns).Error; err != nil {
				return PushResult{}, err
			}
		}
		encoded, err := json.Marshal(canonical)
		if err != nil {
			return PushResult{}, err
		}
		change := models.SyncChange{VaultID: vaultID, TableName: operation.Table, RecordID: uuid.MustParse(recordID), Envelope: string(encoded)}
		if err := tx.Create(&change).Error; err != nil {
			return PushResult{}, err
		}
		result = PushResult{OperationID: operation.OperationID, Fate: "accepted", CanonicalRecord: canonical, Cursor: change.Seq}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return PushResult{}, err
	}
	ledger := models.SyncOperation{DeviceID: deviceID, OperationID: opID, VaultID: vaultID, Outcome: string(encoded)}
	if err := tx.Create(&ledger).Error; err != nil {
		return PushResult{}, err
	}
	return result, nil
}

func HandlePush(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := requestUser(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		var request PushRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid push request"})
			return
		}
		vaultID, err := uuid.Parse(request.VaultID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid vault ID"})
			return
		}
		deviceID, err := uuid.Parse(request.DeviceID)
		if err != nil || request.DeviceID != c.GetString("device_id") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "device mismatch"})
			return
		}
		if len(request.Operations) == 0 || len(request.Operations) > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "operation batch size must be 1..100"})
			return
		}
		pending := make(map[string]map[string]bool)
		for _, operation := range request.Operations {
			if pending[operation.Table] == nil {
				pending[operation.Table] = make(map[string]bool)
			}
			if id, ok := operation.Record["id"].(string); ok {
				pending[operation.Table][id] = true
			}
			if _, err := uuid.Parse(operation.OperationID); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid operation ID"})
				return
			}
			if err := validateRecord(operation.Table, operation.Record, request.VaultID, request.DeviceID, operation.OperationID); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			if operation.Table == "vaults" && operation.Record["owner_id"] != userID.String() {
				c.JSON(http.StatusForbidden, gin.H{"error": "owner mismatch"})
				return
			}
		}
		pushMu.Lock()
		defer pushMu.Unlock()
		results := make([]PushResult, 0, len(request.Operations))
		status := http.StatusInternalServerError
		err = db.Transaction(func(tx *gorm.DB) error {
			vault, exists, allowed, err := accessibleVault(tx, vaultID, userID)
			if err != nil {
				return err
			}
			if !allowed {
				if len(request.Operations) == 0 || request.Operations[0].Table != "vaults" || request.Operations[0].Record["id"] != request.VaultID {
					status = http.StatusForbidden
					return errors.New("vault not owned")
				}
				var count int64
				if err := tx.Model(&models.Vault{}).Where("id = ?", vaultID).Count(&count).Error; err != nil {
					return err
				}
				if count != 0 {
					status = http.StatusForbidden
					return errors.New("vault already exists")
				}
			}
			for _, operation := range request.Operations {
				if isHistoryTable(operation.Table) {
					if !exists || vault.TeamID != nil || vault.OwnerID != userID || vault.Kind != "personal" || !vault.IsDefault {
						status = http.StatusForbidden
						return errors.New("history requires default personal vault")
					}
				}
				version, epoch, err := payloadVersionAndEpoch(operation.Record["data"])
				if err != nil {
					status = http.StatusBadRequest
					return err
				}
				if exists && vault.TeamID != nil {
					if operation.Table == "vaults" {
						status = http.StatusForbidden
						return errors.New("team vault metadata requires team endpoint")
					}
					if vault.RotationState != "ready" {
						status = http.StatusConflict
						return errors.New("team vault rotation required")
					}
					if version != 2 || epoch != vault.KeyEpoch {
						status = http.StatusConflict
						return errors.New("team vault key epoch mismatch")
					}
				} else if version == 2 {
					status = http.StatusBadRequest
					return errors.New("team ciphertext in private vault")
				}
				if err := validateRelationships(tx, vaultID, operation, pending); err != nil {
					// A failed lookup is a server fault, not a bad record: keep it at 500.
					if !errors.Is(err, errRelationshipLookup) {
						status = http.StatusBadRequest
					}
					return err
				}
				result, err := applyOperation(tx, vaultID, operation, deviceID)
				if errors.Is(err, errVaultHasLiveRecords) || errors.Is(err, errVaultDeleted) {
					status = http.StatusConflict
				}
				if err != nil {
					return err
				}
				results = append(results, result)
			}
			return nil
		})
		if err != nil {
			// Below 500 the error is one of this handler's fixed messages; clients log it.
			message := "sync push failed"
			if status < http.StatusInternalServerError {
				message = err.Error()
			}
			c.JSON(status, gin.H{"error": message})
			return
		}
		c.JSON(http.StatusOK, gin.H{"results": results})
	}
}

func HandlePull(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := requestUser(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		var request PullRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pull request"})
			return
		}
		vaultID, err := uuid.Parse(request.VaultID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid vault ID"})
			return
		}
		pushMu.Lock()
		defer pushMu.Unlock()
		tx := db.Begin()
		if tx.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "pull transaction failed"})
			return
		}
		defer tx.Rollback()
		vault, _, allowed, err := accessibleVault(tx, vaultID, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "authorization failed"})
			return
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "vault access denied"})
			return
		}
		limit := request.Limit
		if limit <= 0 {
			limit = 100
		}
		if limit > 100 {
			limit = 100
		}
		var upper uint64
		if err := tx.Model(&models.SyncChange{}).Select("COALESCE(MAX(seq), 0)").Scan(&upper).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "cursor lookup failed"})
			return
		}
		afterCursor := request.AfterCursor
		reset := false
		if vault.TeamID != nil && vault.RotationCursor > 0 && afterCursor < vault.RotationCursor {
			afterCursor = vault.RotationCursor - 1
			reset = true
		}
		var events []models.SyncChange
		if err := tx.Where("vault_id = ? AND seq > ? AND seq <= ?", vaultID, afterCursor, upper).Order("seq ASC").Limit(limit + 1).Find(&events).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "pull failed"})
			return
		}
		hasMore := len(events) > limit
		if hasMore {
			events = events[:limit]
		}
		response := PullResponse{Reset: reset, RotationCursor: vault.RotationCursor, Changes: make([]PullChange, 0, len(events)), NextCursor: request.AfterCursor, UpperCursor: upper, HasMore: hasMore}
		for _, event := range events {
			var record map[string]any
			if err := json.Unmarshal([]byte(event.Envelope), &record); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "corrupt change event"})
				return
			}
			response.Changes = append(response.Changes, PullChange{Cursor: event.Seq, Table: event.TableName, Record: record})
			response.NextCursor = event.Seq
		}
		if !hasMore {
			response.NextCursor = upper
		}
		if err := tx.Commit().Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "pull transaction failed"})
			return
		}
		c.JSON(http.StatusOK, response)
	}
}
