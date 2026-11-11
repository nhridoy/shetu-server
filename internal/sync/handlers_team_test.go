package sync

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
)

func teamCiphertext(table string, vaultID uuid.UUID, epoch int) string {
	payload, _ := json.Marshal(map[string]any{
		"v": 2, "alg": "xchacha20poly1305", "nonce": base64.RawStdEncoding.EncodeToString(make([]byte, 24)),
		"ct": base64.RawStdEncoding.EncodeToString(make([]byte, 32)), "vault_id": vaultID.String(), "epoch": epoch, "record_type": table,
	})
	return string(payload)
}

func TestTeamSyncActiveMemberOnly(t *testing.T) {
	db, router, cfg, owner, member, vaultID := syncTestServer(t)
	teamID := uuid.New()
	if err := db.Create(&models.Team{ID: teamID, OwnerID: owner, Name: "Ops"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&models.Vault{}).Where("id = ?", vaultID).Updates(map[string]any{"team_id": teamID, "key_epoch": 1, "kind": "team"}).Error; err != nil {
		t.Fatal(err)
	}
	grant := models.TeamMember{ID: uuid.New(), TeamID: teamID, UserID: member, Role: "member", State: "pending"}
	if err := db.Create(&grant).Error; err != nil {
		t.Fatal(err)
	}
	deviceID, operationID, hostID := uuid.New(), uuid.New(), uuid.New()
	record := map[string]any{
		"id": hostID.String(), "vault_id": vaultID.String(), "revision": 1,
		"created_at": "2026-09-27T10:20:30.000Z", "updated_at": "2026-09-27T10:20:30.000Z",
		"edited_at": "2026-09-27T10:20:30.000Z", "device_id": deviceID.String(),
		"operation_id": operationID.String(), "name": "Office", "sort_order": 0,
		"data": teamCiphertext("hosts", vaultID, 1),
	}
	push := map[string]any{"vault_id": vaultID.String(), "device_id": deviceID.String(), "operations": []any{map[string]any{"operation_id": operationID.String(), "table": "hosts", "record": record}}}
	pull := map[string]any{"vault_id": vaultID.String(), "after_cursor": 0, "limit": 10}
	if got := syncRequest(t, router, cfg, member, deviceID, "/api/v1/sync/pull", pull); got.Code != http.StatusForbidden {
		t.Fatalf("pending pull: %d", got.Code)
	}
	if err := db.Model(&grant).Update("state", "active").Error; err != nil {
		t.Fatal(err)
	}
	if got := syncRequest(t, router, cfg, member, deviceID, "/api/v1/sync/push", push); got.Code != http.StatusOK {
		t.Fatalf("member push: %d %s", got.Code, got.Body.String())
	}
	if got := syncRequest(t, router, cfg, member, deviceID, "/api/v1/sync/pull", pull); got.Code != http.StatusOK {
		t.Fatalf("member pull: %d %s", got.Code, got.Body.String())
	}
	staleRecord := make(map[string]any, len(record))
	maps.Copy(staleRecord, record)
	staleRecord["data"] = teamCiphertext("hosts", vaultID, 2)
	staleID := uuid.New()
	staleRecord["operation_id"] = staleID.String()
	stalePush := map[string]any{"vault_id": vaultID.String(), "device_id": deviceID.String(), "operations": []any{map[string]any{"operation_id": staleID.String(), "table": "hosts", "record": staleRecord}}}
	if got := syncRequest(t, router, cfg, member, deviceID, "/api/v1/sync/push", stalePush); got.Code != http.StatusConflict {
		t.Fatalf("stale epoch push: %d", got.Code)
	}
	legacyID := uuid.New()
	legacy := models.Vault{ID: legacyID, OwnerID: owner, Kind: "team", Name: "Legacy private", Data: "{}"}
	if err := db.Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	if got := syncRequest(t, router, cfg, member, deviceID, "/api/v1/sync/pull", map[string]any{"vault_id": legacyID.String(), "after_cursor": 0}); got.Code != http.StatusForbidden {
		t.Fatalf("legacy team label leaked: %d", got.Code)
	}
	if err := db.Model(&grant).Update("state", "removed").Error; err != nil {
		t.Fatal(err)
	}
	if got := syncRequest(t, router, cfg, member, deviceID, "/api/v1/sync/pull", pull); got.Code != http.StatusForbidden {
		t.Fatalf("removed pull: %d", got.Code)
	}
	if got := syncRequest(t, router, cfg, member, deviceID, "/api/v1/sync/push", push); got.Code != http.StatusForbidden {
		t.Fatalf("removed push: %d", got.Code)
	}
}
