package sync

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nhridoy/terra-server/internal/models"
)

func TestPushCannotOverwriteAnotherVaultRecord(t *testing.T) {
	db, router, cfg, owner, other, vaultID := syncTestServer(t)
	otherVault := uuid.New()
	if err := db.Create(&models.Vault{ID: otherVault, OwnerID: other, Kind: "personal", Name: "Other", Data: "{}"}).Error; err != nil {
		t.Fatal(err)
	}
	victimID := uuid.New()
	if err := db.Create(&models.Host{ID: victimID, VaultID: otherVault, Name: "Victim", AuthType: "password", Tags: "[]", Data: encryptedData("hosts")}).Error; err != nil {
		t.Fatal(err)
	}
	device, op := uuid.New(), uuid.New()
	record := map[string]any{"id": victimID.String(), "vault_id": vaultID.String(), "revision": 1,
		"created_at": "2026-09-27T10:20:30.000Z", "updated_at": "2026-09-27T10:20:30.000Z", "edited_at": "2026-09-27T10:20:30.000Z",
		"device_id": device.String(), "operation_id": op.String(), "name": "Hijacked", "sort_order": 0, "data": encryptedData("hosts")}
	body := map[string]any{"vault_id": vaultID.String(), "device_id": device.String(), "operations": []any{map[string]any{"operation_id": op.String(), "table": "hosts", "record": record}}}
	response := syncRequest(t, router, cfg, owner, device, "/api/v1/sync/push", body)
	if response.Code == http.StatusOK {
		t.Fatalf("cross-vault overwrite accepted: %s", response.Body.String())
	}
	var victim models.Host
	if err := db.First(&victim, "id = ?", victimID).Error; err != nil {
		t.Fatal(err)
	}
	if victim.VaultID != otherVault || victim.Name != "Victim" {
		t.Fatalf("victim changed: %#v", victim)
	}
}

func TestPushRejectsForeignRelationship(t *testing.T) {
	db, router, cfg, owner, other, vaultID := syncTestServer(t)
	otherVault, groupID := uuid.New(), uuid.New()
	if err := db.Create(&models.Vault{ID: otherVault, OwnerID: other, Kind: "personal", Name: "Other", Data: "{}"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.Group{ID: groupID, VaultID: otherVault, Name: "Foreign", Data: encryptedData("groups")}).Error; err != nil {
		t.Fatal(err)
	}
	device, op := uuid.New(), uuid.New()
	record := map[string]any{"id": uuid.New().String(), "vault_id": vaultID.String(), "revision": 1,
		"created_at": "2026-09-27T10:20:30.000Z", "updated_at": "2026-09-27T10:20:30.000Z", "edited_at": "2026-09-27T10:20:30.000Z",
		"device_id": device.String(), "operation_id": op.String(), "name": "Host", "group_id": groupID.String(), "sort_order": 0, "data": encryptedData("hosts")}
	body := map[string]any{"vault_id": vaultID.String(), "device_id": device.String(), "operations": []any{map[string]any{"operation_id": op.String(), "table": "hosts", "record": record}}}
	response := syncRequest(t, router, cfg, owner, device, "/api/v1/sync/push", body)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("foreign relationship status %d: %s", response.Code, response.Body.String())
	}
	// The client logs this reason; a generic message hides which record is stuck.
	if !strings.Contains(response.Body.String(), "relationship outside vault or missing: group_id") {
		t.Fatalf("foreign relationship reason: %s", response.Body.String())
	}
}
