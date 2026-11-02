package sync

import (
	"encoding/json"
	"maps"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestEverySavedRecordTypePushesAndPulls(t *testing.T) {
	_, router, cfg, owner, _, vaultID := syncTestServer(t)
	device := uuid.New()
	hostID := uuid.New()
	types := []struct {
		table string
		id    uuid.UUID
		extra map[string]any
	}{
		{"vaults", vaultID, map[string]any{"owner_id": owner.String(), "kind": "personal", "is_default": true}},
		{"groups", uuid.New(), nil},
		{"keys", uuid.New(), map[string]any{"key_type": "ed25519", "public_key": "ssh-ed25519 AAAA"}},
		{"snippets", uuid.New(), nil},
		{"workspaces", uuid.New(), nil},
		{"presets", uuid.New(), nil},
		{"hosts", hostID, map[string]any{"auth_type": "password", "tags": "[]"}},
		{"port_forwards", uuid.New(), map[string]any{"host_id": hostID.String(), "mode": "local"}},
	}
	for _, item := range types {
		op := uuid.New()
		record := map[string]any{
			"id": item.id.String(), "vault_id": vaultID.String(), "revision": 1,
			"created_at": "2099-01-01T00:00:00.000Z", "updated_at": "2099-01-01T00:00:00.000Z",
			"edited_at": "2099-01-01T00:00:00.000Z", "device_id": device.String(),
			"operation_id": op.String(), "name": "Item", "sort_order": 0, "data": encryptedData(item.table),
		}
		if item.table == "vaults" {
			record["vault_id"] = ""
		}
		maps.Copy(record, item.extra)
		body := map[string]any{"vault_id": vaultID.String(), "device_id": device.String(), "operations": []any{map[string]any{"operation_id": op.String(), "table": item.table, "record": record}}}
		response := syncRequest(t, router, cfg, owner, device, "/api/v1/sync/push", body)
		if response.Code != http.StatusOK {
			t.Fatalf("push %s: %d %s", item.table, response.Code, response.Body.String())
		}
	}
	pull := syncRequest(t, router, cfg, owner, device, "/api/v1/sync/pull", map[string]any{"vault_id": vaultID.String(), "after_cursor": 0, "limit": 100})
	if pull.Code != http.StatusOK {
		t.Fatalf("pull: %d %s", pull.Code, pull.Body.String())
	}
	var decoded PullResponse
	if err := json.Unmarshal(pull.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Changes) != len(types) {
		t.Fatalf("want %d types, got %d: %s", len(types), len(decoded.Changes), pull.Body.String())
	}
}
