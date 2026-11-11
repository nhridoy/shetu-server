package sync

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
)

func TestVaultDeleteRequiresDescendantTombstonesAndRemainsPullable(t *testing.T) {
	db, router, cfg, owner, _, vaultID := syncTestServer(t)
	hostID := uuid.New()
	if err := db.Create(&models.Host{ID: hostID, VaultID: vaultID, Name: "Host", AuthType: "password", Tags: "[]", Data: encryptedData("hosts")}).Error; err != nil {
		t.Fatal(err)
	}
	device := uuid.New()
	push := func(table string, id uuid.UUID, deleted bool) int {
		t.Helper()
		op := uuid.New()
		record := map[string]any{
			"id": id.String(), "vault_id": vaultID.String(), "revision": 1,
			"created_at": "2026-09-27T10:20:30.000Z", "updated_at": "2026-09-27T10:20:31.000Z",
			"edited_at": "2026-09-27T10:20:31.000Z", "device_id": device.String(),
			"operation_id": op.String(), "name": "Name", "sort_order": 0,
			"data": encryptedData(table),
		}
		if table == "vaults" {
			record["vault_id"] = ""
			record["owner_id"] = owner.String()
			record["kind"] = "personal"
			record["is_default"] = false
		}
		if deleted {
			record["deleted_at"] = "2026-09-27T10:20:31.000Z"
		}
		body := map[string]any{"vault_id": vaultID.String(), "device_id": device.String(), "operations": []any{map[string]any{"operation_id": op.String(), "table": table, "record": record}}}
		return syncRequest(t, router, cfg, owner, device, "/api/v1/sync/push", body).Code
	}
	if status := push("vaults", vaultID, true); status != http.StatusConflict {
		t.Fatalf("delete before children: %d", status)
	}
	if status := push("hosts", hostID, true); status != http.StatusOK {
		t.Fatalf("host tombstone: %d", status)
	}
	if status := push("vaults", vaultID, true); status != http.StatusOK {
		t.Fatalf("vault tombstone: %d", status)
	}
	otherDevice := uuid.New()
	pull := syncRequest(t, router, cfg, owner, otherDevice, "/api/v1/sync/pull", map[string]any{"vault_id": vaultID.String(), "after_cursor": 0, "limit": 10})
	if pull.Code != http.StatusOK {
		t.Fatalf("pull deleted vault: %d %s", pull.Code, pull.Body.String())
	}
}
