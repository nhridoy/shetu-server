package sync

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/nhridoy/terra-server/internal/models"
)

func TestPushConflictAndPagination(t *testing.T) {
	db, router, cfg, owner, _, vaultID := syncTestServer(t)
	device := uuid.New()
	makeRecord := func(id, op uuid.UUID, editedAt, name string) map[string]any {
		return map[string]any{
			"id": id.String(), "vault_id": vaultID.String(), "revision": 1,
			"created_at": "2026-09-27T10:20:30.000Z", "updated_at": editedAt,
			"edited_at": editedAt, "device_id": device.String(), "operation_id": op.String(),
			"name": name, "sort_order": 0, "data": encryptedData("hosts"),
		}
	}
	push := func(id, op uuid.UUID, editedAt, name string) PushResult {
		t.Helper()
		body := map[string]any{"vault_id": vaultID.String(), "device_id": device.String(), "operations": []any{map[string]any{"operation_id": op.String(), "table": "hosts", "record": makeRecord(id, op, editedAt, name)}}}
		response := syncRequest(t, router, cfg, owner, device, "/api/v1/sync/push", body)
		if response.Code != http.StatusOK {
			t.Fatalf("push %s: %d %s", name, response.Code, response.Body.String())
		}
		var decoded struct {
			Results []PushResult `json:"results"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded.Results[0]
	}
	firstID, secondID := uuid.New(), uuid.New()
	first := push(firstID, uuid.New(), "2026-09-27T10:20:30.000Z", "first")
	second := push(secondID, uuid.New(), "2026-09-27T10:20:31.000Z", "second")
	newer := push(firstID, uuid.New(), "2026-09-27T10:20:32.000Z", "newer")
	stale := push(firstID, uuid.New(), "2026-09-27T10:20:29.000Z", "stale")
	if first.Fate != "accepted" || second.Fate != "accepted" || newer.Fate != "accepted" || stale.Fate != "superseded" {
		t.Fatalf("unexpected fates: %s, %s, %s, %s", first.Fate, second.Fate, newer.Fate, stale.Fate)
	}
	if stale.CanonicalRecord["name"] != "newer" {
		t.Fatalf("stale winner: %#v", stale.CanonicalRecord)
	}
	var changes int64
	if err := db.Model(&models.SyncChange{}).Count(&changes).Error; err != nil {
		t.Fatal(err)
	}
	if changes != 3 {
		t.Fatalf("stale edit added event: %d", changes)
	}
	cursor := uint64(0)
	seen := 0
	for range 3 {
		response := syncRequest(t, router, cfg, owner, device, "/api/v1/sync/pull", map[string]any{"vault_id": vaultID.String(), "after_cursor": cursor, "limit": 1})
		if response.Code != http.StatusOK {
			t.Fatalf("pull: %d %s", response.Code, response.Body.String())
		}
		var decoded PullResponse
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Changes) != 1 || decoded.NextCursor <= cursor {
			t.Fatalf("bad page: %s", response.Body.String())
		}
		cursor = decoded.NextCursor
		seen++
	}
	if seen != 3 {
		t.Fatalf("saw %d events", seen)
	}
}
