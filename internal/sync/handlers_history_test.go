package sync

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
)

func historyRecord(table string, vaultID, deviceID, operationID uuid.UUID) map[string]any {
	names := map[string]string{"session_history": "Session", "session_output_chunks": "Output chunk", "session_preferences": "Session preferences"}
	return map[string]any{
		"id": uuid.New().String(), "vault_id": vaultID.String(), "revision": 1,
		"created_at": "2026-10-02T00:00:00.000Z", "updated_at": "2026-10-02T00:00:00.000Z",
		"edited_at": "2026-10-02T00:00:00.000Z", "device_id": deviceID.String(),
		"operation_id": operationID.String(), "name": names[table], "sort_order": 0,
		"data": encryptedData(table),
	}
}

func TestPersonalHistorySyncRoundTripAndTeamDenial(t *testing.T) {
	db, router, cfg, owner, other, vaultID := syncTestServer(t)
	deviceID := uuid.New()
	for _, table := range []string{"session_history", "session_output_chunks", "session_preferences"} {
		operationID := uuid.New()
		record := historyRecord(table, vaultID, deviceID, operationID)
		push := map[string]any{"vault_id": vaultID.String(), "device_id": deviceID.String(), "operations": []any{map[string]any{"operation_id": operationID.String(), "table": table, "record": record}}}
		if got := syncRequest(t, router, cfg, other, deviceID, "/api/v1/sync/push", push); got.Code != http.StatusForbidden {
			t.Fatalf("%s cross-account push: %d", table, got.Code)
		}
		if got := syncRequest(t, router, cfg, owner, deviceID, "/api/v1/sync/push", push); got.Code != http.StatusOK {
			t.Fatalf("%s push: %d %s", table, got.Code, got.Body.String())
		}
		if got := syncRequest(t, router, cfg, owner, deviceID, "/api/v1/sync/push", push); got.Code != http.StatusOK {
			t.Fatalf("%s retry: %d %s", table, got.Code, got.Body.String())
		}
	}
	pull := syncRequest(t, router, cfg, owner, deviceID, "/api/v1/sync/pull", map[string]any{"vault_id": vaultID.String(), "after_cursor": 0, "limit": 10})
	if pull.Code != http.StatusOK {
		t.Fatalf("pull: %d %s", pull.Code, pull.Body.String())
	}
	var response PullResponse
	if err := json.Unmarshal(pull.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Changes) != 3 {
		t.Fatalf("expected three history changes, got %d", len(response.Changes))
	}
	teamID := uuid.New()
	if err := db.Create(&models.Team{ID: teamID, OwnerID: owner, Name: "Ops"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&models.Vault{}).Where("id = ?", vaultID).Updates(map[string]any{"team_id": teamID, "key_epoch": 1, "kind": "team"}).Error; err != nil {
		t.Fatal(err)
	}
	operationID := uuid.New()
	push := map[string]any{"vault_id": vaultID.String(), "device_id": deviceID.String(), "operations": []any{map[string]any{"operation_id": operationID.String(), "table": "session_history", "record": historyRecord("session_history", vaultID, deviceID, operationID)}}}
	if got := syncRequest(t, router, cfg, owner, deviceID, "/api/v1/sync/push", push); got.Code != http.StatusForbidden {
		t.Fatalf("team-vault history push: %d %s", got.Code, got.Body.String())
	}
}

func TestHistoryRejectsPlaintextHostLabel(t *testing.T) {
	_, router, cfg, owner, _, vaultID := syncTestServer(t)
	deviceID, operationID := uuid.New(), uuid.New()
	record := historyRecord("session_history", vaultID, deviceID, operationID)
	record["name"] = "prod-db.internal"
	push := map[string]any{"vault_id": vaultID.String(), "device_id": deviceID.String(), "operations": []any{map[string]any{"operation_id": operationID.String(), "table": "session_history", "record": record}}}
	if got := syncRequest(t, router, cfg, owner, deviceID, "/api/v1/sync/push", push); got.Code != http.StatusBadRequest {
		t.Fatalf("plaintext host label accepted: %d %s", got.Code, got.Body.String())
	}
}

func TestHistoryTombstoneWinsOverLateLiveUpdate(t *testing.T) {
	_, router, cfg, owner, _, vaultID := syncTestServer(t)
	deviceID := uuid.New()
	push := func(record map[string]any) *httptest.ResponseRecorder {
		return syncRequest(t, router, cfg, owner, deviceID, "/api/v1/sync/push", map[string]any{"vault_id": vaultID.String(), "device_id": deviceID.String(), "operations": []any{map[string]any{"operation_id": record["operation_id"], "table": "session_history", "record": record}}})
	}
	live := historyRecord("session_history", vaultID, deviceID, uuid.New())
	if got := push(live); got.Code != http.StatusOK {
		t.Fatalf("live: %d %s", got.Code, got.Body.String())
	}
	deleted := historyRecord("session_history", vaultID, deviceID, uuid.New())
	deleted["id"] = live["id"]
	deleted["edited_at"] = "2026-10-02T00:00:01.000Z"
	deleted["updated_at"] = deleted["edited_at"]
	deleted["deleted_at"] = deleted["edited_at"]
	if got := push(deleted); got.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", got.Code, got.Body.String())
	}
	late := historyRecord("session_history", vaultID, deviceID, uuid.New())
	late["id"] = live["id"]
	late["edited_at"] = "2026-10-02T00:00:02.000Z"
	late["updated_at"] = late["edited_at"]
	if got := push(late); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"fate":"superseded"`) {
		t.Fatalf("late update resurrected deleted history: %d %s", got.Code, got.Body.String())
	}
}
