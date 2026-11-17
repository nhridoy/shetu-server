package sync

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/live"
	"github.com/nhridoy/shetu-server/internal/live/livetest"
	"github.com/nhridoy/shetu-server/internal/models"
)

func hostPush(vaultID, deviceID uuid.UUID) map[string]any {
	opID, hostID := uuid.New(), uuid.New()
	record := map[string]any{
		"id": hostID.String(), "vault_id": vaultID.String(), "revision": 1,
		"created_at": "2026-09-27T10:20:30.000Z", "updated_at": "2026-09-27T10:20:30.000Z",
		"edited_at": "2026-09-27T10:20:30.000Z", "device_id": deviceID.String(),
		"operation_id": opID.String(), "name": "Office", "sort_order": 0,
		"data": encryptedData("hosts"),
	}
	return map[string]any{"vault_id": vaultID.String(), "device_id": deviceID.String(), "operations": []any{map[string]any{"operation_id": opID.String(), "table": "hosts", "record": record}}}
}

func TestLive_PushNotifiesOtherDevicesNotPusher(t *testing.T) {
	_, router, cfg, owner, other, vaultID := syncTestServer(t)
	hub := livetest.UseHub(t)
	pusher, laptop := uuid.New(), uuid.New()
	self := livetest.Listen(t, hub, owner, pusher.String())
	mine := livetest.Listen(t, hub, owner, laptop.String())
	theirs := livetest.Listen(t, hub, other, uuid.NewString())
	if w := syncRequest(t, router, cfg, owner, pusher, "/api/v1/sync/push", hostPush(vaultID, pusher)); w.Code != http.StatusOK {
		t.Fatalf("push: %d %s", w.Code, w.Body.String())
	}
	if k, _ := livetest.Received(mine); len(k) != 1 || k[0] != live.KindChanged {
		t.Fatalf("owner's other device: %v", k)
	}
	if k, _ := livetest.Received(self); len(k) != 0 {
		t.Fatalf("pushing device notified: %v", k)
	}
	if k, _ := livetest.Received(theirs); len(k) != 0 {
		t.Fatalf("another user notified: %v", k)
	}
}

func TestLive_NoSignalOnFailedWrite(t *testing.T) {
	_, router, cfg, owner, other, vaultID := syncTestServer(t)
	hub := livetest.UseHub(t)
	mine := livetest.Listen(t, hub, owner, uuid.NewString())
	dev := uuid.New()
	if w := syncRequest(t, router, cfg, other, dev, "/api/v1/sync/push", hostPush(vaultID, dev)); w.Code != http.StatusForbidden {
		t.Fatalf("foreign push: %d", w.Code)
	}
	if k, _ := livetest.Received(mine); len(k) != 0 {
		t.Fatalf("refused push notified: %v", k)
	}
}

func TestLive_TeamVaultAudienceIsActiveMembers(t *testing.T) {
	db, _, _, owner, other, _ := syncTestServer(t)
	teamID, vaultID, left := uuid.New(), uuid.New(), uuid.New()
	db.Create(&models.User{ID: left, Email: left.String() + "@example.test"})
	db.Create(&models.Team{ID: teamID, OwnerID: owner, Name: "Ops"})
	db.Create(&models.TeamMember{ID: uuid.New(), TeamID: teamID, UserID: owner, Role: "owner", State: "active"})
	db.Create(&models.TeamMember{ID: uuid.New(), TeamID: teamID, UserID: other, Role: "member", State: "active"})
	db.Create(&models.TeamMember{ID: uuid.New(), TeamID: teamID, UserID: left, Role: "member", State: "removed"})
	db.Create(&models.Vault{ID: vaultID, OwnerID: owner, TeamID: &teamID, Kind: "team", Name: "Shared", RotationState: "ready"})
	got := map[uuid.UUID]bool{}
	for _, u := range vaultAudience(db, vaultID) {
		got[u] = true
	}
	if len(got) != 2 || !got[owner] || !got[other] {
		t.Fatalf("team vault audience: %v", got)
	}
}
