package teams

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	gormsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	teamsync "github.com/nhridoy/shetu-server/internal/sync"
	"gorm.io/gorm"
)

func TestRotationStagesAndPublishesAtomically(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	owner, remaining, removed, invited, teamID, vaultID, hostID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	public := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	fingerprint, _ := FingerprintPublicKey(public)
	for _, id := range []uuid.UUID{owner, remaining, removed, invited} {
		if err := db.Create(&models.User{ID: id, Email: id.String() + "@example.com", FullName: "Member", PublicKey: &public}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Create(&models.Team{ID: teamID, OwnerID: owner, Name: "Ops"}).Error; err != nil {
		t.Fatal(err)
	}
	for _, member := range []struct {
		id          uuid.UUID
		role, state string
	}{{owner, "owner", "active"}, {remaining, "member", "active"}, {removed, "member", "removed"}} {
		if err := db.Create(&models.TeamMember{ID: uuid.New(), TeamID: teamID, UserID: member.id, Role: member.role, State: member.state}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Create(&models.Vault{ID: vaultID, TeamID: &teamID, OwnerID: owner, Name: "Shared", Kind: "team", KeyEpoch: 1, RotationState: "rotation_required", Revision: 1, Data: "{}"}).Error; err != nil {
		t.Fatal(err)
	}
	pendingInvite := models.TeamInvite{ID: uuid.New(), TeamID: teamID, RecipientUserID: invited, RecipientEmail: invited.String() + "@example.com", RecipientFingerprint: fingerprint, Role: "member", State: "pending", InviterUserID: owner}
	if err := db.Create(&pendingInvite).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.VaultKeyEnvelope{ID: uuid.New(), VaultID: vaultID, TeamID: teamID, Epoch: 1, RecipientUserID: invited, RecipientFingerprint: fingerprint, Version: 1, EphemeralPublicKey: public, Nonce: "old", Ciphertext: "old"}).Error; err != nil {
		t.Fatal(err)
	}
	oldData := `{"v":2,"alg":"xchacha20poly1305","nonce":"old","ct":"old","vault_id":"` + vaultID.String() + `","record_type":"hosts","epoch":1}`
	if err := db.Create(&models.Host{ID: hostID, VaultID: vaultID, Name: "Box", Revision: 1, Data: oldData}).Error; err != nil {
		t.Fatal(err)
	}
	oldRecord, _ := json.Marshal(map[string]any{"id": hostID, "vault_id": vaultID, "revision": 1, "name": "Box", "data": oldData})
	if err := db.Create(&models.SyncChange{VaultID: vaultID, TableName: "hosts", RecordID: hostID, Envelope: string(oldRecord)}).Error; err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if id, err := uuid.Parse(c.GetHeader("X-Test-User")); err == nil {
			c.Set("user_id", id)
		}
		c.Next()
	})
	RegisterRoutes(router.Group("/api/v1"), db)
	router.POST("/api/v1/sync/pull", teamsync.HandlePull(db))
	call := func(method, path string, actor uuid.UUID, payload any) *httptest.ResponseRecorder {
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("X-Test-User", actor.String())
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	base := "/api/v1/vaults/" + vaultID.String() + "/rotation"
	if rec := call(http.MethodGet, base+"/snapshot", removed, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("removed snapshot: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodGet, base+"/snapshot", owner, nil); rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(hostID.String())) {
		t.Fatalf("rotation snapshot: %d %s", rec.Code, rec.Body.String())
	}
	nonce := base64.RawStdEncoding.EncodeToString(make([]byte, 24))
	ct := base64.RawStdEncoding.EncodeToString(make([]byte, 48))
	newDataBytes, _ := json.Marshal(map[string]any{"v": 2, "alg": "xchacha20poly1305", "nonce": nonce, "ct": ct, "vault_id": vaultID.String(), "record_type": "hosts", "epoch": 2})
	envelope := models.VaultKeyEnvelope{VaultID: vaultID, TeamID: teamID, Epoch: 2, RecipientUserID: owner, RecipientFingerprint: fingerprint, Version: 1, EphemeralPublicKey: public, Nonce: nonce, Ciphertext: ct}
	memberEnvelope := envelope
	memberEnvelope.RecipientUserID = remaining
	opID := uuid.New()
	stage := map[string]any{"operation_id": opID, "expected_epoch": 1, "expected_revision": 1, "rows": []any{map[string]any{"table": "hosts", "id": hostID, "revision": 1, "data": string(newDataBytes)}}, "envelopes": []any{envelope, memberEnvelope}}
	partial := map[string]any{"operation_id": opID, "expected_epoch": 1, "expected_revision": 1, "rows": []any{}, "envelopes": []any{envelope, memberEnvelope}}
	if rec := call(http.MethodPost, base+"/stage", owner, partial); rec.Code != http.StatusOK {
		t.Fatalf("partial stage: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, base+"/commit", owner, map[string]any{"operation_id": opID}); rec.Code != http.StatusConflict {
		t.Fatalf("incomplete stage committed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, base+"/stage", removed, stage); rec.Code != http.StatusForbidden {
		t.Fatalf("removed stage: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, base+"/stage", owner, stage); rec.Code != http.StatusOK {
		t.Fatalf("stage: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, base+"/stage", owner, stage); rec.Code != http.StatusOK {
		t.Fatalf("stage retry: %d %s", rec.Code, rec.Body.String())
	}
	var before models.Host
	db.First(&before, "id = ?", hostID)
	if before.Data != oldData {
		t.Fatal("staging published ciphertext")
	}
	if err := db.Model(&models.Host{}).Where("id = ?", hostID).Update("revision", 2).Error; err != nil {
		t.Fatal(err)
	}
	if rec := call(http.MethodPost, base+"/commit", owner, map[string]any{"operation_id": opID}); rec.Code != http.StatusConflict {
		t.Fatalf("stale rotation committed: %d %s", rec.Code, rec.Body.String())
	}
	var premature models.Vault
	db.First(&premature, "id = ?", vaultID)
	if premature.KeyEpoch != 1 || premature.RotationCursor != 0 {
		t.Fatal("failed commit published partial rotation")
	}
	if err := db.Model(&models.Host{}).Where("id = ?", hostID).Update("revision", 1).Error; err != nil {
		t.Fatal(err)
	}
	if rec := call(http.MethodPost, base+"/commit", owner, map[string]any{"operation_id": opID}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body.String())
	}
	var after models.Vault
	db.First(&after, "id = ?", vaultID)
	if after.KeyEpoch != 2 || after.RotationState != "ready" {
		t.Fatalf("epoch/state=%d/%s", after.KeyEpoch, after.RotationState)
	}
	if err := db.First(&pendingInvite, "id = ?", pendingInvite.ID).Error; err != nil || pendingInvite.State != "cancelled" {
		t.Fatalf("pending invite state=%q error=%v", pendingInvite.State, err)
	}
	var staleGrantCount int64
	if err := db.Model(&models.VaultKeyEnvelope{}).Where("vault_id = ? AND recipient_user_id = ?", vaultID, invited).Count(&staleGrantCount).Error; err != nil || staleGrantCount != 0 {
		t.Fatalf("stale grant count=%d error=%v", staleGrantCount, err)
	}
	keyURL := "/api/v1/vaults/" + vaultID.String() + "/key-envelope"
	if rec := call(http.MethodGet, keyURL, remaining, nil); rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(remaining.String())) {
		t.Fatalf("remaining member key: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodGet, keyURL, removed, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("removed member retained key access: %d %s", rec.Code, rec.Body.String())
	}
	db.First(&before, "id = ?", hostID)
	if before.Data != string(newDataBytes) {
		t.Fatal("rotation did not publish row")
	}
	if rec := call(http.MethodPost, base+"/commit", owner, map[string]any{"operation_id": opID}); rec.Code != http.StatusOK {
		t.Fatalf("commit retry: %d %s", rec.Code, rec.Body.String())
	}
	pull := call(http.MethodPost, "/api/v1/sync/pull", owner, map[string]any{"vault_id": vaultID, "after_cursor": 0, "limit": 100})
	var pulled struct {
		Reset          bool   `json:"reset"`
		RotationCursor uint64 `json:"rotation_cursor"`
		Changes        []struct {
			Record map[string]any `json:"record"`
		} `json:"changes"`
	}
	if err := json.Unmarshal(pull.Body.Bytes(), &pulled); err != nil {
		t.Fatal(err)
	}
	if pull.Code != http.StatusOK || !pulled.Reset || pulled.RotationCursor == 0 || len(pulled.Changes) != 2 || pulled.Changes[1].Record["data"] != string(newDataBytes) {
		t.Fatalf("rotation snapshot missing: %d %s", pull.Code, pull.Body.String())
	}
	for _, change := range pulled.Changes {
		if change.Record["data"] == oldData {
			t.Fatalf("old-epoch change escaped cutover: %s", pull.Body.String())
		}
	}
}
