package teams

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	gormsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

func TestTeamVaultRequiresGrantForEveryActiveMember(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	owner, member, teamID, vaultID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	public := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	fingerprint, err := FingerprintPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{owner, member} {
		user := models.User{ID: id, Email: id.String() + "@example.com", FullName: "Person", PublicKey: &public}
		if err := db.Create(&user).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Create(&models.Team{ID: teamID, OwnerID: owner, Name: "Ops"}).Error; err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		id   uuid.UUID
		role string
	}{{owner, "owner"}, {member, "member"}} {
		if err := db.Create(&models.TeamMember{ID: uuid.New(), TeamID: teamID, UserID: entry.id, Role: entry.role, State: "active"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		id, err := uuid.Parse(c.GetHeader("X-Test-User"))
		if err == nil {
			c.Set("user_id", id)
		}
		c.Next()
	})
	RegisterRoutes(router.Group("/api/v1"), db)
	request := func(method, path string, user uuid.UUID, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("X-Test-User", user.String())
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	membersPath := "/api/v1/teams/" + teamID.String() + "/members"
	if rec := request(http.MethodGet, membersPath, uuid.New(), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign members: %d", rec.Code)
	}
	members := request(http.MethodGet, membersPath, owner, nil)
	if members.Code != http.StatusOK {
		t.Fatalf("member list: %d %s", members.Code, members.Body.String())
	}
	var membersReply struct {
		Data []struct {
			UserID      uuid.UUID `json:"user_id"`
			PublicKey   string    `json:"public_key"`
			Fingerprint string    `json:"fingerprint"`
		} `json:"data"`
	}
	if err := json.Unmarshal(members.Body.Bytes(), &membersReply); err != nil {
		t.Fatal(err)
	}
	if len(membersReply.Data) != 2 || membersReply.Data[0].PublicKey == "" || membersReply.Data[0].Fingerprint != fingerprint {
		t.Fatalf("bad member keys: %s", members.Body.String())
	}
	envelope := func(user uuid.UUID) models.VaultKeyEnvelope {
		return models.VaultKeyEnvelope{VaultID: vaultID, TeamID: teamID, Epoch: 1, RecipientUserID: user, RecipientFingerprint: fingerprint, Version: 1, EphemeralPublicKey: public, Nonce: "nonce", Ciphertext: "ciphertext"}
	}
	post := func(envelopes []models.VaultKeyEnvelope) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"id": vaultID, "name": "Shared", "envelopes": envelopes})
		return request(http.MethodPost, "/api/v1/teams/"+teamID.String()+"/vaults", owner, body)
	}
	if rec := post([]models.VaultKeyEnvelope{envelope(owner)}); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing grant: %d %s", rec.Code, rec.Body.String())
	}
	var count int64
	db.Model(&models.Vault{}).Where("id = ?", vaultID).Count(&count)
	if count != 0 {
		t.Fatal("partial vault created")
	}
	if rec := post([]models.VaultKeyEnvelope{envelope(owner), envelope(member)}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	db.Model(&models.VaultKeyEnvelope{}).Where("vault_id = ?", vaultID).Count(&count)
	if count != 2 {
		t.Fatalf("grants=%d", count)
	}
	path := "/api/v1/vaults/" + vaultID.String() + "/key-envelope"
	if rec := request(http.MethodGet, path, member, nil); rec.Code != http.StatusOK {
		t.Fatalf("member envelope: %d %s", rec.Code, rec.Body.String())
	}
	if rec := request(http.MethodGet, path, uuid.New(), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign envelope: %d", rec.Code)
	}
	renamePath := "/api/v1/teams/" + teamID.String() + "/vaults/" + vaultID.String()
	if rec := request(http.MethodPatch, renamePath, member, []byte(`{"name":"Renamed"}`)); rec.Code != http.StatusForbidden {
		t.Fatalf("member renamed vault: %d", rec.Code)
	}
	if rec := request(http.MethodPatch, renamePath, owner, []byte(`{"name":"  Renamed  "}`)); rec.Code != http.StatusOK {
		t.Fatalf("owner rename: %d %s", rec.Code, rec.Body.String())
	}
	var renamed models.Vault
	if err := db.First(&renamed, "id = ?", vaultID).Error; err != nil || renamed.Name != "Renamed" || renamed.Revision != 2 {
		t.Fatalf("renamed vault=%+v error=%v", renamed, err)
	}
	var change models.SyncChange
	if err := db.Where("vault_id = ? AND table_name = ?", vaultID, "vaults").Last(&change).Error; err != nil || !strings.Contains(change.Envelope, `"name":"Renamed"`) {
		t.Fatalf("rename sync event=%s error=%v", change.Envelope, err)
	}
	memberPath := "/api/v1/teams/" + teamID.String() + "/members/" + member.String()
	if rec := request(http.MethodPatch, memberPath, member, []byte(`{"role":"admin"}`)); rec.Code != http.StatusForbidden {
		t.Fatalf("member promoted self: %d", rec.Code)
	}
	if rec := request(http.MethodPatch, memberPath, owner, []byte(`{"role":"admin"}`)); rec.Code != http.StatusOK {
		t.Fatalf("owner role update: %d %s", rec.Code, rec.Body.String())
	}
	if rec := request(http.MethodDelete, memberPath, owner, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("owner removal: %d %s", rec.Code, rec.Body.String())
	}
	if rec := request(http.MethodGet, path, member, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("removed key access: %d", rec.Code)
	}
	var after models.Vault
	if err := db.First(&after, "id = ?", vaultID).Error; err != nil {
		t.Fatal(err)
	}
	if after.RotationState != "rotation_required" {
		t.Fatalf("removal did not require rotation: %q", after.RotationState)
	}
	deletePath := "/api/v1/teams/" + teamID.String() + "/vaults/" + vaultID.String()
	if rec := request(http.MethodDelete, deletePath, member, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("removed user deleted vault: %d", rec.Code)
	}
	if rec := request(http.MethodDelete, deletePath, owner, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("owner deleted vault: %d %s", rec.Code, rec.Body.String())
	}
}
