package teams

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	gormsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

func TestExistingAccountInviteIsRecipientBound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	owner, recipient, stranger := uuid.New(), uuid.New(), uuid.New()
	key := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	for _, user := range []models.User{
		{ID: owner, Email: "owner@example.com", FullName: "Owner", PublicKey: &key},
		{ID: recipient, Email: "member@example.com", FullName: "Member", PublicKey: &key},
	} {
		if err := db.Create(&user).Error; err != nil {
			t.Fatal(err)
		}
	}
	team := models.Team{ID: uuid.New(), OwnerID: owner, Name: "Ops"}
	if err := db.Create(&team).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: owner, Role: "owner", State: "active"}).Error; err != nil {
		t.Fatal(err)
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
	lookupPath := "/api/v1/teams/" + team.ID.String() + "/recipient-key?email=member%40example.com"
	if rec := request(http.MethodGet, lookupPath, stranger, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("stranger key lookup: %d", rec.Code)
	}
	lookup := request(http.MethodGet, lookupPath, owner, nil)
	if lookup.Code != http.StatusOK {
		t.Fatalf("recipient key lookup: %d %s", lookup.Code, lookup.Body.String())
	}
	fingerprint, err := FingerprintPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"email": " MEMBER@example.com ", "role": "member", "recipient_fingerprint": fingerprint, "envelopes": []any{}})
	path := "/api/v1/teams/" + team.ID.String() + "/invites"
	if rec := request(http.MethodPost, path, stranger, payload); rec.Code != http.StatusForbidden {
		t.Fatalf("stranger invite: %d %s", rec.Code, rec.Body.String())
	}
	blocked := models.Vault{ID: uuid.New(), OwnerID: owner, TeamID: &team.ID, KeyEpoch: 1,
		RotationState: "rotation_required", Kind: "team", Name: "Shared", Data: "{}"}
	if err := db.Create(&blocked).Error; err != nil {
		t.Fatal(err)
	}
	if rec := request(http.MethodPost, path, owner, payload); rec.Code != http.StatusConflict {
		t.Fatalf("invite during rotation: %d %s", rec.Code, rec.Body.String())
	}
	if err := db.Delete(&blocked).Error; err != nil {
		t.Fatal(err)
	}
	oldInvite := models.TeamInvite{ID: uuid.New(), TeamID: team.ID, RecipientUserID: recipient,
		RecipientEmail: "member@example.com", RecipientFingerprint: fingerprint, Role: "member",
		State: "pending", InviterUserID: owner, ExpiresAt: "2000-01-01T00:00:00.000Z"}
	if err := db.Create(&oldInvite).Error; err != nil {
		t.Fatal(err)
	}
	created := request(http.MethodPost, path, owner, payload)
	if created.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", created.Code, created.Body.String())
	}
	if err := db.First(&oldInvite, "id = ?", oldInvite.ID).Error; err != nil || oldInvite.State != "expired" {
		t.Fatalf("old invite state=%q error=%v", oldInvite.State, err)
	}
	var reply struct {
		Data models.TeamInvite `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Data.RecipientUserID != recipient || reply.Data.State != "pending" {
		t.Fatalf("bad invite: %+v", reply.Data)
	}
	declinePath := "/api/v1/teams/invites/" + reply.Data.ID.String() + "/decline"
	if rec := request(http.MethodPost, declinePath, stranger, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("stranger decline: %d", rec.Code)
	}
	if rec := request(http.MethodPost, declinePath, recipient, nil); rec.Code != http.StatusOK {
		t.Fatalf("decline: %d %s", rec.Code, rec.Body.String())
	}
	recreated := request(http.MethodPost, path, owner, payload)
	if recreated.Code != http.StatusCreated {
		t.Fatalf("reinvite: %d %s", recreated.Code, recreated.Body.String())
	}
	if err := json.Unmarshal(recreated.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	acceptPath := "/api/v1/teams/invites/" + reply.Data.ID.String() + "/accept"
	if rec := request(http.MethodPost, acceptPath, stranger, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("stranger accepted: %d", rec.Code)
	}
	blocked.ID = uuid.New()
	if err := db.Create(&blocked).Error; err != nil {
		t.Fatal(err)
	}
	if rec := request(http.MethodPost, acceptPath, recipient, nil); rec.Code != http.StatusConflict {
		t.Fatalf("accept during rotation: %d %s", rec.Code, rec.Body.String())
	}
	if err := db.Delete(&blocked).Error; err != nil {
		t.Fatal(err)
	}
	changedKey := "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
	if err := db.Model(&models.User{}).Where("id = ?", recipient).Update("public_key", changedKey).Error; err != nil {
		t.Fatal(err)
	}
	if rec := request(http.MethodPost, acceptPath, recipient, nil); rec.Code != http.StatusConflict {
		t.Fatalf("changed identity key accepted: %d %s", rec.Code, rec.Body.String())
	}
	if err := db.Model(&models.User{}).Where("id = ?", recipient).Update("public_key", key).Error; err != nil {
		t.Fatal(err)
	}
	if rec := request(http.MethodPost, acceptPath, recipient, nil); rec.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	if role, err := RoleFor(db, team.ID, recipient); err != nil || role != "member" {
		t.Fatalf("role=%q error=%v", role, err)
	}
	if rec := request(http.MethodPost, acceptPath, recipient, nil); rec.Code != http.StatusConflict {
		t.Fatalf("replay: %d", rec.Code)
	}
	expired := models.TeamInvite{ID: uuid.New(), TeamID: team.ID, RecipientUserID: recipient,
		RecipientEmail: "member@example.com", RecipientFingerprint: fingerprint, Role: "member",
		State: "pending", InviterUserID: owner, ExpiresAt: "2000-01-01T00:00:00.000Z"}
	if err := db.Create(&expired).Error; err != nil {
		t.Fatal(err)
	}
	if rec := request(http.MethodGet, "/api/v1/teams/invites/mine", recipient, nil); rec.Code != http.StatusOK || bytes.Contains(rec.Body.Bytes(), []byte(expired.ID.String())) {
		t.Fatalf("expired invitation listed: %d %s", rec.Code, rec.Body.String())
	}
	if err := db.First(&expired, "id = ?", expired.ID).Error; err != nil || expired.State != "expired" {
		t.Fatalf("expired invitation state=%q error=%v", expired.State, err)
	}
}
