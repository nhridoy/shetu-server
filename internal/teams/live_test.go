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
	"github.com/nhridoy/shetu-server/internal/live"
	"github.com/nhridoy/shetu-server/internal/live/livetest"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

type teamFixture struct {
	db       *gorm.DB
	router   *gin.Engine
	owner    uuid.UUID
	member   uuid.UUID
	outsider uuid.UUID
	team     uuid.UUID
}

func newTeamFixture(t *testing.T) teamFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	f := teamFixture{db: db, owner: uuid.New(), member: uuid.New(), outsider: uuid.New(), team: uuid.New()}
	for _, u := range []uuid.UUID{f.owner, f.member, f.outsider} {
		db.Create(&models.User{ID: u, Email: u.String() + "@example.com", FullName: "U"})
	}
	db.Create(&models.Team{ID: f.team, OwnerID: f.owner, Name: "Ops"})
	db.Create(&models.TeamMember{ID: uuid.New(), TeamID: f.team, UserID: f.owner, Role: "owner", State: "active"})
	db.Create(&models.TeamMember{ID: uuid.New(), TeamID: f.team, UserID: f.member, Role: "member", State: "active"})
	f.router = gin.New()
	f.router.Use(func(c *gin.Context) {
		if id, err := uuid.Parse(c.GetHeader("X-Test-User")); err == nil {
			c.Set("user_id", id)
		}
		c.Next()
	})
	RegisterRoutes(f.router.Group("/api/v1"), db)
	return f
}

func (f teamFixture) do(method, path string, user uuid.UUID, body any) *httptest.ResponseRecorder {
	encoded, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func TestLive_TeamRenameNotifiesMembers(t *testing.T) {
	f := newTeamFixture(t)
	hub := livetest.UseHub(t)
	member := livetest.Listen(t, hub, f.member, "m")
	outsider := livetest.Listen(t, hub, f.outsider, "o")
	if w := f.do(http.MethodPatch, "/api/v1/teams/"+f.team.String(), f.owner, map[string]any{"name": "Platform"}); w.Code >= 300 {
		t.Fatalf("rename: %d %s", w.Code, w.Body.String())
	}
	if k, _ := livetest.Received(member); len(k) != 1 || k[0] != live.KindChanged {
		t.Fatalf("member: %v", k)
	}
	if k, _ := livetest.Received(outsider); len(k) != 0 {
		t.Fatalf("outsider notified: %v", k)
	}
}

func TestLive_TeamDeleteNotifiesFormerMembers(t *testing.T) {
	f := newTeamFixture(t)
	hub := livetest.UseHub(t)
	member := livetest.Listen(t, hub, f.member, "m")
	if w := f.do(http.MethodDelete, "/api/v1/teams/"+f.team.String(), f.owner, nil); w.Code >= 300 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if k, _ := livetest.Received(member); len(k) != 1 {
		t.Fatalf("member of the deleted team: %v", k)
	}
}

func TestLive_TeamSyncNotifiesOnlyWhenAccepted(t *testing.T) {
	f := newTeamFixture(t)
	hub := livetest.UseHub(t)
	member := livetest.Listen(t, hub, f.member, "m")
	// A read-only team sync (every app's poll) must never signal, or syncs would trigger each other.
	if w := f.do(http.MethodPost, "/api/v1/teams/sync", f.owner, map[string]any{"operations": []any{}}); w.Code != http.StatusOK {
		t.Fatalf("read sync: %d %s", w.Code, w.Body.String())
	}
	if k, _ := livetest.Received(member); len(k) != 0 {
		t.Fatalf("read-only team sync signalled: %v", k)
	}
	op := map[string]any{"operation_id": uuid.New(), "type": "team.create", "payload": map[string]any{"team_id": uuid.New(), "name": "New"}}
	if w := f.do(http.MethodPost, "/api/v1/teams/sync", f.owner, map[string]any{"operations": []any{op}}); w.Code != http.StatusOK {
		t.Fatalf("write sync: %d %s", w.Code, w.Body.String())
	}
	if k, _ := livetest.Received(member); len(k) != 1 {
		t.Fatalf("accepted team write: %v", k)
	}
}
