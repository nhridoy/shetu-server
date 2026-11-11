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

func TestTeamSyncCreatesIdempotentlyAndScopesSnapshot(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	actor, other := uuid.New(), uuid.New()
	if err := db.Create(&models.User{ID: actor, Email: "actor@example.com", FullName: "Actor"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.User{ID: other, Email: "other@example.com", FullName: "Other"}).Error; err != nil {
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
	teamID, operationID := uuid.New(), uuid.New()
	body, _ := json.Marshal(map[string]any{"operations": []any{map[string]any{
		"operation_id": operationID, "type": "team.create", "payload": map[string]any{"team_id": teamID, "name": "Offline Team"},
	}}})
	request := func(user uuid.UUID) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/sync", bytes.NewReader(body))
		req.Header.Set("X-Test-User", user.String())
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		return resp
	}
	first, retry := request(actor), request(actor)
	if first.Code != http.StatusOK || retry.Code != http.StatusOK {
		t.Fatalf("sync status: first=%d %s retry=%d %s", first.Code, first.Body, retry.Code, retry.Body)
	}
	var count int64
	if err := db.Model(&models.Team{}).Where("id = ?", teamID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("idempotent team count=%d err=%v", count, err)
	}
	if request(other).Code != http.StatusOK {
		t.Fatalf("other account snapshot failed")
	}
	var otherCount int64
	if err := db.Model(&models.TeamMember{}).Where("team_id = ? AND user_id = ?", teamID, other).Count(&otherCount).Error; err != nil || otherCount != 0 {
		t.Fatalf("foreign user gained membership: count=%d err=%v", otherCount, err)
	}
}

func TestTeamSyncRejectsOversizedOperationBatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("user_id", uuid.New()); c.Next() })
	RegisterRoutes(router.Group("/api/v1"), db)
	operations := make([]any, 51)
	for i := range operations {
		operations[i] = map[string]any{"operation_id": uuid.New(), "type": "team.create", "payload": map[string]any{}}
	}
	body, _ := json.Marshal(map[string]any{"operations": operations})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/sync", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected bounded batch rejection, got %d: %s", rec.Code, rec.Body.String())
	}
}
