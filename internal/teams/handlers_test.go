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

func TestTeamCreateAndListIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	owner, other := uuid.New(), uuid.New()
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
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}
	created := request(http.MethodPost, "/api/v1/teams", owner, []byte(`{"name":"Operations"}`))
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var response struct {
		Data models.Team `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.OwnerID != owner || response.Data.ID == uuid.Nil {
		t.Fatalf("wrong team: %+v", response.Data)
	}
	var member models.TeamMember
	if err := db.Where("team_id = ? AND user_id = ?", response.Data.ID, owner).First(&member).Error; err != nil || member.Role != "owner" || member.State != "active" {
		t.Fatalf("owner membership missing: %+v %v", member, err)
	}
	mine := request(http.MethodGet, "/api/v1/teams", owner, nil)
	otherList := request(http.MethodGet, "/api/v1/teams", other, nil)
	if mine.Code != http.StatusOK || otherList.Code != http.StatusOK {
		t.Fatalf("list status: %d/%d", mine.Code, otherList.Code)
	}
	var mineBody, otherBody struct {
		Data []models.Team `json:"data"`
	}
	if err := json.Unmarshal(mine.Body.Bytes(), &mineBody); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(otherList.Body.Bytes(), &otherBody); err != nil {
		t.Fatal(err)
	}
	if len(mineBody.Data) != 1 || len(otherBody.Data) != 0 {
		t.Fatalf("team visibility: mine=%d other=%d", len(mineBody.Data), len(otherBody.Data))
	}
	teamPath := "/api/v1/teams/" + response.Data.ID.String()
	if rec := request(http.MethodPatch, teamPath, other, []byte(`{"name":"Stolen"}`)); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign rename: %d", rec.Code)
	}
	if rec := request(http.MethodPatch, teamPath, owner, []byte(`{"name":"New Ops"}`)); rec.Code != http.StatusOK {
		t.Fatalf("owner rename: %d %s", rec.Code, rec.Body.String())
	}
	if rec := request(http.MethodDelete, teamPath, other, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign delete: %d", rec.Code)
	}
	if rec := request(http.MethodDelete, teamPath, owner, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("owner delete: %d %s", rec.Code, rec.Body.String())
	}
}
