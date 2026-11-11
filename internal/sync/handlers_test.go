package sync

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	gormsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/auth"
	"github.com/nhridoy/shetu-server/internal/config"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

func syncTestServer(t *testing.T) (*gorm.DB, *gin.Engine, *config.Config, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	owner, other, vaultID := uuid.New(), uuid.New(), uuid.New()
	for _, userID := range []uuid.UUID{owner, other} {
		if err := db.Create(&models.User{ID: userID, Email: userID.String() + "@example.test"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Create(&models.Vault{ID: vaultID, OwnerID: owner, Kind: "personal", Name: "Personal", IsDefault: true, Data: "{}"}).Error; err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: "sync-test-secret", JWTExpiry: time.Hour}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	protected := router.Group("/api/v1")
	protected.Use(auth.JWTMiddleware(cfg))
	protected.POST("/sync/push", HandlePush(db))
	protected.POST("/sync/pull", HandlePull(db))
	return db, router, cfg, owner, other, vaultID
}

func syncRequest(t *testing.T, router *gin.Engine, cfg *config.Config, userID, deviceID uuid.UUID, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	if userID != uuid.Nil {
		token, err := auth.GenerateAccessToken(userID, deviceID.String(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestPushPullIdempotencyAndAuthorization(t *testing.T) {
	db, router, cfg, owner, other, vaultID := syncTestServer(t)
	deviceID, operationID, hostID := uuid.New(), uuid.New(), uuid.New()
	record := map[string]any{
		"id": hostID.String(), "vault_id": vaultID.String(), "revision": 1,
		"created_at": "2026-09-27T10:20:30.000Z", "updated_at": "2026-09-27T10:20:30.000Z",
		"edited_at": "2026-09-27T10:20:30.000Z", "device_id": deviceID.String(),
		"operation_id": operationID.String(), "name": "Office", "sort_order": 0,
		"data": encryptedData("hosts"),
	}
	push := map[string]any{"vault_id": vaultID.String(), "device_id": deviceID.String(), "operations": []any{map[string]any{"operation_id": operationID.String(), "table": "hosts", "record": record}}}
	foreign := syncRequest(t, router, cfg, other, deviceID, "/api/v1/sync/push", push)
	if foreign.Code != http.StatusForbidden {
		t.Fatalf("foreign push: %d %s", foreign.Code, foreign.Body.String())
	}
	unauthenticated := syncRequest(t, router, cfg, uuid.Nil, deviceID, "/api/v1/sync/push", push)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated push: %d", unauthenticated.Code)
	}
	accepted := syncRequest(t, router, cfg, owner, deviceID, "/api/v1/sync/push", push)
	if accepted.Code != http.StatusOK {
		t.Fatalf("push: %d %s", accepted.Code, accepted.Body.String())
	}
	retry := syncRequest(t, router, cfg, owner, deviceID, "/api/v1/sync/push", push)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", retry.Code, retry.Body.String())
	}
	var changes int64
	if err := db.Model(&models.SyncChange{}).Count(&changes).Error; err != nil {
		t.Fatal(err)
	}
	if changes != 1 {
		t.Fatalf("retry appended %d changes", changes)
	}
	pull := map[string]any{"vault_id": vaultID.String(), "after_cursor": 0, "limit": 1}
	foreignPull := syncRequest(t, router, cfg, other, deviceID, "/api/v1/sync/pull", pull)
	if foreignPull.Code != http.StatusForbidden {
		t.Fatalf("foreign pull: %d", foreignPull.Code)
	}
	response := syncRequest(t, router, cfg, owner, deviceID, "/api/v1/sync/pull", pull)
	if response.Code != http.StatusOK {
		t.Fatalf("pull: %d %s", response.Code, response.Body.String())
	}
	var result struct {
		Changes []struct {
			Cursor uint64         `json:"cursor"`
			Table  string         `json:"table"`
			Record map[string]any `json:"record"`
		} `json:"changes"`
		NextCursor uint64 `json:"next_cursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 1 || result.Changes[0].Table != "hosts" || result.NextCursor == 0 {
		t.Fatalf("bad pull: %s", response.Body.String())
	}
}
