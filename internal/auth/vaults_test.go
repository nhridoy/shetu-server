package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
)

func TestDefaultVaultIsScopedAndReused(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	owner := uuid.New()
	other := uuid.New()
	if err := models.SeedPersonalVault(db, other); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	protected := router.Group("/api/v1")
	protected.Use(JWTMiddleware(cfg))
	protected.GET("/vaults/default", HandleDefaultVault(db))

	request := func(user uuid.UUID) (int, map[string]any) {
		t.Helper()
		token, err := GenerateAccessToken(user, "", cfg)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/vaults/default", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return response.Code, body
	}

	status, first := request(owner)
	if status != http.StatusOK {
		t.Fatalf("first request: status %d, body %v", status, first)
	}
	firstVault := first["data"].(map[string]any)
	if firstVault["name"] != "Personal" || firstVault["owner_id"] != owner.String() || firstVault["is_default"] != true {
		t.Fatalf("wrong default vault: %v", firstVault)
	}

	status, second := request(owner)
	if status != http.StatusOK || second["data"].(map[string]any)["id"] != firstVault["id"] {
		t.Fatalf("default vault changed: status %d, body %v", status, second)
	}
	var count int64
	if err := db.Model(&models.Vault{}).Where("owner_id = ? AND deleted_at IS NULL", owner).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected one vault for owner, got %d", count)
	}

	unauthenticated := httptest.NewRecorder()
	router.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/v1/vaults/default", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("missing token returned %d", unauthenticated.Code)
	}
}
