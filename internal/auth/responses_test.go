package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSuccessResponse(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	Success(c, http.StatusOK, gin.H{"id": "123"})
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	// verify envelope structure
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if _, ok := resp["data"]; !ok {
		t.Fatal("response missing data field")
	}
	if _, ok := resp["meta"]; !ok {
		t.Fatal("response missing meta field")
	}
	// Check meta has request_id
	meta, ok := resp["meta"].(map[string]any)
	if !ok {
		t.Fatal("meta is not an object")
	}
	if _, ok := meta["request_id"]; !ok {
		t.Fatal("meta missing request_id")
	}
}

func TestErrorResponse(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	Error(c, http.StatusBadRequest, "INVALID_INPUT", "invalid email")
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if _, ok := resp["error"]; !ok {
		t.Fatal("response missing error field")
	}
	errorObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatal("error is not an object")
	}
	if errorObj["code"] != "INVALID_INPUT" {
		t.Fatalf("expected code INVALID_INPUT, got %v", errorObj["code"])
	}
	if errorObj["message"] != "invalid email" {
		t.Fatalf("expected message 'invalid email', got %v", errorObj["message"])
	}
	// Check error has request_id
	if _, ok := errorObj["request_id"]; !ok {
		t.Fatal("error missing request_id")
	}
}

func TestSuccessResponseWithRequestID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("request_id", "req-123")
	Success(c, http.StatusOK, gin.H{"id": "123"})
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	meta := resp["meta"].(map[string]any)
	if meta["request_id"] != "req-123" {
		t.Fatalf("expected request_id 'req-123', got %v", meta["request_id"])
	}
}
