package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
)

func TestGenerateAccessToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:          "test-secret",
		JWTExpiry:          15 * time.Minute,
		RefreshTokenExpiry: 30 * 24 * time.Hour,
	}
	userID := uuid.New()
	deviceID := "device-123"
	accessToken, err := GenerateAccessToken(userID, deviceID, cfg)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}
	if accessToken == "" {
		t.Fatal("access token is empty")
	}
}

func TestVerifyAccessToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:          "test-secret",
		JWTExpiry:          15 * time.Minute,
		RefreshTokenExpiry: 30 * 24 * time.Hour,
	}
	userID := uuid.New()
	deviceID := "device-123"
	accessToken, err := GenerateAccessToken(userID, deviceID, cfg)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}
	claims, err := VerifyAccessToken(accessToken, cfg)
	if err != nil {
		t.Fatalf("VerifyAccessToken failed: %v", err)
	}
	if claims.Subject != userID.String() {
		t.Fatalf("expected subject %s, got %s", userID.String(), claims.Subject)
	}
	if claims.DeviceID != deviceID {
		t.Fatalf("expected device_id %s, got %s", deviceID, claims.DeviceID)
	}
}

func TestVerifyAccessTokenExpired(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:          "test-secret",
		JWTExpiry:          -1 * time.Hour, // already expired
		RefreshTokenExpiry: 30 * 24 * time.Hour,
	}
	userID := uuid.New()
	deviceID := "device-123"
	accessToken, err := GenerateAccessToken(userID, deviceID, cfg)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}
	_, err = VerifyAccessToken(accessToken, cfg)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}
