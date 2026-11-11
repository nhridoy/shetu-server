package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
)

type Claims struct {
	jwt.RegisteredClaims
	DeviceID string `json:"device_id"`
}

func GenerateAccessToken(userID uuid.UUID, deviceID string, cfg *config.Config) (string, error) {
	now := time.Now()
	accessClaims := Claims{
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(cfg.JWTExpiry)),
		ID:        uuid.New().String(),
		DeviceID:  deviceID,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString([]byte(cfg.JWTSecret))
}

func VerifyAccessToken(tokenString string, cfg *config.Config) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		return []byte(cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrTokenInvalidClaims
}
