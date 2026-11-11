package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

const emailVerifyPurpose = "email_verify"
const otpTTL = 15 * time.Minute
const maxOtpAttempts = 5

func generateOtp() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func issueEmailVerifyCode(db *gorm.DB, userID uuid.UUID) (string, error) {
	if err := db.Where("user_id = ? AND purpose = ?", userID, emailVerifyPurpose).
		Delete(&models.AuthCode{}).Error; err != nil {
		return "", fmt.Errorf("clear old verification codes: %w", err)
	}

	otp, err := generateOtp()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(otp))
	code := models.AuthCode{
		CodeHash:  base64.RawStdEncoding.EncodeToString(hash[:]),
		Purpose:   emailVerifyPurpose,
		UserID:    userID,
		DeviceID:  "",
		ExpiresAt: time.Now().Add(otpTTL),
	}
	if err := db.Create(&code).Error; err != nil {
		return "", fmt.Errorf("store verification code: %w", err)
	}
	return otp, nil
}

func findEmailVerifyCode(db *gorm.DB, userID uuid.UUID) (*models.AuthCode, error) {
	var code models.AuthCode
	err := db.Where("user_id = ? AND purpose = ?", userID, emailVerifyPurpose).
		Order("created_at DESC").First(&code).Error
	if err != nil {
		return nil, err
	}
	return &code, nil
}
