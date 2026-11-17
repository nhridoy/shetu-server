package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
	"github.com/nhridoy/shetu-server/internal/email"
	"github.com/nhridoy/shetu-server/internal/models"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

const twoFactorSetupPurpose = "two_factor_setup"

var errTwoFactorUnavailable = errors.New("two-factor unavailable")

// deliverOtp sends an email code; tests replace it to read the code.
var deliverOtp = func(cfg *config.Config, to, code string) error {
	return email.New(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, cfg.LogOtpFallback).SendOtp(to, code)
}

// notifyTwoFactor sends a best-effort notice in the background; it never delays the response.
var notifyTwoFactor = func(cfg *config.Config, to, event string) {
	sender := email.New(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, cfg.LogOtpFallback)
	if !sender.Enabled() {
		return
	}
	go func() {
		// The error is not logged: SMTP errors often echo the recipient address.
		if sender.SendTwoFactorNotice(to, event) != nil {
			slog.Warn("two-factor notice not sent", "event", event)
		}
	}()
}

// twoFactorRow returns the user's two-factor row, enabled or in setup; nil when none.
func twoFactorRow(db *gorm.DB, userID uuid.UUID) (*models.TwoFactor, error) {
	var tf models.TwoFactor
	err := db.First(&tf, "user_id = ?", userID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &tf, nil
}

func writeCodeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errCodeReused):
		Error(c, http.StatusUnauthorized, "TWO_FACTOR_CODE_REUSED", "This code was just used. Wait for the next code.")
	case errors.Is(err, errCodeInvalid):
		Error(c, http.StatusUnauthorized, "TWO_FACTOR_INVALID", "That code isn't right.")
	case errors.Is(err, errTwoFactorUnavailable):
		Error(c, http.StatusServiceUnavailable, "TWO_FACTOR_UNAVAILABLE", "Two-factor isn't available on this server.")
	default:
		Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check the code")
	}
}

// verifySecondFactor accepts a current authenticator code or an unused backup code for an
// enabled account. Each code is consumed with a conditional update, so two requests racing
// with the same code can't both pass.
func verifySecondFactor(db *gorm.DB, cfg *config.Config, tf *models.TwoFactor, code string) (bool, error) {
	norm := normalizeCode(code)
	if len(norm) == 6 && isDigits(norm) {
		if cfg.TwoFactorKey == nil {
			return false, errTwoFactorUnavailable
		}
		secret, err := openSecret(cfg.TwoFactorKey, tf.Secret)
		if err != nil {
			return false, errTwoFactorUnavailable
		}
		step, err := matchTOTP(secret, norm, nowFunc(), tf.LastStep)
		if err != nil {
			return false, err
		}
		res := db.Model(&models.TwoFactor{}).Where("user_id = ? AND last_step < ?", tf.UserID, step).Update("last_step", step)
		if res.Error != nil {
			return false, res.Error
		}
		if res.RowsAffected == 0 {
			return false, errCodeReused
		}
		tf.LastStep = step
		return false, nil
	}
	res := db.Model(&models.TwoFactorBackupCode{}).
		Where("user_id = ? AND code_hash = ? AND used_at IS NULL", tf.UserID, hashCode(norm)).
		Update("used_at", nowFunc())
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected == 0 {
		return false, errCodeInvalid
	}
	var user models.User
	if db.Select("email").First(&user, "id = ?", tf.UserID).Error == nil {
		notifyTwoFactor(cfg, user.Email, "backup_used")
	}
	return true, nil
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// consumeEmailCode checks a 6-digit email code for purpose: 15 minutes, 5 attempts, single use.
func consumeEmailCode(db *gorm.DB, userID uuid.UUID, purpose, code string) error {
	var row models.AuthCode
	err := db.Where("user_id = ? AND purpose = ? AND used_at IS NULL", userID, purpose).Order("created_at DESC").First(&row).Error
	if err != nil || row.ExpiresAt.Before(time.Now()) || row.Attempts >= maxOtpAttempts {
		return errCodeInvalid
	}
	sum := sha256.Sum256([]byte(normalizeCode(code)))
	if !ConstantTimeCompare([]byte(base64.RawStdEncoding.EncodeToString(sum[:])), []byte(row.CodeHash)) {
		db.Model(&models.AuthCode{}).Where("id = ?", row.ID).Update("attempts", gorm.Expr("attempts + 1"))
		return errCodeInvalid
	}
	res := db.Where("id = ?", row.ID).Delete(&models.AuthCode{})
	if res.Error != nil || res.RowsAffected == 0 {
		return errCodeInvalid
	}
	return nil
}

func replaceBackupCodes(tx *gorm.DB, userID uuid.UUID) ([]string, error) {
	plain, hashes, err := newBackupCodes()
	if err != nil {
		return nil, err
	}
	if err := tx.Where("user_id = ?", userID).Delete(&models.TwoFactorBackupCode{}).Error; err != nil {
		return nil, err
	}
	rows := make([]models.TwoFactorBackupCode, len(hashes))
	for i, h := range hashes {
		rows[i] = models.TwoFactorBackupCode{UserID: userID, CodeHash: h}
	}
	if err := tx.Create(&rows).Error; err != nil {
		return nil, err
	}
	return plain, nil
}

func currentUser(c *gin.Context, db *gorm.DB) (*models.User, bool) {
	var user models.User
	if err := db.First(&user, "id = ?", c.MustGet("user_id").(uuid.UUID)).Error; err != nil {
		Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load user")
		return nil, false
	}
	return &user, true
}

// enabledTwoFactor loads the caller's enabled two-factor row, answering 400 when it is off.
func enabledTwoFactor(c *gin.Context, db *gorm.DB, userID uuid.UUID) (*models.TwoFactor, bool) {
	tf, err := twoFactorRow(db, userID)
	if err != nil {
		Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load two-factor")
		return nil, false
	}
	if tf == nil || tf.EnabledAt == nil {
		Error(c, http.StatusBadRequest, "TWO_FACTOR_OFF", "Two-factor is off.")
		return nil, false
	}
	return tf, true
}

func HandleTwoFactorStatus(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, ok := currentUser(c, db)
		if !ok {
			return
		}
		tf, err := twoFactorRow(db, user.ID)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load two-factor")
			return
		}
		var left int64
		enabled := tf != nil && tf.EnabledAt != nil
		if enabled {
			db.Model(&models.TwoFactorBackupCode{}).Where("user_id = ? AND used_at IS NULL", user.ID).Count(&left)
		}
		Success(c, http.StatusOK, gin.H{
			"enabled":           enabled,
			"available":         cfg.TwoFactorKey != nil,
			"backup_codes_left": left,
			"email_verified":    user.EmailVerifiedAt != nil,
		})
	}
}

// HandleTwoFactorSetup starts setup: a new secret waits as pending until confirmed, and an
// unverified address gets an email code (the email fallback must reach a working inbox).
func HandleTwoFactorSetup(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.TwoFactorKey == nil {
			writeCodeError(c, errTwoFactorUnavailable)
			return
		}
		user, ok := currentUser(c, db)
		if !ok {
			return
		}
		tf, err := twoFactorRow(db, user.ID)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load two-factor")
			return
		}
		if tf != nil && tf.EnabledAt != nil {
			Error(c, http.StatusConflict, "TWO_FACTOR_ENABLED", "Two-factor is already on.")
			return
		}
		key, err := totp.Generate(totp.GenerateOpts{Issuer: "Shetu", AccountName: user.Email})
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create a secret")
			return
		}
		sealed, err := sealSecret(cfg.TwoFactorKey, key.Secret())
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to store the secret")
			return
		}
		row := models.TwoFactor{UserID: user.ID, PendingSecret: sealed}
		if err := db.Save(&row).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to store the secret")
			return
		}
		emailCodeSent := false
		if user.EmailVerifiedAt == nil {
			code, err := issueEmailCode(db, user.ID, twoFactorSetupPurpose)
			if err == nil {
				err = deliverOtp(cfg, user.Email, code)
			}
			if err != nil {
				Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "couldn't send the email code")
				return
			}
			emailCodeSent = true
		}
		Success(c, http.StatusOK, gin.H{"otpauth_url": key.URL(), "secret": key.Secret(), "email_code_sent": emailCodeSent})
	}
}

func HandleTwoFactorConfirm(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Code      string `json:"code" binding:"required"`
			EmailCode string `json:"email_code"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "code is required")
			return
		}
		if cfg.TwoFactorKey == nil {
			writeCodeError(c, errTwoFactorUnavailable)
			return
		}
		user, ok := currentUser(c, db)
		if !ok {
			return
		}
		tf, err := twoFactorRow(db, user.ID)
		if err != nil || tf == nil || tf.EnabledAt != nil || tf.PendingSecret == "" {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Start turning on two-factor again.")
			return
		}
		needEmail := user.EmailVerifiedAt == nil
		if needEmail && req.EmailCode == "" {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Enter the code from your email.")
			return
		}
		secret, err := openSecret(cfg.TwoFactorKey, tf.PendingSecret)
		if err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Start turning on two-factor again.")
			return
		}
		step, err := matchTOTP(secret, req.Code, nowFunc(), 0)
		if err != nil {
			writeCodeError(c, err)
			return
		}
		if needEmail {
			if err := consumeEmailCode(db, user.ID, twoFactorSetupPurpose, req.EmailCode); err != nil {
				writeCodeError(c, err)
				return
			}
		}
		var codes []string
		err = db.Transaction(func(tx *gorm.DB) error {
			now := nowFunc()
			res := tx.Model(&models.TwoFactor{}).Where("user_id = ? AND enabled_at IS NULL AND pending_secret = ?", user.ID, tf.PendingSecret).
				Updates(map[string]any{"secret": tf.PendingSecret, "pending_secret": "", "enabled_at": now, "last_step": step})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				return errCodeInvalid
			}
			if needEmail {
				if err := tx.Model(&models.User{}).Where("id = ?", user.ID).Update("email_verified_at", now).Error; err != nil {
					return err
				}
			}
			var err error
			codes, err = replaceBackupCodes(tx, user.ID)
			return err
		})
		if errors.Is(err, errCodeInvalid) {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Start turning on two-factor again.")
			return
		}
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to turn on two-factor")
			return
		}
		notifyTwoFactor(cfg, user.Email, "enabled")
		Success(c, http.StatusOK, gin.H{"backup_codes": codes})
	}
}

type codeRequest struct {
	Code string `json:"code" binding:"required"`
}

func HandleTwoFactorDisable(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req codeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "code is required")
			return
		}
		user, ok := currentUser(c, db)
		if !ok {
			return
		}
		tf, ok := enabledTwoFactor(c, db, user.ID)
		if !ok {
			return
		}
		if _, err := verifySecondFactor(db, cfg, tf, req.Code); err != nil {
			writeCodeError(c, err)
			return
		}
		if err := removeTwoFactor(db, user.ID); err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to turn off two-factor")
			return
		}
		notifyTwoFactor(cfg, user.Email, "disabled")
		c.Status(http.StatusNoContent)
	}
}

// removeTwoFactor deletes the user's secret, backup codes and open challenges.
func removeTwoFactor(db *gorm.DB, userID uuid.UUID) error {
	return db.Transaction(func(tx *gorm.DB) error {
		for _, m := range []any{&models.TwoFactor{}, &models.TwoFactorBackupCode{}, &models.TwoFactorChallenge{}} {
			if err := tx.Where("user_id = ?", userID).Delete(m).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func HandleTwoFactorBackupCodes(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req codeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "code is required")
			return
		}
		user, ok := currentUser(c, db)
		if !ok {
			return
		}
		tf, ok := enabledTwoFactor(c, db, user.ID)
		if !ok {
			return
		}
		if _, err := verifySecondFactor(db, cfg, tf, req.Code); err != nil {
			writeCodeError(c, err)
			return
		}
		var codes []string
		err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			codes, err = replaceBackupCodes(tx, user.ID)
			return err
		})
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create backup codes")
			return
		}
		Success(c, http.StatusOK, gin.H{"backup_codes": codes})
	}
}
