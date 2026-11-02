package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/terra-server/internal/config"
	"github.com/nhridoy/terra-server/internal/email"
	"github.com/nhridoy/terra-server/internal/models"
	"gorm.io/gorm"
)

type preloginRequest struct {
	Email string `json:"email" binding:"required"`
}

type kdfParams struct {
	M int `json:"m"`
	T int `json:"t"`
	P int `json:"p"`
}

// Minimum KDF policy. The verifier's brute-force cost is set by the params
// chosen at account creation, so the server never accepts weaker values —
// a malicious client could otherwise register accounts that are cheap to
// brute-force. Values above the minimums are allowed (flexible policy).
const (
	minKDFMemoryKiB = 32 * 1024
	minKDFTime      = 2
	minKDFParallel  = 1
)

func validKDF(k kdfParams) bool {
	return k.M >= minKDFMemoryKiB && k.T >= minKDFTime && k.P >= minKDFParallel
}

type keyringPayload struct {
	DekWrappedByKek        string `json:"dek_wrapped_by_kek"`
	DekWrappedByRecovery   string `json:"dek_wrapped_by_recovery"`
	PrivateKeyWrappedByDek string `json:"private_key_wrapped_by_dek"`
}

type registerRequest struct {
	UserID       string         `json:"user_id" binding:"required"`
	DeviceID     string         `json:"device_id"`
	Email        string         `json:"email" binding:"required"`
	FullName     string         `json:"full_name"`
	PasswordHash string         `json:"password_hash" binding:"required"`
	RecoveryCode string         `json:"recovery_code"`
	PublicKey    string         `json:"public_key"`
	Keyring      keyringPayload `json:"keyring"`
	KDF          kdfParams      `json:"kdf"`
	ServerSalt   string         `json:"server_salt" binding:"required"`
	SaltCL       string         `json:"salt_cl" binding:"required"`
}

type verifyEmailRequest struct {
	Email    string `json:"email" binding:"required"`
	Otp      string `json:"otp" binding:"required"`
	DeviceID string `json:"device_id"`
}

func HandlePrelogin(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req preloginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "email is required")
			return
		}

		var user models.User
		found := db.Where("email = ?", req.Email).First(&user).Error == nil

		if found {
			kdf := map[string]any{
				"m": user.KDFM,
				"t": user.KDFT,
				"p": user.KDFP,
			}
			nonce, err := randBytes(32)
			if err != nil {
				Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate nonce")
				return
			}
			storeLoginNonce(db, req.Email, nonce)
			Success(c, http.StatusOK, gin.H{
				"nonce":       nonce,
				"kdf":         kdf,
				"server_salt": deref(user.AuthSalt),
				"salt_cl":     deref(user.SaltCL),
			})
			return
		}

		kdf := map[string]any{
			"m": 32768,
			"t": 2,
			"p": 1,
		}
		nonce, err := randBytes(32)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate nonce")
			return
		}
		serverSalt, err := randBytes(32)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate salt")
			return
		}
		saltCL, err := randBytes(16)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate salt")
			return
		}
		Success(c, http.StatusOK, gin.H{
			"nonce":       nonce,
			"kdf":         kdf,
			"server_salt": serverSalt,
			"salt_cl":     saltCL,
		})
	}
}

func HandleRegister(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req registerRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
			return
		}

		if !validKDF(req.KDF) {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid kdf parameters")
			return
		}

		userID, err := uuid.Parse(req.UserID)
		if err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid user_id")
			return
		}
		if req.DeviceID != "" {
			if _, err := uuid.Parse(req.DeviceID); err != nil {
				Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid device_id")
				return
			}
		}

		var existing models.User
		if db.Where("id = ?", userID).First(&existing).Error == nil ||
			db.Where("email = ?", req.Email).First(&existing).Error == nil {
			// A user_id or email that already exists (verified or not, with the
			// same password or a different one) is always a conflict. The
			// account already exists and re-registration must not proceed.
			Error(c, http.StatusConflict, "CONFLICT", "email already registered")
			return
		}

		fullName := req.FullName
		if fullName == "" {
			fullName = req.Email
		}

		var recoveryHash *string
		if req.RecoveryCode != "" {
			codeBytes, err := base64.RawStdEncoding.DecodeString(req.RecoveryCode)
			if err != nil {
				Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid recovery_code encoding")
				return
			}
			codeHash := sha256.Sum256(codeBytes)
			hash := base64.RawStdEncoding.EncodeToString(codeHash[:])
			recoveryHash = &hash
		}

		var publicKey *string
		if req.PublicKey != "" {
			publicKey = &req.PublicKey
		}

		user := models.User{
			ID:           userID,
			Email:        req.Email,
			FullName:     fullName,
			AuthProvider: "password",
			AuthVerifier: &req.PasswordHash,
			AuthSalt:     &req.ServerSalt,
			SaltCL:       &req.SaltCL,
			KDFM:         req.KDF.M,
			KDFT:         req.KDF.T,
			KDFP:         req.KDF.P,
			PublicKey:    publicKey,
			RecoveryHash: recoveryHash,
			Initialized:  true,
		}
		if err := db.Create(&user).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create user")
			return
		}

		if err := seedKeyring(db, userID, req.Keyring); err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to store keyring")
			return
		}

		if err := models.SeedPersonalVault(db, userID); err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to seed vault")
			return
		}

		if cfg.RequireEmailVerification {
			respondVerificationRequired(c, db, cfg, &user)
			return
		}

		rt, err := createRefreshToken(db, userID, req.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create refresh token")
			return
		}

		at, err := GenerateAccessToken(userID, req.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
			return
		}

		Success(c, http.StatusCreated, gin.H{
			"access_token":  at,
			"refresh_token": rt,
			"user":          user,
			"keyring":       fetchKeyring(db, user.ID),
		})
	}
}

func respondVerificationRequired(c *gin.Context, db *gorm.DB, cfg *config.Config, user *models.User) {
	otp, err := issueEmailVerifyCode(db, user.ID)
	if err != nil {
		Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create verification code")
		return
	}
	sender := email.New(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, cfg.LogOtpFallback)
	if err := sender.SendOtp(user.Email, otp); err != nil {
		slog.Error("failed to send verification otp", "email", user.Email, "error", err)
		Error(c, http.StatusServiceUnavailable, "EMAIL_DELIVERY_FAILED", "verification email could not be sent, please try again")
		return
	}
	Success(c, http.StatusCreated, gin.H{
		"verification_required": true,
		"user":                  user,
	})
}

type loginRequest struct {
	Email        string `json:"email" binding:"required"`
	Proof        string `json:"proof" binding:"required"`
	Nonce        string `json:"nonce" binding:"required"`
	DeviceID     string `json:"device_id"`
	ClientPubkey string `json:"client_pubkey"`
}

func HandleLogin(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req loginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
			return
		}

		var user models.User
		if db.Where("email = ?", req.Email).First(&user).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}

		if user.AuthVerifier == nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}

		proofBytes, err := base64.RawStdEncoding.DecodeString(req.Proof)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}
		nonceBytes, err := base64.RawStdEncoding.DecodeString(req.Nonce)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}
		if !consumeLoginNonce(db, req.Email, req.Nonce) {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}
		verifierBytes, err := base64.RawStdEncoding.DecodeString(*user.AuthVerifier)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}

		expectedProof := GenerateProof(verifierBytes, nonceBytes)
		if !ConstantTimeCompare(proofBytes, expectedProof) {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}

		if cfg.RequireEmailVerification && user.AuthProvider == "password" && user.EmailVerifiedAt == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{
				"code":       "VERIFICATION_REQUIRED",
				"message":    "verify your email",
				"email":      user.Email,
				"request_id": c.GetString("request_id"),
			}})
			return
		}

		now := time.Now()
		db.Model(&user).Update("last_login_at", &now)

		rtToken, err := createRefreshToken(db, user.ID, req.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create refresh token")
			return
		}

		at, err := GenerateAccessToken(user.ID, req.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
			return
		}

		keyring := fetchKeyring(db, user.ID)

		Success(c, http.StatusOK, gin.H{
			"access_token":  at,
			"refresh_token": rtToken,
			"user":          user,
			"keyring":       keyring,
		})
	}
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func HandleRefresh(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req refreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "refresh_token is required")
			return
		}

		tokenHash := hashToken(req.RefreshToken)

		var rt models.RefreshToken
		if db.Where("token_hash = ?", tokenHash).First(&rt).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid refresh token")
			return
		}

		if rt.RevokedAt != nil {
			db.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", rt.UserID).
				Update("revoked_at", time.Now())
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "refresh token revoked (reuse detected)")
			return
		}

		if time.Now().After(rt.ExpiresAt) {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "refresh token expired")
			return
		}

		now := time.Now()
		db.Model(&rt).Updates(map[string]any{
			"revoked_at": &now,
			"rotated_at": &now,
		})

		newRT, err := createRefreshToken(db, rt.UserID, rt.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create refresh token")
			return
		}

		at, err := GenerateAccessToken(rt.UserID, rt.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
			return
		}

		Success(c, http.StatusOK, gin.H{
			"access_token":  at,
			"refresh_token": newRT,
		})
	}
}

func HandleLogout(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req refreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "refresh_token is required")
			return
		}

		tokenHash := hashToken(req.RefreshToken)

		var rt models.RefreshToken
		if db.Where("token_hash = ?", tokenHash).First(&rt).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid refresh token")
			return
		}

		now := time.Now()
		db.Model(&rt).Update("revoked_at", &now)

		c.Status(http.StatusNoContent)
	}
}

type passwordChangeRequest struct {
	OldProof        string    `json:"old_proof" binding:"required"`
	OldNonce        string    `json:"old_nonce" binding:"required"`
	NewVerifier     string    `json:"new_verifier" binding:"required"`
	NewEncryptedDEK string    `json:"new_encrypted_dek"`
	NewNonce        string    `json:"new_nonce"`
	NewKDF          kdfParams `json:"new_kdf"`
	NewServerSalt   string    `json:"new_server_salt"`
	NewSaltCL       string    `json:"new_salt_cl"`
}

func HandlePasswordChange(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing user context")
			return
		}

		var req passwordChangeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
			return
		}

		var user models.User
		if db.Where("id = ?", userID).First(&user).Error != nil {
			Error(c, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}

		if user.AuthVerifier == nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "no verifier set")
			return
		}

		oldProofBytes, err := base64.RawStdEncoding.DecodeString(req.OldProof)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid old proof")
			return
		}
		oldNonceBytes, err := base64.RawStdEncoding.DecodeString(req.OldNonce)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid old nonce")
			return
		}
		if !consumeLoginNonce(db, user.Email, req.OldNonce) {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid old nonce")
			return
		}
		verifierBytes, err := base64.RawStdEncoding.DecodeString(*user.AuthVerifier)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid stored verifier")
			return
		}

		expectedProof := GenerateProof(verifierBytes, oldNonceBytes)
		if !ConstantTimeCompare(oldProofBytes, expectedProof) {
			Error(c, http.StatusForbidden, "FORBIDDEN", "current password is incorrect")
			return
		}

		if req.NewKDF.M != 0 && !validKDF(req.NewKDF) {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid kdf parameters")
			return
		}

		updates := map[string]any{
			"auth_verifier": req.NewVerifier,
		}
		if req.NewServerSalt != "" {
			updates["auth_salt"] = req.NewServerSalt
		}
		if req.NewSaltCL != "" {
			updates["salt_cl"] = req.NewSaltCL
		}
		user.AuthVerifier = &req.NewVerifier
		if req.NewServerSalt != "" {
			user.AuthSalt = &req.NewServerSalt
		}
		if req.NewSaltCL != "" {
			user.SaltCL = &req.NewSaltCL
		}
		if req.NewKDF.M != 0 {
			user.KDFM = req.NewKDF.M
		}
		if req.NewKDF.T != 0 {
			user.KDFT = req.NewKDF.T
		}
		if req.NewKDF.P != 0 {
			user.KDFP = req.NewKDF.P
		}
		// Verifier/salts and the re-wrapped keyring must land together: a
		// partial write would leave the account with a new password whose
		// vault key is still wrapped with the old KEK (unrecoverable vault).
		err = db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Save(&user).Error; err != nil {
				return err
			}
			if req.NewEncryptedDEK != "" {
				return upsertUserKey(tx, user.ID, "dek_wrapped_by_kek", req.NewEncryptedDEK)
			}
			return nil
		})
		if err != nil {
			slog.Error("failed to update password", "error", err)
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update user")
			return
		}

		clearLoginNonces(db, user.Email)

		deviceID := c.GetString("device_id")
		db.Model(&models.RefreshToken{}).
			Where("user_id = ? AND device_id <> ? AND revoked_at IS NULL", user.ID, deviceID).
			Update("revoked_at", time.Now())

		c.Status(http.StatusNoContent)
	}
}

type recoveryRequest struct {
	RecoveryCode            string    `json:"recovery_code" binding:"required"`
	Signature               string    `json:"signature" binding:"required"`
	NewRecoveryCode         string    `json:"new_recovery_code"`
	NewVerifier             string    `json:"new_verifier" binding:"required"`
	NewEncryptedDEK         string    `json:"new_encrypted_dek"`
	NewDekWrappedByRecovery string    `json:"new_dek_wrapped_by_recovery"`
	NewNonce                string    `json:"new_nonce"`
	NewKDF                  kdfParams `json:"new_kdf"`
	NewServerSalt           string    `json:"new_server_salt"`
	NewSaltCL               string    `json:"new_salt_cl"`
}

func HandleRecovery(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req recoveryRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
			return
		}

		recoveryCodeBytes, err := base64.RawStdEncoding.DecodeString(req.RecoveryCode)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid recovery code")
			return
		}
		codeHash := sha256.Sum256(recoveryCodeBytes)
		codeHashB64 := base64.RawStdEncoding.EncodeToString(codeHash[:])

		var user models.User
		if db.Where("recovery_hash = ?", codeHashB64).First(&user).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid recovery code")
			return
		}

		sigBytes, err := base64.RawStdEncoding.DecodeString(req.Signature)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid signature encoding")
			return
		}

		if user.PublicKey == nil || *user.PublicKey == "" || req.NewNonce == "" {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid signature")
			return
		}
		pubKeyBytes, err := base64.RawStdEncoding.DecodeString(*user.PublicKey)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid signature")
			return
		}
		nonceBytes, err := base64.RawStdEncoding.DecodeString(req.NewNonce)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid signature")
			return
		}
		mac := hmac.New(sha256.New, pubKeyBytes)
		mac.Write(nonceBytes)
		if !ConstantTimeCompare(sigBytes, mac.Sum(nil)) {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid signature")
			return
		}

		user.AuthVerifier = &req.NewVerifier
		if req.NewRecoveryCode != "" {
			newCodeBytes, err := base64.RawStdEncoding.DecodeString(req.NewRecoveryCode)
			if err != nil {
				Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid new recovery code")
				return
			}
			newCodeHash := sha256.Sum256(newCodeBytes)
			newHashB64 := base64.RawStdEncoding.EncodeToString(newCodeHash[:])
			user.RecoveryHash = &newHashB64
		} else {
			user.RecoveryHash = nil
		}
		if req.NewServerSalt != "" {
			user.AuthSalt = &req.NewServerSalt
		}
		if req.NewSaltCL != "" {
			user.SaltCL = &req.NewSaltCL
		}
		if req.NewKDF.M != 0 {
			user.KDFM = req.NewKDF.M
		}
		if req.NewKDF.T != 0 {
			user.KDFT = req.NewKDF.T
		}
		if req.NewKDF.P != 0 {
			user.KDFP = req.NewKDF.P
		}
		// Verifier/salts, recovery hash, and the re-wrapped keyring must land
		// together; a partial write leaves the vault key wrapped with a key
		// that no longer matches the stored verifier.
		err = db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Save(&user).Error; err != nil {
				return err
			}
			if req.NewEncryptedDEK != "" {
				if err := upsertUserKey(tx, user.ID, "dek_wrapped_by_kek", req.NewEncryptedDEK); err != nil {
					return err
				}
			}
			if req.NewDekWrappedByRecovery != "" {
				return upsertUserKey(tx, user.ID, "dek_wrapped_by_recovery", req.NewDekWrappedByRecovery)
			}
			return nil
		})
		if err != nil {
			slog.Error("failed to update recovery", "error", err)
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update user")
			return
		}

		clearLoginNonces(db, user.Email)

		db.Model(&models.RefreshToken{}).
			Where("user_id = ? AND revoked_at IS NULL", user.ID).
			Update("revoked_at", time.Now())

		c.Status(http.StatusNoContent)
	}
}

type recoveryPrefetchRequest struct {
	RecoveryCode string `json:"recovery_code" binding:"required"`
}

var keyringKeyTypes = []string{
	"dek_wrapped_by_kek",
	"dek_wrapped_by_recovery",
	"private_key_wrapped_by_dek",
}

func seedKeyring(db *gorm.DB, userID uuid.UUID, kr keyringPayload) error {
	rows := map[string]string{
		"dek_wrapped_by_kek":         kr.DekWrappedByKek,
		"dek_wrapped_by_recovery":    kr.DekWrappedByRecovery,
		"private_key_wrapped_by_dek": kr.PrivateKeyWrappedByDek,
	}
	for keyType, payload := range rows {
		if payload == "" {
			continue
		}
		if err := upsertUserKey(db, userID, keyType, payload); err != nil {
			return err
		}
	}
	return nil
}

func upsertUserKey(db *gorm.DB, userID uuid.UUID, keyType, payload string) error {
	var uk models.UserKey
	err := db.Where("user_id = ? AND key_type = ?", userID, keyType).First(&uk).Error
	if err == nil {
		return db.Model(&uk).Update("payload", payload).Error
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}
	return db.Create(&models.UserKey{
		UserID:  userID,
		KeyType: keyType,
		Payload: payload,
	}).Error
}

func fetchKeyring(db *gorm.DB, userID uuid.UUID) *map[string]string {
	keyring := map[string]string{}
	var rows []models.UserKey
	db.Where("user_id = ? AND key_type IN ?", userID, keyringKeyTypes).Find(&rows)
	for _, r := range rows {
		keyring[r.KeyType] = r.Payload
	}
	if len(keyring) == 0 {
		return nil
	}
	return &keyring
}

type attachRecoveryMaterialRequest struct {
	RecoveryCode         string `json:"recovery_code" binding:"required"`
	DekWrappedByRecovery string `json:"dek_wrapped_by_recovery" binding:"required"`
}

// HandleAttachRecoveryMaterial stores the recovery kit (hash + wrapped DEK) for
// an already-verified account. Signup defers kit creation until email
// verification so the code is always generated client-side on the verifying
// device; this endpoint is the server-side half of that attach.
func HandleAttachRecoveryMaterial(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing user context")
			return
		}

		var req attachRecoveryMaterialRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "recovery_code and dek_wrapped_by_recovery are required")
			return
		}

		codeBytes, err := base64.RawStdEncoding.DecodeString(req.RecoveryCode)
		if err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid recovery_code encoding")
			return
		}

		var user models.User
		if db.Where("id = ?", userID).First(&user).Error != nil {
			Error(c, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}

		if cfg.RequireEmailVerification && user.AuthProvider == "password" && user.EmailVerifiedAt == nil {
			Error(c, http.StatusForbidden, "FORBIDDEN", "email not verified")
			return
		}

		codeHash := sha256.Sum256(codeBytes)
		hashB64 := base64.RawStdEncoding.EncodeToString(codeHash[:])

		var uk models.UserKey
		rowExists := db.Where("user_id = ? AND key_type = ?", user.ID, "dek_wrapped_by_recovery").First(&uk).Error == nil
		if user.RecoveryHash != nil && rowExists {
			Error(c, http.StatusConflict, "RECOVERY_ALREADY_EXISTS", "recovery material already set for this account")
			return
		}

		// Row and hash are written atomically so a partial failure rolls back
		// and the client simply retries on the next login.
		err = db.Transaction(func(tx *gorm.DB) error {
			if err := upsertUserKey(tx, user.ID, "dek_wrapped_by_recovery", req.DekWrappedByRecovery); err != nil {
				return err
			}
			return tx.Model(&user).Update("recovery_hash", &hashB64).Error
		})
		if err != nil {
			slog.Error("failed to store recovery material", "error", err)
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to store recovery material")
			return
		}

		Success(c, http.StatusOK, gin.H{"recovery_attached": true})
	}
}

func HandleRecoveryPrefetch(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req recoveryPrefetchRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "recovery_code is required")
			return
		}

		recoveryCodeBytes, err := base64.RawStdEncoding.DecodeString(req.RecoveryCode)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid recovery code")
			return
		}
		codeHash := sha256.Sum256(recoveryCodeBytes)
		codeHashB64 := base64.RawStdEncoding.EncodeToString(codeHash[:])

		var user models.User
		if db.Where("recovery_hash = ?", codeHashB64).First(&user).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid recovery code")
			return
		}

		var uk models.UserKey
		if db.Where("user_id = ? AND key_type = ?", user.ID, "dek_wrapped_by_recovery").First(&uk).Error != nil {
			Error(c, http.StatusNotFound, "NOT_FOUND", "no recovery data for this account")
			return
		}

		var pk models.UserKey
		db.Where("user_id = ? AND key_type = ?", user.ID, "private_key_wrapped_by_dek").First(&pk)

		nonce, err := randBytes(32)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate nonce")
			return
		}
		Success(c, http.StatusOK, gin.H{
			"nonce": nonce,
			"email": user.Email,
			"kdf": map[string]any{
				"m": user.KDFM,
				"t": user.KDFT,
				"p": user.KDFP,
			},
			"server_salt":                deref(user.AuthSalt),
			"salt_cl":                    deref(user.SaltCL),
			"dek_wrapped_by_recovery":    uk.Payload,
			"private_key_wrapped_by_dek": pk.Payload,
		})
	}
}

func HandleMe(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing user context")
			return
		}

		var user models.User
		if db.Where("id = ?", userID).First(&user).Error != nil {
			Error(c, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}

		Success(c, http.StatusOK, user)
	}
}

func createRefreshToken(db *gorm.DB, userID uuid.UUID, deviceID string, cfg *config.Config) (string, error) {
	rawToken, err := randBytes(48)
	if err != nil {
		return "", err
	}
	tokenHash := hashToken(rawToken)

	now := time.Now()
	rt := models.RefreshToken{
		UserID:    userID,
		TokenHash: tokenHash,
		DeviceID:  deviceID,
		ExpiresAt: now.Add(cfg.RefreshTokenExpiry),
	}
	if err := db.Create(&rt).Error; err != nil {
		return "", err
	}
	return rawToken, nil
}

func HandleVerifyEmail(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req verifyEmailRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "email and otp are required")
			return
		}

		var user models.User
		if db.Where("email = ?", req.Email).First(&user).Error != nil {
			Error(c, http.StatusBadRequest, "INVALID_VERIFICATION_CODE", "verification code expired or invalid")
			return
		}
		if user.EmailVerifiedAt != nil {
			Error(c, http.StatusBadRequest, "INVALID_VERIFICATION_CODE", "verification code expired or invalid")
			return
		}

		code, err := findEmailVerifyCode(db, user.ID)
		if err != nil || code.ExpiresAt.Before(time.Now()) {
			Error(c, http.StatusBadRequest, "INVALID_VERIFICATION_CODE", "verification code expired or invalid")
			return
		}

		hash := sha256.Sum256([]byte(req.Otp))
		hashB64 := base64.RawStdEncoding.EncodeToString(hash[:])
		if !ConstantTimeCompare([]byte(hashB64), []byte(code.CodeHash)) {
			code.Attempts++
			if code.Attempts >= maxOtpAttempts {
				db.Delete(&code)
				Error(c, http.StatusBadRequest, "INVALID_VERIFICATION_CODE", "too many failed attempts, request a new code")
				return
			}
			db.Save(&code)
			Error(c, http.StatusBadRequest, "INVALID_VERIFICATION_CODE", "verification code expired or invalid")
			return
		}

		now := time.Now()
		if err := db.Model(&user).Updates(map[string]any{
			"email_verified_at": &now,
			"last_login_at":     &now,
		}).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to verify email")
			return
		}
		user.EmailVerifiedAt = &now

		if err := db.Delete(&code).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to consume verification code")
			return
		}

		rt, err := createRefreshToken(db, user.ID, req.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create refresh token")
			return
		}
		at, err := GenerateAccessToken(user.ID, req.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
			return
		}

		Success(c, http.StatusOK, gin.H{
			"access_token":  at,
			"refresh_token": rt,
			"user":          user,
			"keyring":       fetchKeyring(db, user.ID),
		})
	}
}

func HandleResendVerification(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email string `json:"email" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "email is required")
			return
		}

		var user models.User
		if db.Where("email = ?", req.Email).First(&user).Error != nil ||
			user.AuthProvider != "password" || user.EmailVerifiedAt != nil {
			Success(c, http.StatusOK, gin.H{"verification_required": true})
			return
		}

		existing, err := findEmailVerifyCode(db, user.ID)
		if err == nil && time.Since(existing.CreatedAt) < time.Minute {
			Error(c, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "wait before requesting a new code")
			return
		}

		otp, err := issueEmailVerifyCode(db, user.ID)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create verification code")
			return
		}
		sender := email.New(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, cfg.LogOtpFallback)
		if err := sender.SendOtp(user.Email, otp); err != nil {
			slog.Error("failed to send verification otp", "email", user.Email, "error", err)
			Error(c, http.StatusServiceUnavailable, "EMAIL_DELIVERY_FAILED", "verification email could not be sent, please try again")
			return
		}

		Success(c, http.StatusOK, gin.H{"verification_required": true})
	}
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawStdEncoding.EncodeToString(h[:])
}

const loginNonceTTL = 5 * time.Minute

// storeLoginNonce persists the prelogin challenge so a login proof can only
// be bound to a nonce the server actually issued (never a captured pair
// replayed against a fresh nonce or swapped to another user).
func storeLoginNonce(db *gorm.DB, email, nonce string) {
	// Clear stale rows for this email on issue (expired or already used).
	db.Where("email = ? AND (expires_at < ? OR used_at IS NOT NULL)", email, time.Now()).
		Delete(&models.LoginNonce{})
	db.Create(&models.LoginNonce{
		Email:     email,
		NonceHash: hashToken(nonce),
		ExpiresAt: time.Now().Add(loginNonceTTL),
	})
}

// consumeLoginNonce atomically checks a nonce was issued for this email, is
// still fresh and unused, then marks it used (single-use). Returns false on
// replay, expiry, or if the nonce was never issued.
func consumeLoginNonce(db *gorm.DB, email, nonce string) bool {
	var nonceRow models.LoginNonce
	err := db.Where("email = ? AND nonce_hash = ?", email, hashToken(nonce)).First(&nonceRow).Error
	if err != nil {
		return false
	}
	if nonceRow.UsedAt != nil || time.Now().After(nonceRow.ExpiresAt) {
		return false
	}
	now := time.Now()
	db.Model(&nonceRow).Update("used_at", &now)
	return true
}

// clearLoginNonces invalidates every outstanding nonce for an account after
// its verifier changes (password change, OAuth setup, recovery).
func clearLoginNonces(db *gorm.DB, email string) {
	db.Where("email = ?", email).Delete(&models.LoginNonce{})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func randBytes(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand read: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}
