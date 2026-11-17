package auth

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

const (
	challengeLogin    = "login"
	challengeOAuth    = "oauth"
	challengeRecovery = "recovery"
	recoveryProofPath = "recovery_proof"

	challengeTTL         = 5 * time.Minute
	recoveryChallengeTTL = 15 * time.Minute
	recoveryProofTTL     = 10 * time.Minute
	maxChallengeAttempts = 5
	// Per account: fresh challenges don't reset the guess count.
	maxAccountAttempts   = 20
	accountAttemptWindow = 15 * time.Minute

	twoFactorRecoveryPurpose = "two_factor_recovery"
)

// twoFactorOn returns the user's enabled two-factor row. A lookup error is returned, never
// read as "off": callers must fail closed.
func twoFactorOn(db *gorm.DB, userID uuid.UUID) (*models.TwoFactor, bool, error) {
	tf, err := twoFactorRow(db, userID)
	if err != nil {
		return nil, false, err
	}
	if tf == nil || tf.EnabledAt == nil {
		return nil, false, nil
	}
	return tf, true, nil
}

// accountAttempts sums the user's recent second-factor guesses across all challenges. A
// challenge takes guesses until it expires, so any guess in the window belongs to one
// created up to a challenge lifetime before it: look back that much further.
func accountAttempts(db *gorm.DB, userID uuid.UUID) (int64, error) {
	var recent int64
	since := time.Now().Add(-accountAttemptWindow - recoveryChallengeTTL)
	err := db.Model(&models.TwoFactorChallenge{}).
		Where("user_id = ? AND path IN ? AND created_at > ?", userID, []string{challengeLogin, challengeOAuth, challengeRecovery}, since).
		Select("COALESCE(SUM(attempts), 0)").Scan(&recent).Error
	return recent, err
}

func accountLocked(c *gin.Context) {
	Error(c, http.StatusTooManyRequests, "TWO_FACTOR_LOCKED", "Too many two-factor attempts. Try again in 30 minutes.")
}

func newChallenge(db *gorm.DB, userID uuid.UUID, deviceID, path string, ttl time.Duration) (string, error) {
	token, err := randBytes(32)
	if err != nil {
		return "", err
	}
	row := models.TwoFactorChallenge{
		TokenHash: hashToken(token),
		UserID:    userID,
		DeviceID:  deviceID,
		Path:      path,
		ExpiresAt: time.Now().Add(ttl),
	}
	if err := db.Create(&row).Error; err != nil {
		return "", err
	}
	return token, nil
}

// twoFactorRequired answers a passed first factor: no tokens or key material, only a challenge.
// The message is readable by clients that predate two-factor. 403, like VERIFICATION_REQUIRED:
// the app's HTTP layer treats a 401 as an expired session and would refresh and resend.
func twoFactorRequired(c *gin.Context, token string) {
	c.JSON(http.StatusForbidden, gin.H{"error": gin.H{
		"code":       "TWO_FACTOR_REQUIRED",
		"message":    "Enter your two-factor code. Update Shetu if you don't see a code field.",
		"challenge":  token,
		"request_id": c.GetString("request_id"),
	}})
}

// gateTwoFactor stops a sign-in at the second factor when the account has two-factor on.
// It reports whether it answered the request.
func gateTwoFactor(c *gin.Context, db *gorm.DB, userID uuid.UUID, deviceID, path string, ttl time.Duration) bool {
	_, on, err := twoFactorOn(db, userID)
	if err != nil {
		Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check two-factor")
		return true
	}
	if !on {
		return false
	}
	recent, err := accountAttempts(db, userID)
	if err != nil {
		Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to start two-factor")
		return true
	}
	if recent >= maxAccountAttempts {
		accountLocked(c)
		return true
	}
	token, err := newChallenge(db, userID, deviceID, path, ttl)
	if err != nil {
		Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to start two-factor")
		return true
	}
	twoFactorRequired(c, token)
	return true
}

func challengeExpired(c *gin.Context) {
	Error(c, http.StatusUnauthorized, "TWO_FACTOR_EXPIRED", "Start signing in again.")
}

// issueSignIn finishes a sign-in: records the device and answers with tokens, user and keyring.
func issueSignIn(c *gin.Context, db *gorm.DB, cfg *config.Config, user models.User, deviceID, method string) {
	now := time.Now()
	db.Model(&user).Update("last_login_at", &now)

	recordSignIn(c, db, cfg, user.ID, deviceID, method)
	rtToken, err := createRefreshToken(db, user.ID, deviceID, cfg)
	if err != nil {
		Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create refresh token")
		return
	}

	at, err := GenerateAccessToken(user.ID, deviceID, cfg)
	if err != nil {
		Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
		return
	}

	Success(c, http.StatusOK, gin.H{
		"access_token":  at,
		"refresh_token": rtToken,
		"user":          user,
		"keyring":       fetchKeyring(db, user.ID),
	})
}

// takeChallengeAttempt spends one of the challenge's attempts. The conditional update makes
// an expired, used or exhausted challenge fail even under concurrent requests.
func takeChallengeAttempt(db *gorm.DB, token string) (*models.TwoFactorChallenge, bool) {
	hash := hashToken(token)
	res := db.Model(&models.TwoFactorChallenge{}).
		Where("token_hash = ? AND path IN ? AND used_at IS NULL AND attempts < ? AND expires_at > ?",
			hash, []string{challengeLogin, challengeOAuth, challengeRecovery}, maxChallengeAttempts, time.Now()).
		Update("attempts", gorm.Expr("attempts + 1"))
	if res.Error != nil || res.RowsAffected == 0 {
		return nil, false
	}
	var ch models.TwoFactorChallenge
	if db.First(&ch, "token_hash = ?", hash).Error != nil {
		return nil, false
	}
	return &ch, true
}

// markUsed consumes a challenge or proof once; false when another request got there first.
func markUsed(db *gorm.DB, id uint) bool {
	res := db.Model(&models.TwoFactorChallenge{}).Where("id = ? AND used_at IS NULL", id).Update("used_at", time.Now())
	return res.Error == nil && res.RowsAffected == 1
}

type twoFactorVerifyRequest struct {
	Challenge string `json:"challenge" binding:"required"`
	Code      string `json:"code" binding:"required"`
	Kind      string `json:"kind"`
}

// HandleTwoFactorVerify turns a challenge and a code into the response the first factor would
// have given: tokens for login and OAuth, the recovery material and a proof for recovery.
func HandleTwoFactorVerify(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req twoFactorVerifyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "challenge and code are required")
			return
		}
		ch, ok := takeChallengeAttempt(db, req.Challenge)
		if !ok {
			challengeExpired(c)
			return
		}
		// The attempt is counted first, so concurrent guesses can't all pass this check.
		recent, err := accountAttempts(db, ch.UserID)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check the code")
			return
		}
		if recent > maxAccountAttempts {
			accountLocked(c)
			return
		}
		tf, on, err := twoFactorOn(db, ch.UserID)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check the code")
			return
		}
		if !on {
			challengeExpired(c)
			return
		}
		viaEmail := req.Kind == "email"
		if viaEmail {
			if ch.Path != challengeRecovery {
				writeCodeError(c, errCodeInvalid)
				return
			}
			if err := consumeEmailCode(db, ch.UserID, twoFactorRecoveryPurpose, req.Code); err != nil {
				codeRefused(c, db, cfg, ch, err)
				return
			}
		} else if usedBackup, err := verifySecondFactor(db, cfg, tf, req.Code); err != nil {
			codeRefused(c, db, cfg, ch, err)
			return
		} else if usedBackup {
			recordEvent(c, db, cfg, ch.UserID, "backup_code_used", ch.DeviceID, "")
		}
		if !markUsed(db, ch.ID) {
			challengeExpired(c)
			return
		}
		var user models.User
		if err := db.First(&user, "id = ?", ch.UserID).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load user")
			return
		}
		if ch.Path == challengeRecovery {
			finishRecoveryChallenge(c, db, user, viaEmail)
			return
		}
		method := "password"
		if ch.Path == challengeOAuth {
			method = user.AuthProvider
		}
		issueSignIn(c, db, cfg, user, ch.DeviceID, method)
	}
}

// HandleTwoFactorEmail emails a code for a recovery challenge: the fallback when the
// authenticator and backup codes are lost. It never needs TWO_FACTOR_KEY.
func HandleTwoFactorEmail(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Challenge string `json:"challenge" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "challenge is required")
			return
		}
		var ch models.TwoFactorChallenge
		err := db.First(&ch, "token_hash = ? AND used_at IS NULL AND expires_at > ?", hashToken(req.Challenge), time.Now()).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			challengeExpired(c)
			return
		}
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load challenge")
			return
		}
		if ch.Path != challengeRecovery {
			writeCodeError(c, errCodeInvalid)
			return
		}
		var user models.User
		if err := db.First(&user, "id = ?", ch.UserID).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load user")
			return
		}
		code, err := issueEmailCode(db, user.ID, twoFactorRecoveryPurpose)
		if err == nil {
			err = deliverOtp(cfg, user.Email, code)
		}
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "couldn't send the email code")
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// finishOAuthCallback ends an OAuth sign-in for an existing, initialized user: the app gets
// tokens, or a challenge when the account has two-factor on.
func finishOAuthCallback(c *gin.Context, db *gorm.DB, cfg *config.Config, state *models.OAuthState, user models.User) {
	_, on, err := twoFactorOn(db, user.ID)
	if err != nil {
		c.Redirect(http.StatusFound, oauthTargetURL(state, cfg, "error", url.Values{"message": []string{"two_factor_failed"}}))
		return
	}
	if on {
		token, err := newChallenge(db, user.ID, state.DeviceID, challengeOAuth, challengeTTL)
		if err != nil {
			c.Redirect(http.StatusFound, oauthTargetURL(state, cfg, "error", url.Values{"message": []string{"two_factor_failed"}}))
			return
		}
		c.Redirect(http.StatusFound, oauthTargetURL(state, cfg, "two_factor", url.Values{
			"challenge": []string{token},
			"user_id":   []string{user.ID.String()},
		}))
		return
	}

	recordSignIn(c, db, cfg, user.ID, state.DeviceID, user.AuthProvider)
	rt, err := createRefreshToken(db, user.ID, state.DeviceID, cfg)
	if err != nil {
		c.Redirect(http.StatusFound, oauthTargetURL(state, cfg, "error", url.Values{"message": []string{"token_generation_failed"}}))
		return
	}

	at, err := GenerateAccessToken(user.ID, state.DeviceID, cfg)
	if err != nil {
		c.Redirect(http.StatusFound, oauthTargetURL(state, cfg, "error", url.Values{"message": []string{"token_generation_failed"}}))
		return
	}

	c.Redirect(http.StatusFound, oauthTargetURL(state, cfg, "success", url.Values{
		"access_token":  []string{at},
		"refresh_token": []string{rt},
		"user_id":       []string{user.ID.String()},
	}))
}

// finishRecoveryChallenge hands out the recovery material and a single-use proof for
// POST /auth/recovery. A proof won with the emailed code turns two-factor off when used.
func finishRecoveryChallenge(c *gin.Context, db *gorm.DB, user models.User, viaEmail bool) {
	token, err := newChallenge(db, user.ID, "", recoveryProofPath, recoveryProofTTL)
	if err == nil && viaEmail {
		err = db.Model(&models.TwoFactorChallenge{}).Where("token_hash = ?", hashToken(token)).Update("disable_two_factor", true).Error
	}
	if err != nil {
		Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to finish two-factor")
		return
	}
	writeRecoveryPrefetch(c, db, user, token)
}

// takeRecoveryProof consumes the user's recovery proof once.
func takeRecoveryProof(db *gorm.DB, userID uuid.UUID, token string) (*models.TwoFactorChallenge, bool) {
	if token == "" {
		return nil, false
	}
	hash := hashToken(token)
	res := db.Model(&models.TwoFactorChallenge{}).
		Where("token_hash = ? AND user_id = ? AND path = ? AND used_at IS NULL AND expires_at > ?", hash, userID, recoveryProofPath, time.Now()).
		Update("used_at", time.Now())
	if res.Error != nil || res.RowsAffected == 0 {
		return nil, false
	}
	var proof models.TwoFactorChallenge
	if db.First(&proof, "token_hash = ?", hash).Error != nil {
		return nil, false
	}
	return &proof, true
}

// codeRefused answers a refused code; only a wrong code is a security event (the email wording
// follows how the person got this far: login, oauth or recovery). A code replayed in the same
// 30 seconds or an expired emailed code is the owner's own timing, not a guess.
func codeRefused(c *gin.Context, db *gorm.DB, cfg *config.Config, ch *models.TwoFactorChallenge, err error) {
	if errors.Is(err, errCodeInvalid) {
		recordEvent(c, db, cfg, ch.UserID, eventKindTwoFAFail, "", ch.Path)
	}
	writeCodeError(c, err)
}
