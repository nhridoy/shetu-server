package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/account"
	"github.com/nhridoy/shetu-server/internal/config"
	"github.com/nhridoy/shetu-server/internal/email"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

type deletionRequest struct {
	Proof string `json:"proof" binding:"required"`
	Nonce string `json:"nonce" binding:"required"`
	Email string `json:"email" binding:"required"`
}

func HandleRequestDeletion(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := c.Get("user_id")
		if !ok {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing user context")
			return
		}
		var req deletionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
			return
		}
		var user models.User
		if err := db.Where("id = ?", userID).First(&user).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			Error(c, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		} else if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load user")
			return
		}
		// Checked before the proof so a typo does not burn the nonce.
		if !strings.EqualFold(strings.TrimSpace(req.Email), user.Email) {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "email does not match")
			return
		}
		if status, code, msg := verifyPasswordProof(db, &user, req.Proof, req.Nonce); status != 0 {
			Error(c, status, code, msg)
			return
		}
		at, err := account.Schedule(db, userID.(uuid.UUID), time.Now())
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to schedule deletion")
			return
		}
		sender := email.New(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, cfg.LogOtpFallback)
		if sender.Enabled() {
			// Background so SMTP never delays the response; the error is not
			// logged because SMTP errors often echo the recipient address.
			go func() {
				if sender.SendAccountDeletionNotice(user.Email, at) != nil {
					slog.Warn("account deletion notice not sent")
				}
			}()
		}
		Success(c, http.StatusOK, gin.H{"deletion_scheduled_for": at.UTC().Format(time.RFC3339)})
	}
}

func HandleCancelDeletion(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := c.Get("user_id")
		if !ok {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing user context")
			return
		}
		err := account.Cancel(db, userID.(uuid.UUID))
		if errors.Is(err, account.ErrAccountDeleted) {
			Error(c, http.StatusGone, "ACCOUNT_DELETED", "account has been deleted")
			return
		}
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to cancel deletion")
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func HandleAccountStatus(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			UserID string `json:"user_id"`
		}
		id, err := uuid.Parse("")
		if c.ShouldBindJSON(&req) == nil {
			id, err = uuid.Parse(req.UserID)
		}
		if err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid user_id")
			return
		}
		status, at, err := account.GetStatus(db, id)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to read account status")
			return
		}
		data := gin.H{"status": status}
		if at != nil {
			data["deletion_scheduled_for"] = at.UTC().Format(time.RFC3339)
		}
		Success(c, http.StatusOK, data)
	}
}
