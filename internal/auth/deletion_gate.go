package auth

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/account"
	"gorm.io/gorm"
)

// DeletionGate must run after JWTMiddleware. It rejects requests from
// accounts that are scheduled for deletion (except reading /me and cancelling)
// or already deleted.
func DeletionGate(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := c.Get("user_id")
		if !ok {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing user context")
			c.Abort()
			return
		}
		status, at, err := account.GetStatus(db, id.(uuid.UUID))
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check account status")
			c.Abort()
			return
		}
		switch status {
		case account.StatusScheduled:
			m, p := c.Request.Method, c.FullPath()
			if (m == http.MethodGet && p == "/api/v1/me") || (m == http.MethodDelete && p == "/api/v1/me/deletion") {
				break
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": gin.H{
				"code":                   "ACCOUNT_DELETION_SCHEDULED",
				"message":                "account is scheduled for deletion",
				"deletion_scheduled_for": at.UTC().Format(time.RFC3339),
				"request_id":             c.GetString("request_id"),
			}})
			return
		case account.StatusDeleted:
			Error(c, http.StatusGone, "ACCOUNT_DELETED", "account has been deleted")
			c.Abort()
			return
		}
		c.Next()
	}
}
