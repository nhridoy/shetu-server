package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

// HandleDefaultVault returns the account's canonical Personal vault. Older
// accounts without one are repaired here so the client can mirror the same ID.
func HandleDefaultVault(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := c.Get("user_id")
		if !ok {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing user")
			return
		}
		ownerID, ok := userID.(uuid.UUID)
		if !ok {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid user")
			return
		}
		if err := models.SeedPersonalVault(db, ownerID); err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to ensure default vault")
			return
		}
		var vault models.Vault
		if err := db.Where(
			"owner_id = ? AND kind = ? AND is_default = ? AND deleted_at IS NULL",
			ownerID, "personal", true,
		).Order("created_at ASC").First(&vault).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load default vault")
			return
		}
		Success(c, http.StatusOK, gin.H{
			"id":         vault.ID.String(),
			"owner_id":   vault.OwnerID.String(),
			"name":       vault.Name,
			"kind":       vault.Kind,
			"sort_order": vault.SortOrder,
			"is_default": vault.IsDefault,
		})
	}
}
