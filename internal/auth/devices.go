package auth

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/nhridoy/shetu-server/internal/models"
)

// validDeviceID is true for the client-made UUID device ids; anything else (older clients, the
// OAuth fallback "default") is not tracked as a device.
func validDeviceID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

// touchDevice records that a device got tokens. A fresh sign-in (the person has the credentials
// again) clears a revoke; a refresh never does.
func touchDevice(db *gorm.DB, userID uuid.UUID, deviceID string, freshSignIn bool) error {
	if !validDeviceID(deviceID) {
		return nil
	}
	now := time.Now()
	updates := []string{"last_seen_at"}
	if freshSignIn {
		updates = append(updates, "revoked_at")
	}
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "device_id"}},
		DoUpdates: clause.AssignmentColumns(updates),
	}).Create(&models.Device{UserID: userID, DeviceID: deviceID, LastSeenAt: now}).Error
}

// recordDevice is touchDevice for sign-in paths: a failure is logged, never blocks the sign-in.
func recordDevice(db *gorm.DB, userID uuid.UUID, deviceID string, freshSignIn bool) {
	if err := touchDevice(db, userID, deviceID, freshSignIn); err != nil {
		slog.Warn("failed to record device", "error", err)
	}
}

// deviceRevoked reports whether the user's device has been signed out remotely.
// deviceRevoked reports whether the device was signed out. A lookup error is returned, never
// read as "not revoked".
func deviceRevoked(db *gorm.DB, userID uuid.UUID, deviceID string) (bool, error) {
	if !validDeviceID(deviceID) {
		return false, nil
	}
	var n int64
	err := db.Model(&models.Device{}).
		Where("user_id = ? AND device_id = ? AND revoked_at IS NOT NULL", userID, deviceID).
		Count(&n).Error
	return n > 0, err
}

const deviceFieldMax = 100

func capField(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > deviceFieldMax {
		s = string(r[:deviceFieldMax])
	}
	return s
}

type deviceView struct {
	DeviceID   string    `json:"device_id"`
	Name       string    `json:"name"`
	Platform   string    `json:"platform"`
	AppVersion string    `json:"app_version"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	Current    bool      `json:"current"`
}

// HandleListDevices lists the user's active devices: not revoked and still holding a live
// refresh token (a device that signed out normally drops off).
func HandleListDevices(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(uuid.UUID)
		var rows []models.Device
		err := db.Where("user_id = ? AND revoked_at IS NULL", userID).
			Where("EXISTS (SELECT 1 FROM refresh_tokens rt WHERE rt.user_id = devices.user_id AND rt.device_id = devices.device_id AND rt.revoked_at IS NULL AND rt.rotated_at IS NULL AND rt.expires_at > ?)", time.Now()).
			Order("last_seen_at DESC").
			Find(&rows).Error
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list devices")
			return
		}
		current := c.GetString("device_id")
		out := make([]deviceView, 0, len(rows))
		for _, d := range rows {
			out = append(out, deviceView{d.DeviceID, d.Name, d.Platform, d.AppVersion, d.CreatedAt, d.LastSeenAt, d.DeviceID == current})
		}
		Success(c, http.StatusOK, out)
	}
}

// currentDevice returns the caller's own device id, or answers 400 for tokens without one.
func currentDevice(c *gin.Context) (string, bool) {
	id := c.GetString("device_id")
	if !validDeviceID(id) {
		Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Update Shetu to manage devices")
		return "", false
	}
	return id, true
}

// HandleUpdateCurrentDevice stores this device's name, platform and app version.
func HandleUpdateCurrentDevice(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(uuid.UUID)
		deviceID, ok := currentDevice(c)
		if !ok {
			return
		}
		var req struct {
			Name       string `json:"name"`
			Platform   string `json:"platform"`
			AppVersion string `json:"app_version"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid device info")
			return
		}
		if err := touchDevice(db, userID, deviceID, false); err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save device")
			return
		}
		err := db.Model(&models.Device{}).Where("user_id = ? AND device_id = ?", userID, deviceID).
			Updates(map[string]any{
				// The computer name only fills an empty name: a rename from the list sticks.
				"name":        gorm.Expr("CASE WHEN name = '' THEN ? ELSE name END", capField(req.Name)),
				"platform":    capField(req.Platform),
				"app_version": capField(req.AppVersion),
			}).Error
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save device")
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// HandleRenameDevice renames one of the user's devices.
func HandleRenameDevice(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(uuid.UUID)
		var req struct {
			Name string `json:"name"`
		}
		_ = c.ShouldBindJSON(&req)
		name := strings.TrimSpace(req.Name)
		if name == "" || len([]rune(name)) > deviceFieldMax {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "name must be 1-100 characters")
			return
		}
		res := db.Model(&models.Device{}).
			Where("user_id = ? AND device_id = ? AND revoked_at IS NULL", userID, c.Param("device_id")).
			Update("name", name)
		if res.Error != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to rename device")
			return
		}
		if res.RowsAffected == 0 {
			Error(c, http.StatusNotFound, "NOT_FOUND", "device not found")
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// revokeDevices signs the given devices out: marks them revoked and revokes their refresh tokens.
func revokeDevices(tx *gorm.DB, userID uuid.UUID, deviceIDs []string) error {
	now := time.Now()
	if err := tx.Model(&models.Device{}).
		Where("user_id = ? AND device_id IN ? AND revoked_at IS NULL", userID, deviceIDs).
		Update("revoked_at", now).Error; err != nil {
		return err
	}
	return tx.Model(&models.RefreshToken{}).
		Where("user_id = ? AND device_id IN ? AND revoked_at IS NULL", userID, deviceIDs).
		Update("revoked_at", now).Error
}

// HandleRevokeDevice signs out one other device of the user.
func HandleRevokeDevice(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(uuid.UUID)
		target := c.Param("device_id")
		if target == c.GetString("device_id") {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "use Sign out for this device")
			return
		}
		var n int64
		db.Model(&models.Device{}).Where("user_id = ? AND device_id = ? AND revoked_at IS NULL", userID, target).Count(&n)
		if n == 0 {
			Error(c, http.StatusNotFound, "NOT_FOUND", "device not found")
			return
		}
		if err := db.Transaction(func(tx *gorm.DB) error { return revokeDevices(tx, userID, []string{target}) }); err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to sign out device")
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// HandleRevokeOtherDevices signs out every device of the user except this one.
func HandleRevokeOtherDevices(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(uuid.UUID)
		current, ok := currentDevice(c)
		if !ok {
			return
		}
		var others []string
		if err := db.Model(&models.Device{}).
			Where("user_id = ? AND device_id <> ? AND revoked_at IS NULL", userID, current).
			Pluck("device_id", &others).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to sign out devices")
			return
		}
		if len(others) > 0 {
			if err := db.Transaction(func(tx *gorm.DB) error { return revokeDevices(tx, userID, others) }); err != nil {
				Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to sign out devices")
				return
			}
		}
		Success(c, http.StatusOK, gin.H{"revoked": len(others)})
	}
}
