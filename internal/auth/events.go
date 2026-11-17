package auth

import (
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
	"github.com/nhridoy/shetu-server/internal/email"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

const (
	eventGroupWindow   = time.Hour
	maxGroupedIPs      = 20
	eventPageSize      = 50
	maxEventPageSize   = 100
	eventKindTwoFAFail = "two_factor_failed"
)

// Failed attempts are grouped per account and kind per hour, so a burst is one row.
var groupedEventKinds = map[string]bool{"sign_in_failed": true, eventKindTwoFAFail: true}

var emailedEventKinds = map[string]bool{
	"sign_in_new_device": true, "password_changed": true, "recovery_used": true,
	"device_revoked": true, "devices_revoked_others": true, eventKindTwoFAFail: true,
	"two_factor_enabled": true, "two_factor_disabled": true, "backup_code_used": true,
}

// deliverSecurityNotice emails the account owner in the background; tests replace it.
var deliverSecurityNotice = func(cfg *config.Config, to, kind, detail, ip string, at time.Time) {
	sender := email.New(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, cfg.LogOtpFallback)
	if !sender.Enabled() {
		return
	}
	go func() {
		// The error is not logged: SMTP errors often echo the recipient address.
		if sender.SendSecurityNotice(to, kind, detail, ip, at) != nil {
			slog.Warn("security notice not sent", "kind", kind)
		}
	}()
}

// recordEvent writes a security event and emails the owner for risky kinds. It never fails
// the request: errors are logged.
func recordEvent(c *gin.Context, db *gorm.DB, cfg *config.Config, userID uuid.UUID, kind, deviceID, detail string) {
	ip := c.ClientIP()
	now := time.Now()
	inserted := true
	var err error
	if groupedEventKinds[kind] {
		inserted, err = addGroupedEvent(db, userID, kind, deviceID, detail, ip, now)
	} else {
		err = db.Create(&models.SecurityEvent{UserID: userID, Kind: kind, Detail: detail, DeviceID: deviceID, IP: ip, IPs: ip, IPCount: 1, Count: 1, LastAt: now}).Error
	}
	if err != nil {
		slog.Warn("security event not recorded", "kind", kind, "error", err)
		return
	}
	// A wrong two-factor code emails once per account per hour: only when its row is new.
	if !emailedEventKinds[kind] || (kind == eventKindTwoFAFail && !inserted) {
		return
	}
	var user models.User
	if db.Select("email").First(&user, "id = ?", userID).Error != nil {
		return
	}
	deliverSecurityNotice(cfg, user.Email, kind, detail, ip, now)
}

// addGroupedEvent adds to this hour's row for the account and kind, or starts one.
func addGroupedEvent(db *gorm.DB, userID uuid.UUID, kind, deviceID, detail, ip string, now time.Time) (bool, error) {
	var rows []models.SecurityEvent
	if err := db.Where("user_id = ? AND kind = ? AND created_at > ?", userID, kind, now.Add(-eventGroupWindow)).
		Order("id DESC").Limit(1).Find(&rows).Error; err != nil {
		return false, err
	}
	if len(rows) == 0 {
		row := models.SecurityEvent{UserID: userID, Kind: kind, Detail: detail, DeviceID: deviceID, IP: ip, IPs: ip, IPCount: 1, Count: 1, LastAt: now}
		return true, db.Create(&row).Error
	}
	row := rows[0]
	ips := strings.Split(row.IPs, ",")
	if ip != "" && !slices.Contains(ips, ip) && len(ips) < maxGroupedIPs {
		ips = append(ips, ip)
	}
	return false, db.Model(&models.SecurityEvent{}).Where("id = ?", row.ID).Updates(map[string]any{
		"count":    gorm.Expr("count + 1"),
		"ip":       ip,
		"ips":      strings.Join(ips, ","),
		"ip_count": len(ips),
		"last_at":  now,
	}).Error
}

type securityEventView struct {
	ID            uint      `json:"id"`
	Kind          string    `json:"kind"`
	Detail        string    `json:"detail"`
	DeviceName    string    `json:"device_name"`
	Platform      string    `json:"platform"`
	IP            string    `json:"ip"`
	Count         int       `json:"count"`
	IPCount       int       `json:"ip_count"`
	CreatedAt     time.Time `json:"created_at"`
	LastAt        time.Time `json:"last_at"`
	CurrentDevice bool      `json:"current_device"`
}

// HandleListSecurityEvents pages the caller's security events, newest first. Device names come
// from the devices table at read time, so a rename shows in older entries too.
func HandleListSecurityEvents(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(uuid.UUID)
		limit := eventPageSize
		if n, err := strconv.Atoi(c.Query("limit")); err == nil && n > 0 {
			limit = min(n, maxEventPageSize)
		}
		q := db.Table("security_events AS e").
			Select("e.id, e.kind, e.detail, e.device_id, e.ip, e.count, e.ip_count, e.created_at, e.last_at, COALESCE(d.name, '') AS device_name, COALESCE(d.platform, '') AS platform").
			Joins("LEFT JOIN devices d ON d.user_id = e.user_id AND d.device_id = e.device_id AND e.device_id <> ''").
			Where("e.user_id = ?", userID)
		if before, err := strconv.ParseUint(c.Query("before"), 10, 64); err == nil {
			q = q.Where("e.id < ?", before)
		}
		var rows []struct {
			ID, Count, IPCount         int
			Kind, Detail, DeviceID, IP string
			DeviceName, Platform       string
			CreatedAt, LastAt          time.Time
		}
		if err := q.Order("e.id DESC").Limit(limit + 1).Scan(&rows).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list security events")
			return
		}
		var next *uint
		if len(rows) > limit {
			rows = rows[:limit]
			id := uint(rows[limit-1].ID)
			next = &id
		}
		current := c.GetString("device_id")
		events := make([]securityEventView, len(rows))
		for i, r := range rows {
			events[i] = securityEventView{
				ID: uint(r.ID), Kind: r.Kind, Detail: r.Detail, DeviceName: r.DeviceName, Platform: r.Platform,
				IP: r.IP, Count: r.Count, IPCount: r.IPCount, CreatedAt: r.CreatedAt, LastAt: r.LastAt,
				CurrentDevice: r.DeviceID != "" && r.DeviceID == current,
			}
		}
		Success(c, http.StatusOK, gin.H{"events": events, "next": next})
	}
}
