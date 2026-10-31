package models

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

const canonicalTimestampLayout = "2006-01-02T15:04:05.000Z"

// CanonicalUTCMillis is the sole datetime format used for synced rows and wire envelopes.
func CanonicalUTCMillis(value time.Time) string {
	return value.UTC().Format(canonicalTimestampLayout)
}

func parseLegacyTimestamp(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if n, err := strconv.ParseInt(value, 10, 64); err == nil {
		if len(value) <= 10 {
			return time.Unix(n, 0).UTC(), nil
		}
		return time.UnixMilli(n).UTC(), nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05.999999999-07:00:00",
		"2006-01-02 15:04:05-07:00:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp %q", value)
}

// MigrateTimestamps normalizes legacy SQLite datetime storage without changing encrypted payloads.
// It is safe to rerun after a partial or complete upgrade. Other databases
// never stored the legacy formats this migration targets.
func MigrateTimestamps(db *gorm.DB) error {
	if db.Dialector.Name() != "sqlite" {
		return nil
	}

	tables := map[string][]string{
		"vaults":                {"created_at", "updated_at", "deleted_at"},
		"groups":                {"created_at", "updated_at", "deleted_at"},
		"hosts":                 {"created_at", "updated_at", "deleted_at"},
		"keys":                  {"created_at", "updated_at", "deleted_at"},
		"snippets":              {"created_at", "updated_at", "deleted_at"},
		"workspaces":            {"created_at", "updated_at", "deleted_at"},
		"presets":               {"created_at", "updated_at", "deleted_at"},
		"port_forwards":         {"created_at", "updated_at", "deleted_at"},
		"session_history":       {"created_at", "updated_at", "deleted_at"},
		"session_output_chunks": {"created_at", "updated_at", "deleted_at"},
		"session_preferences":   {"created_at", "updated_at", "deleted_at"},
	}
	return db.Transaction(func(tx *gorm.DB) error {
		for table, columns := range tables {
			if !tx.Migrator().HasTable(table) {
				continue
			}
			for _, column := range columns {
				if !tx.Migrator().HasColumn(table, column) {
					continue
				}
				var rows []struct {
					ID        string
					Timestamp *string
				}
				if err := tx.Raw(fmt.Sprintf("SELECT CAST(id AS TEXT) AS id, CAST(%s AS TEXT) AS timestamp FROM %s WHERE %s IS NOT NULL", column, table, column)).Scan(&rows).Error; err != nil {
					return err
				}
				for _, row := range rows {
					if row.Timestamp == nil || *row.Timestamp == "" {
						continue
					}
					parsed, err := parseLegacyTimestamp(*row.Timestamp)
					if err != nil {
						return fmt.Errorf("%s.%s id=%s: %w", table, column, row.ID, err)
					}
					canonical := CanonicalUTCMillis(parsed)
					if canonical != *row.Timestamp {
						if err := tx.Exec(fmt.Sprintf("UPDATE %s SET %s = ? WHERE id = ?", table, column), canonical, row.ID).Error; err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	})
}
