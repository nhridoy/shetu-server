package database

import (
	"errors"
	"fmt"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const sqlitePrefix = "sqlite://"

// Open connects to the database selected by DATABASE_URL.
//
// Supported forms:
//   - sqlite://path/to/terra.db (SQLite, used for local development)
//   - postgres://user:pass@host:5432/terra (PostgreSQL, used in production)
//   - postgresql://user:pass@host:5432/terra (alias)
//
// A bare path is treated as SQLite for backwards compatibility.
func Open(databaseURL string) (*gorm.DB, error) {
	dialector, err := dialectorFor(databaseURL)
	if err != nil {
		return nil, err
	}
	return gorm.Open(dialector, &gorm.Config{})
}

func dialectorFor(databaseURL string) (gorm.Dialector, error) {
	switch {
	case databaseURL == "":
		return nil, errors.New("database URL is empty")
	case strings.HasPrefix(databaseURL, "postgres://"), strings.HasPrefix(databaseURL, "postgresql://"):
		return postgres.Open(databaseURL), nil
	case strings.HasPrefix(databaseURL, sqlitePrefix):
		return sqlite.Open(strings.TrimPrefix(databaseURL, sqlitePrefix)), nil
	case strings.Contains(databaseURL, "://"):
		scheme, _, _ := strings.Cut(databaseURL, "://")
		return nil, fmt.Errorf("unsupported database URL scheme %q (supported: sqlite, postgres, postgresql)", scheme)
	default:
		return sqlite.Open(databaseURL), nil
	}
}
