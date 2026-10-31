package database

import (
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
)

func TestDialectorForSelectsDriver(t *testing.T) {
	tests := []struct {
		name    string
		dsn     string
		want    string
		wantDSN string
		wantErr string
	}{
		{name: "sqlite relative path", dsn: "sqlite://terra.db", want: "sqlite", wantDSN: "terra.db"},
		{name: "sqlite absolute path", dsn: "sqlite:///data/terra.db", want: "sqlite", wantDSN: "/data/terra.db"},
		{name: "sqlite options preserved", dsn: "sqlite://teams.db?cache=shared&_fk=1", want: "sqlite", wantDSN: "teams.db?cache=shared&_fk=1"},
		{name: "plain sqlite path", dsn: "terra.db", want: "sqlite", wantDSN: "terra.db"},
		{name: "postgres url", dsn: "postgres://user:pass@localhost:5432/terra", want: "postgres"},
		{name: "postgresql url", dsn: "postgresql://user:pass@localhost:5432/terra", want: "postgres"},
		{name: "unsupported scheme", dsn: "mysql://user:pass@localhost:3306/terra", wantErr: "unsupported database URL scheme"},
		{name: "empty url", dsn: "", wantErr: "database URL is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dialectorFor(tt.dsn)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("dialectorFor(%q) error = nil, want %q", tt.dsn, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("dialectorFor(%q) error = %q, want it to contain %q", tt.dsn, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("dialectorFor(%q) error = %v", tt.dsn, err)
			}
			if got.Name() != tt.want {
				t.Fatalf("dialectorFor(%q).Name() = %q, want %q", tt.dsn, got.Name(), tt.want)
			}
			if tt.wantDSN != "" {
				dialector, ok := got.(*sqlite.Dialector)
				if !ok {
					t.Fatalf("dialectorFor(%q) = %T, want *sqlite.Dialector", tt.dsn, got)
				}
				if dialector.DSN != tt.wantDSN {
					t.Fatalf("dialectorFor(%q).DSN = %q, want %q", tt.dsn, dialector.DSN, tt.wantDSN)
				}
			}
		})
	}
}

func TestOpenSQLite(t *testing.T) {
	db, err := Open("sqlite://:memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB() error = %v", err)
	}
	defer sqlDB.Close()

	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("ping error = %v", err)
	}
}
