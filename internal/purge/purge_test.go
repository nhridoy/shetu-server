package purge

import (
	"context"
	"testing"
	"time"

	gormsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var due = time.Date(2026, 12, 13, 10, 0, 0, 0, time.UTC)

const goneEmail = "gone@example.com"

var allTables = []string{
	"users", "user_keys", "refresh_tokens", "auth_codes", "login_nonces", "vaults", "teams",
	"team_members", "team_invites", "team_sync_operations", "vault_key_envelopes", "vault_rotations",
	"groups", "hosts", "keys", "snippets", "workspaces", "presets", "port_forwards", "session_history",
	"session_output_chunks", "session_preferences", "sync_changes", "sync_operations", "deleted_accounts",
}

var vaultTables = []string{
	"groups", "hosts", "keys", "snippets", "workspaces", "presets", "port_forwards", "session_history",
	"session_output_chunks", "session_preferences", "sync_changes", "sync_operations",
	"vault_key_envelopes", "vault_rotations",
}

type seeded struct {
	user, otherMember, thirdOwner uuid.UUID
	personalVault, sharedVault    uuid.UUID
	ownedTeam, thirdTeam          uuid.UUID
	thirdVault                    uuid.UUID
}

func openDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	// In-memory SQLite is per connection; the loop test reads from another goroutine.
	sqlDB.SetMaxOpenConns(1)
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func create(t *testing.T, db *gorm.DB, rows ...any) {
	t.Helper()
	for _, r := range rows {
		if err := db.Create(r).Error; err != nil {
			t.Fatalf("seed %T: %v", r, err)
		}
	}
}

// seedVaultRows puts one row in every vault-scoped table except envelopes.
func seedVaultRows(t *testing.T, db *gorm.DB, vaultID uuid.UUID) {
	t.Helper()
	sf := func() models.SessionSyncFields { return models.SessionSyncFields{ID: uuid.New(), VaultID: vaultID} }
	create(t, db,
		&models.Group{ID: uuid.New(), VaultID: vaultID},
		&models.Host{ID: uuid.New(), VaultID: vaultID},
		&models.Key{ID: uuid.New(), VaultID: vaultID},
		&models.Snippet{ID: uuid.New(), VaultID: vaultID},
		&models.Workspace{ID: uuid.New(), VaultID: vaultID},
		&models.Preset{ID: uuid.New(), VaultID: vaultID},
		&models.PortForward{ID: uuid.New(), VaultID: vaultID},
		&models.SessionHistory{SessionSyncFields: sf()},
		&models.SessionOutputChunk{SessionSyncFields: sf()},
		&models.SessionPreferences{SessionSyncFields: sf()},
		&models.SyncChange{VaultID: vaultID, TableName: "hosts", RecordID: uuid.New(), Envelope: "{}"},
		&models.SyncOperation{DeviceID: uuid.New(), OperationID: uuid.New(), VaultID: vaultID, Outcome: "{}"},
		&models.VaultRotation{ID: uuid.New(), VaultID: vaultID, OperationID: uuid.New(), State: "staged"},
	)
}

func envelope(vaultID, teamID, recipient uuid.UUID) *models.VaultKeyEnvelope {
	return &models.VaultKeyEnvelope{ID: uuid.New(), VaultID: vaultID, TeamID: teamID, Epoch: 1, RecipientUserID: recipient}
}

// seedRichUser builds a user scheduled for deletion at `at` who has a personal
// vault, owns a team with another member and a shared vault, and is a member of
// a third party's team.
func seedRichUser(t *testing.T, db *gorm.DB, at time.Time) seeded {
	t.Helper()
	s := seeded{
		user: uuid.New(), otherMember: uuid.New(), thirdOwner: uuid.New(),
		personalVault: uuid.New(), sharedVault: uuid.New(), thirdVault: uuid.New(),
		ownedTeam: uuid.New(), thirdTeam: uuid.New(),
	}
	create(t, db,
		&models.User{ID: s.user, Email: goneEmail, FullName: "Gone", DeletionScheduledFor: &at},
		&models.User{ID: s.otherMember, Email: "other@example.com", FullName: "Other"},
		&models.User{ID: s.thirdOwner, Email: "third@example.com", FullName: "Third"},

		// Personal vault.
		&models.Vault{ID: s.personalVault, OwnerID: s.user, Kind: "personal", Name: "mine", IsDefault: true},

		// Owned team: the user, another member, a shared vault, a pending invite.
		&models.Team{ID: s.ownedTeam, OwnerID: s.user, Name: "owned"},
		&models.TeamMember{ID: uuid.New(), TeamID: s.ownedTeam, UserID: s.user, Role: "owner", State: "active"},
		&models.TeamMember{ID: uuid.New(), TeamID: s.ownedTeam, UserID: s.otherMember, Role: "member", State: "active"},
		&models.Vault{ID: s.sharedVault, OwnerID: s.user, TeamID: &s.ownedTeam, Kind: "team", Name: "shared", RotationState: "ready"},
		envelope(s.sharedVault, s.ownedTeam, s.user),
		envelope(s.sharedVault, s.ownedTeam, s.otherMember),
		&models.TeamInvite{ID: uuid.New(), TeamID: s.ownedTeam, RecipientUserID: uuid.New(), RecipientEmail: "invitee@example.com", Role: "member", State: "pending", InviterUserID: s.user},
		&models.TeamSyncOperation{UserID: s.user, OperationID: uuid.New(), Outcome: "{}"},

		// Third party's team the user belongs to.
		&models.Team{ID: s.thirdTeam, OwnerID: s.thirdOwner, Name: "third"},
		&models.TeamMember{ID: uuid.New(), TeamID: s.thirdTeam, UserID: s.thirdOwner, Role: "owner", State: "active"},
		&models.TeamMember{ID: uuid.New(), TeamID: s.thirdTeam, UserID: s.user, Role: "member", State: "active"},
		&models.Vault{ID: s.thirdVault, OwnerID: s.thirdOwner, TeamID: &s.thirdTeam, Kind: "team", Name: "theirs", RotationState: "ready"},
		envelope(s.thirdVault, s.thirdTeam, s.user),
		envelope(s.thirdVault, s.thirdTeam, s.thirdOwner),
		&models.TeamInvite{ID: uuid.New(), TeamID: s.thirdTeam, RecipientUserID: s.user, RecipientEmail: goneEmail, Role: "admin", State: "pending", InviterUserID: s.thirdOwner},

		// Credentials.
		&models.RefreshToken{UserID: s.user, TokenHash: "rt", DeviceID: "d", ExpiresAt: at.Add(time.Hour)},
		&models.UserKey{UserID: s.user, KeyType: "identity", Payload: "p"},
		&models.AuthCode{CodeHash: "ac", Purpose: "verify", UserID: s.user, DeviceID: "d", ExpiresAt: at.Add(time.Hour)},
		&models.LoginNonce{Email: goneEmail, NonceHash: "n1", ExpiresAt: at.Add(time.Hour)},
		&models.LoginNonce{Email: "third@example.com", NonceHash: "n2", ExpiresAt: at.Add(time.Hour)},
	)
	seedVaultRows(t, db, s.personalVault)
	seedVaultRows(t, db, s.sharedVault)
	seedVaultRows(t, db, s.thirdVault)
	return s
}

type check struct {
	table, where string
	args         []any
}

func count(t *testing.T, db *gorm.DB, table, where string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.Table(table).Where(where, args...).Count(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func tableCounts(t *testing.T, db *gorm.DB) map[string]int64 {
	t.Helper()
	counts := map[string]int64{}
	for _, table := range allTables {
		counts[table] = count(t, db, table, "1 = 1")
	}
	return counts
}

func TestPurgeRemovesEverything(t *testing.T) {
	db := openDB(t)
	s := seedRichUser(t, db, due)

	n, err := PurgeDue(db, due.Add(time.Second))
	if err != nil || n != 1 {
		t.Fatalf("PurgeDue = %d, %v; want 1, nil", n, err)
	}

	gone := []uuid.UUID{s.personalVault, s.sharedVault}
	checks := []check{
		{"users", "id = ?", []any{s.user}},
		{"user_keys", "user_id = ?", []any{s.user}},
		{"refresh_tokens", "user_id = ?", []any{s.user}},
		{"auth_codes", "user_id = ?", []any{s.user}},
		{"login_nonces", "email = ?", []any{goneEmail}},
		{"team_sync_operations", "user_id = ?", []any{s.user}},
		{"vaults", "owner_id = ? OR id IN ? OR team_id = ?", []any{s.user, gone, s.ownedTeam}},
		{"teams", "owner_id = ? OR id = ?", []any{s.user, s.ownedTeam}},
		{"team_members", "user_id = ? OR team_id = ?", []any{s.user, s.ownedTeam}},
		{"team_invites", "team_id = ? OR recipient_user_id = ? OR inviter_user_id = ? OR recipient_email = ?", []any{s.ownedTeam, s.user, s.user, goneEmail}},
		{"vault_key_envelopes", "recipient_user_id = ? OR team_id = ? OR vault_id IN ?", []any{s.user, s.ownedTeam, gone}},
	}
	for _, table := range vaultTables {
		checks = append(checks, check{table, "vault_id IN ?", []any{gone}})
	}
	for _, c := range checks {
		if n := count(t, db, c.table, c.where, c.args...); n != 0 {
			t.Errorf("%s: %d rows still reference the purged user", c.table, n)
		}
	}

	var tomb models.DeletedAccount
	if err := db.Where("user_id = ?", s.user).Take(&tomb).Error; err != nil {
		t.Fatalf("deleted_accounts row: %v", err)
	}
	if !tomb.DeletedAt.Equal(due.Add(time.Second)) {
		t.Errorf("deleted_at = %v", tomb.DeletedAt)
	}

	// Other people keep their accounts, the third party keeps its team.
	for _, id := range []uuid.UUID{s.otherMember, s.thirdOwner} {
		if count(t, db, "users", "id = ?", id) != 1 {
			t.Errorf("user %s was deleted", id)
		}
	}
	if count(t, db, "teams", "id = ?", s.thirdTeam) != 1 {
		t.Error("third-party team was deleted")
	}
	if count(t, db, "team_members", "team_id = ? AND user_id = ? AND state = ?", s.thirdTeam, s.thirdOwner, "active") != 1 {
		t.Error("third-party team owner membership was touched")
	}
	if count(t, db, "vault_key_envelopes", "vault_id = ? AND recipient_user_id = ?", s.thirdVault, s.thirdOwner) != 1 {
		t.Error("third-party owner's envelope was deleted")
	}
	if count(t, db, "login_nonces", "email = ?", "third@example.com") != 1 {
		t.Error("someone else's login nonce was deleted")
	}
	for _, table := range vaultTables {
		if table == "vault_key_envelopes" {
			continue
		}
		if count(t, db, table, "vault_id = ?", s.thirdVault) != 1 {
			t.Errorf("%s: third-party vault row was deleted", table)
		}
	}
	var v models.Vault
	if err := db.Where("id = ?", s.thirdVault).Take(&v).Error; err != nil {
		t.Fatalf("third-party vault: %v", err)
	}
	if v.RotationState != "rotation_required" {
		t.Errorf("third-party vault rotation_state = %q, want rotation_required", v.RotationState)
	}
}

func TestPurgeSkipsUsersNotDue(t *testing.T) {
	db := openDB(t)
	seedRichUser(t, db, due)
	before := tableCounts(t, db)

	n, err := PurgeDue(db, due.Add(-time.Second))
	if err != nil || n != 0 {
		t.Fatalf("PurgeDue = %d, %v; want 0, nil", n, err)
	}
	after := tableCounts(t, db)
	for table, c := range before {
		if after[table] != c {
			t.Errorf("%s: %d rows before, %d after", table, c, after[table])
		}
	}
}

func TestPurgeRollsBackOnError(t *testing.T) {
	db := openDB(t)
	s := seedRichUser(t, db, due)
	if err := db.Exec(`CREATE TRIGGER fail_user_delete BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT, 'boom'); END;`).Error; err != nil {
		t.Fatal(err)
	}
	before := tableCounts(t, db)

	n, err := PurgeDue(db, due.Add(time.Second))
	if err == nil || n != 0 {
		t.Fatalf("PurgeDue = %d, %v; want 0 and an error", n, err)
	}
	after := tableCounts(t, db)
	for table, c := range before {
		if after[table] != c {
			t.Errorf("%s: %d rows before, %d after", table, c, after[table])
		}
	}
	var v models.Vault
	if err := db.Where("id = ?", s.thirdVault).Take(&v).Error; err != nil {
		t.Fatal(err)
	}
	if v.RotationState != "ready" {
		t.Errorf("third-party vault rotation not rolled back: %q", v.RotationState)
	}
	if count(t, db, "team_members", "team_id = ? AND user_id = ? AND state = ?", s.thirdTeam, s.user, "active") != 1 {
		t.Error("membership removal not rolled back")
	}
}

func TestPurgeIsIdempotent(t *testing.T) {
	db := openDB(t)
	seedRichUser(t, db, due)
	if n, err := PurgeDue(db, due); err != nil || n != 1 {
		t.Fatalf("first PurgeDue = %d, %v; want 1, nil", n, err)
	}
	if n, err := PurgeDue(db, due); err != nil || n != 0 {
		t.Fatalf("second PurgeDue = %d, %v; want 0, nil", n, err)
	}
}

func TestRunPurgeLoopRunsImmediately(t *testing.T) {
	db := openDB(t)
	// Due in the past so the loop's own time.Now() picks it up.
	s := seedRichUser(t, db, time.Now().Add(-time.Minute))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunPurgeLoop(ctx, db, time.Hour)
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for count(t, db, "deleted_accounts", "user_id = ?", s.user) == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("user not purged before the first tick")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunPurgeLoop did not return after cancel")
	}
}
