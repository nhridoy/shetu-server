package teams

import (
	"testing"

	gormsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

func TestRemoveMemberTx(t *testing.T) {
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	teamID, owner, member := uuid.New(), uuid.New(), uuid.New()
	deleted := "2026-01-01T00:00:00.000Z"
	rows := []any{
		&models.TeamMember{ID: uuid.New(), TeamID: teamID, UserID: member, Role: "member", State: "active"},
		&models.TeamMember{ID: uuid.New(), TeamID: teamID, UserID: owner, Role: "owner", State: "active"},
		&models.Vault{ID: uuid.New(), OwnerID: owner, TeamID: &teamID, Kind: "team", Name: "live", Revision: 1, RotationState: "ready"},
		&models.Vault{ID: uuid.New(), OwnerID: owner, TeamID: &teamID, Kind: "team", Name: "gone", Revision: 1, RotationState: "ready", DeletedAt: &deleted},
	}
	for _, r := range rows {
		if err := db.Create(r).Error; err != nil {
			t.Fatal(err)
		}
	}
	const now = "2026-02-02T00:00:00.000Z"
	if err := RemoveMemberTx(db, teamID, member, now); err != nil {
		t.Fatal(err)
	}
	var m, o models.TeamMember
	db.Where("user_id = ?", member).Take(&m)
	db.Where("user_id = ?", owner).Take(&o)
	if m.State != "removed" || o.State != "active" {
		t.Fatalf("member=%s owner=%s", m.State, o.State)
	}
	var live, gone models.Vault
	db.Where("name = ?", "live").Take(&live)
	db.Where("name = ?", "gone").Take(&gone)
	if live.RotationState != "rotation_required" || live.Revision != 2 || live.UpdatedAt != now {
		t.Fatalf("live vault %+v", live)
	}
	if gone.RotationState != "ready" || gone.Revision != 1 {
		t.Fatalf("deleted vault touched %+v", gone)
	}
}
