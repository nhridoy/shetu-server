package teams

import (
	"testing"

	gormsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

func TestRoleForActiveMembershipOnly(t *testing.T) {
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	teamID, userID := uuid.New(), uuid.New()
	member := models.TeamMember{ID: uuid.New(), TeamID: teamID, UserID: userID, Role: "admin", State: "pending"}
	if err := db.Create(&member).Error; err != nil {
		t.Fatal(err)
	}
	if role, err := RoleFor(db, teamID, userID); err != nil || role != "" {
		t.Fatalf("pending role=%q error=%v", role, err)
	}
	if err := db.Model(&member).Update("state", "active").Error; err != nil {
		t.Fatal(err)
	}
	if role, err := RoleFor(db, teamID, userID); err != nil || role != "admin" {
		t.Fatalf("active role=%q error=%v", role, err)
	}
	if role, err := RoleFor(db, teamID, uuid.New()); err != nil || role != "" {
		t.Fatalf("foreign role=%q error=%v", role, err)
	}
}
