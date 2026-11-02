package auth

import (
	"testing"

	gormsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/nhridoy/terra-server/internal/models"
	"gorm.io/gorm"
)

func setupVerifyDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestGenerateOtp_IsSixDigits(t *testing.T) {
	for range 50 {
		otp, err := generateOtp()
		if err != nil {
			t.Fatal(err)
		}
		if len(otp) != 6 {
			t.Fatalf("expected 6 digits, got %q", otp)
		}
		for _, ch := range otp {
			if ch < '0' || ch > '9' {
				t.Fatalf("non-digit in otp %q", otp)
			}
		}
	}
}

func TestIssueEmailVerifyCode_ReplacesOldRow(t *testing.T) {
	db := setupVerifyDB(t)
	userID := uuid.New()
	first, err := issueEmailVerifyCode(db, userID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := issueEmailVerifyCode(db, userID)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("expected different otps")
	}
	var count int64
	db.Model(&models.AuthCode{}).Where("user_id = ? AND purpose = ?", userID, emailVerifyPurpose).Count(&count)
	if count != 1 {
		t.Fatalf("expected exactly 1 row after re-issue, got %d", count)
	}
	code, err := findEmailVerifyCode(db, userID)
	if err != nil {
		t.Fatal(err)
	}
	if code.CodeHash == second {
		t.Fatal("expected hashed code, got plaintext")
	}
}

func TestFindEmailVerifyCode_None(t *testing.T) {
	db := setupVerifyDB(t)
	_, err := findEmailVerifyCode(db, uuid.New())
	if err != gorm.ErrRecordNotFound {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}
}
