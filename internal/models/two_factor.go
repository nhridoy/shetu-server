package models

import (
	"time"

	"github.com/google/uuid"
)

// TwoFactor holds an account's authenticator secret, sealed with the server's TWO_FACTOR_KEY.
// A row with EnabledAt nil is a setup in progress (PendingSecret set, Secret empty).
type TwoFactor struct {
	UserID        uuid.UUID  `gorm:"type:uuid;primaryKey;constraint:OnDelete:CASCADE" json:"-"`
	Secret        string     `gorm:"not null;default:''" json:"-"`
	PendingSecret string     `gorm:"not null;default:''" json:"-"`
	EnabledAt     *time.Time `json:"enabled_at,omitempty"`
	// The last accepted 30-second step; a code from it or earlier is refused (replay guard).
	LastStep  int64     `gorm:"not null;default:0" json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (TwoFactor) TableName() string { return "two_factors" }

type TwoFactorBackupCode struct {
	ID        uint       `gorm:"primaryKey;autoIncrement" json:"-"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE" json:"-"`
	CodeHash  string     `gorm:"not null" json:"-"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func (TwoFactorBackupCode) TableName() string { return "two_factor_backup_codes" }

// TwoFactorChallenge is a sign-in waiting for its second factor (Path login, oauth or recovery),
// or a recovery proof handed out after one (Path recovery_proof).
type TwoFactorChallenge struct {
	ID        uint       `gorm:"primaryKey;autoIncrement" json:"-"`
	TokenHash string     `gorm:"uniqueIndex:idx_two_factor_challenges_token_hash;not null" json:"-"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE" json:"-"`
	DeviceID  string     `gorm:"not null;default:''" json:"-"`
	Path      string     `gorm:"not null" json:"-"`
	Attempts  int        `gorm:"not null;default:0" json:"-"`
	ExpiresAt time.Time  `gorm:"not null;index" json:"-"`
	UsedAt    *time.Time `json:"-"`
	// Set on a recovery proof won with the emailed code: the recovery turns two-factor off.
	DisableTwoFactor bool      `gorm:"not null;default:false" json:"-"`
	CreatedAt        time.Time `json:"-"`
}

func (TwoFactorChallenge) TableName() string { return "two_factor_challenges" }
