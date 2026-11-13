package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                   uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	Email                string     `gorm:"uniqueIndex:idx_users_email;not null" json:"email"`
	FullName             string     `gorm:"not null" json:"full_name"`
	AvatarURL            string     `gorm:"not null;default:''" json:"avatar_url,omitempty"`
	AuthProvider         string     `gorm:"not null;default:'password'" json:"auth_provider"`
	ProviderSub          *string    `gorm:"uniqueIndex:idx_users_auth_provider_provider_sub" json:"provider_sub,omitempty"`
	AuthVerifier         *string    `json:"-"`
	AuthSalt             *string    `json:"-"`
	SaltCL               *string    `json:"salt_cl,omitempty"`
	KDFM                 int        `gorm:"not null;default:67108864" json:"kdf_m"`
	KDFT                 int        `gorm:"not null;default:3" json:"kdf_t"`
	KDFP                 int        `gorm:"not null;default:1" json:"kdf_p"`
	PublicKey            *string    `json:"public_key,omitempty"`
	RecoveryHash         *string    `json:"-"`
	Initialized          bool       `gorm:"not null;default:false" json:"initialized"`
	LastLoginAt          *time.Time `json:"last_login_at,omitempty"`
	EmailVerifiedAt      *time.Time `json:"email_verified_at,omitempty"`
	DeletionScheduledFor *time.Time `json:"deletion_scheduled_for,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

func (User) TableName() string {
	return "users"
}
