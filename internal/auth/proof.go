package auth

import (
	"encoding/base64"
	"net/http"

	"github.com/nhridoy/shetu-server/internal/models"
	"gorm.io/gorm"
)

// verifyPasswordProof checks a login-style proof against the user's stored
// verifier and consumes the nonce. It returns status 0 on success.
func verifyPasswordProof(db *gorm.DB, user *models.User, proofB64, nonceB64 string) (int, string, string) {
	if user.AuthVerifier == nil {
		return http.StatusUnauthorized, "UNAUTHORIZED", "no verifier set"
	}
	proofBytes, err := base64.RawStdEncoding.DecodeString(proofB64)
	if err != nil {
		return http.StatusUnauthorized, "UNAUTHORIZED", "invalid old proof"
	}
	nonceBytes, err := base64.RawStdEncoding.DecodeString(nonceB64)
	if err != nil {
		return http.StatusUnauthorized, "UNAUTHORIZED", "invalid old nonce"
	}
	if !consumeLoginNonce(db, user.Email, nonceB64) {
		return http.StatusUnauthorized, "UNAUTHORIZED", "invalid old nonce"
	}
	verifierBytes, err := base64.RawStdEncoding.DecodeString(*user.AuthVerifier)
	if err != nil {
		return http.StatusUnauthorized, "UNAUTHORIZED", "invalid stored verifier"
	}
	if !ConstantTimeCompare(proofBytes, GenerateProof(verifierBytes, nonceBytes)) {
		return http.StatusForbidden, "FORBIDDEN", "current password is incorrect"
	}
	return 0, "", ""
}
