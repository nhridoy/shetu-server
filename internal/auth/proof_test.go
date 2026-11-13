package auth

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/nhridoy/shetu-server/internal/models"
)

func proofFor(verifier []byte, nonceB64 string) string {
	n, _ := base64.RawStdEncoding.DecodeString(nonceB64)
	return base64.RawStdEncoding.EncodeToString(GenerateProof(verifier, n))
}

func TestVerifyPasswordProof_Valid(t *testing.T) {
	db := setupTestDB(t)
	id, verifier := seedUserWithVerifier(t, db, "a@example.com")
	var user models.User
	db.First(&user, "id = ?", id)
	nonce := base64.RawStdEncoding.EncodeToString([]byte("nonce-bytes-1234"))
	seedLoginNonce(t, db, user.Email, nonce)
	proof := proofFor(verifier, nonce)

	if status, code, msg := verifyPasswordProof(db, &user, proof, nonce); status != 0 {
		t.Fatalf("want success, got %d %s %s", status, code, msg)
	}
	status, _, msg := verifyPasswordProof(db, &user, proof, nonce)
	if status != http.StatusUnauthorized || msg != "invalid old nonce" {
		t.Fatalf("replay: got %d %q", status, msg)
	}
}

func TestVerifyPasswordProof_WrongProof(t *testing.T) {
	db := setupTestDB(t)
	id, _ := seedUserWithVerifier(t, db, "b@example.com")
	var user models.User
	db.First(&user, "id = ?", id)
	nonce := base64.RawStdEncoding.EncodeToString([]byte("nonce-bytes-1234"))
	seedLoginNonce(t, db, user.Email, nonce)
	proof := proofFor([]byte("wrong-verifier"), nonce)

	status, code, _ := verifyPasswordProof(db, &user, proof, nonce)
	if status != http.StatusForbidden || code != "FORBIDDEN" {
		t.Fatalf("got %d %s", status, code)
	}
}

func TestVerifyPasswordProof_NoVerifier(t *testing.T) {
	db := setupTestDB(t)
	user := models.User{Email: "c@example.com"}
	status, _, msg := verifyPasswordProof(db, &user, "", "")
	if status != http.StatusUnauthorized || msg != "no verifier set" {
		t.Fatalf("got %d %q", status, msg)
	}
}
