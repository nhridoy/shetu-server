package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	totpPeriod      = 30
	backupCodeCount = 10
)

var (
	errCodeInvalid = errors.New("two-factor code invalid")
	errCodeReused  = errors.New("two-factor code reused")
)

// nowFunc is the clock for code checks; tests pin it.
var nowFunc = time.Now

func sealSecret(key []byte, plain string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), nil)), nil
}

func openSecret(key []byte, sealed string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil || len(raw) < gcm.NonceSize() {
		return "", errors.New("sealed secret malformed")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New("sealed secret does not open with this key")
	}
	return string(plain), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("two-factor key: %w", err)
	}
	return cipher.NewGCM(block)
}

// matchTOTP checks code against the steps around now (±1 for clock drift) and returns the
// matching step. A step at or before lastStep was already used.
func matchTOTP(secret, code string, now time.Time, lastStep int64) (int64, error) {
	code = normalizeCode(code)
	if len(code) != 6 {
		return 0, errCodeInvalid
	}
	opts := totp.ValidateOpts{Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	current := now.Unix() / totpPeriod
	for step := current - 1; step <= current+1; step++ {
		want, err := totp.GenerateCodeCustom(secret, time.Unix(step*totpPeriod, 0), opts)
		if err != nil {
			return 0, errCodeInvalid
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			if step <= lastStep {
				return 0, errCodeReused
			}
			return step, nil
		}
	}
	return 0, errCodeInvalid
}

// newBackupCodes returns 10 single-use codes formatted xxxx-xxxx and their hashes.
func newBackupCodes() ([]string, []string, error) {
	plain := make([]string, 0, backupCodeCount)
	hashes := make([]string, 0, backupCodeCount)
	seen := map[string]bool{}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for len(plain) < backupCodeCount {
		raw := make([]byte, 5) // 40 bits → 8 base32 characters
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, fmt.Errorf("backup code: %w", err)
		}
		s := strings.ToLower(enc.EncodeToString(raw))
		code := s[:4] + "-" + s[4:]
		if seen[code] {
			continue
		}
		seen[code] = true
		plain = append(plain, code)
		hashes = append(hashes, hashCode(code))
	}
	return plain, hashes, nil
}

// normalizeCode drops spaces and dashes and lowercases, so "123 456" and "ABCD-EFGH" match.
func normalizeCode(s string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(s)))
}

func hashCode(s string) string {
	sum := sha256.Sum256([]byte(normalizeCode(s)))
	return base64.RawStdEncoding.EncodeToString(sum[:])
}
