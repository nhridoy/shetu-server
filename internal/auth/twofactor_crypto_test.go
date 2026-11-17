package auth

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestSealOpenRoundTrip(t *testing.T) {
	a, err := sealSecret(testKey(1), "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := sealSecret(testKey(1), "JBSWY3DPEHPK3PXP")
	if a == b {
		t.Fatal("two seals of the same secret must differ")
	}
	got, err := openSecret(testKey(1), a)
	if err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := openSecret(testKey(2), a); err == nil {
		t.Fatal("open with another key must fail")
	}
}

func TestMatchTOTP(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Shetu", AccountName: "a@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	secret := key.Secret()
	now := time.Unix(1_800_000_015, 0)
	step := now.Unix() / 30
	code, _ := totp.GenerateCode(secret, now)
	got, err := matchTOTP(secret, code, now, 0)
	if err != nil || got != step {
		t.Fatalf("now: step %d err %v", got, err)
	}
	for _, d := range []time.Duration{-30 * time.Second, 30 * time.Second} {
		c, _ := totp.GenerateCode(secret, now.Add(d))
		if _, err := matchTOTP(secret, c, now, 0); err != nil {
			t.Fatalf("drift %v refused: %v", d, err)
		}
	}
	for _, d := range []time.Duration{-60 * time.Second, 60 * time.Second} {
		c, _ := totp.GenerateCode(secret, now.Add(d))
		if c == code {
			continue
		}
		if _, err := matchTOTP(secret, c, now, 0); !errors.Is(err, errCodeInvalid) {
			t.Fatalf("drift %v: want invalid, got %v", d, err)
		}
	}
	if _, err := matchTOTP(secret, code, now, step); !errors.Is(err, errCodeReused) {
		t.Fatalf("reuse: want reused, got %v", err)
	}
	spaced := code[:3] + " " + code[3:]
	if _, err := matchTOTP(secret, spaced, now, 0); err != nil {
		t.Fatalf("spaced code refused: %v", err)
	}
}

func TestNewBackupCodes(t *testing.T) {
	plain, hashes, err := newBackupCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 10 || len(hashes) != 10 {
		t.Fatalf("want 10, got %d/%d", len(plain), len(hashes))
	}
	re := regexp.MustCompile(`^[a-z2-7]{4}-[a-z2-7]{4}$`)
	seen := map[string]bool{}
	for i, c := range plain {
		if !re.MatchString(c) {
			t.Fatalf("bad format %q", c)
		}
		if seen[c] {
			t.Fatalf("duplicate %q", c)
		}
		seen[c] = true
		if hashCode(strings.ToUpper(c)) != hashes[i] {
			t.Fatalf("hash mismatch for %q", c)
		}
	}
}

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[string]string{"123 456": "123456", "ABCD-efgh": "abcdefgh", " 12-34 ": "1234"} {
		if got := normalizeCode(in); got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
}
