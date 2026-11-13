package email

import (
	"testing"
	"time"
)

func TestSendOtp_DisabledWithoutFallback_Errors(t *testing.T) {
	s := New("", 587, "", "", "", false)
	if s.Enabled() {
		t.Fatal("expected disabled sender when host empty")
	}
	if err := s.SendOtp("user@example.com", "123456"); err == nil {
		t.Fatal("disabled sender without log fallback must refuse to deliver the code")
	}
}

func TestSendOtp_DisabledWithFallback_LogsAndSucceeds(t *testing.T) {
	s := New("", 587, "", "", "", true)
	if s.Enabled() {
		t.Fatal("expected disabled sender when host empty")
	}
	if err := s.SendOtp("user@example.com", "123456"); err != nil {
		t.Fatalf("log fallback should not error: %v", err)
	}
}

func TestNew_DefaultPort(t *testing.T) {
	s := New("smtp.example.com", 587, "u", "p", "no-reply@example.com", false)
	if !s.Enabled() {
		t.Fatal("expected enabled sender when host set")
	}
	if s.Port != 587 || s.Username != "u" || s.From != "no-reply@example.com" || s.LogOtpFallback {
		t.Fatalf("sender fields not preserved: %+v", s)
	}
}

func TestSendAccountDeletionNotice_DisabledReturnsError(t *testing.T) {
	s := New("", 587, "", "", "", false)
	if err := s.SendAccountDeletionNotice("user@example.com", time.Now()); err == nil {
		t.Fatal("disabled sender must return an error")
	}
}
