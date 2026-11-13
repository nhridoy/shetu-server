package email

import (
	"net"
	"net/textproto"
	"strings"
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

func TestDeletionNoticeBody_UsesUTCDate(t *testing.T) {
	// 02:00 on the 14th in UTC+6 is still the 13th in UTC.
	on := time.Date(2026, 12, 14, 2, 0, 0, 0, time.FixedZone("UTC+6", 6*60*60))
	body := deletionNoticeBody(on)
	if !strings.Contains(body, "13 December 2026 (UTC)") {
		t.Fatalf("body = %q, want the UTC date marked (UTC)", body)
	}
}

// A server that accepts the connection but never greets must not block the
// sender forever.
func TestSend_StalledServerTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // hold the connection open, say nothing
		}
	}()
	old := sessionTimeout
	sessionTimeout = 200 * time.Millisecond
	defer func() { sessionTimeout = old }()

	port := ln.Addr().(*net.TCPAddr).Port
	s := New("127.0.0.1", port, "", "", "no-reply@example.com", false)
	done := make(chan error, 1)
	go func() { done <- s.send("user@example.com", "subject", "<p>hi</p>") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("send to a silent server must fail")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("send did not time out")
	}
}

// The deadline-bound client still speaks plain SMTP end to end.
func TestSend_DeliversToPlainServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tp := textproto.NewConn(c)
		var cmds []string
		tp.PrintfLine("220 test ready")
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return
			}
			cmds = append(cmds, line)
			switch verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0]); verb {
			case "EHLO":
				tp.PrintfLine("250 test")
			case "DATA":
				tp.PrintfLine("354 go")
				body, _ := tp.ReadDotLines()
				cmds = append(cmds, strings.Join(body, "\n"))
				tp.PrintfLine("250 queued")
			case "QUIT":
				tp.PrintfLine("221 bye")
				got <- cmds
				return
			default:
				tp.PrintfLine("250 ok")
			}
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	s := New("127.0.0.1", port, "", "", "no-reply@example.com", false)
	if err := s.send("user@example.com", "Hello", "<p>hi</p>"); err != nil {
		t.Fatal(err)
	}
	cmds := strings.Join(<-got, "\n")
	for _, want := range []string{"MAIL FROM:<no-reply@example.com>", "RCPT TO:<user@example.com>", "Subject: Hello", "<p>hi</p>", "QUIT"} {
		if !strings.Contains(cmds, want) {
			t.Errorf("session missing %q:\n%s", want, cmds)
		}
	}
}
