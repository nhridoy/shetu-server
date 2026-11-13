package email

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"time"
)

// Package vars so tests can shorten them.
var (
	dialTimeout    = 10 * time.Second
	sessionTimeout = 30 * time.Second
)

type Sender struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// LogOtpFallback logs verification codes to the server console when SMTP
	// is not configured. DEV ONLY — enabling this in production leaks codes
	// into logs. Off by default; the server refuses to enroll OTPs without
	// SMTP unless this is explicitly set.
	LogOtpFallback bool
}

func New(host string, port int, username, password, from string, logOtpFallback bool) *Sender {
	return &Sender{Host: host, Port: port, Username: username, Password: password, From: from, LogOtpFallback: logOtpFallback}
}

func (s *Sender) Enabled() bool {
	return s.Host != ""
}

func (s *Sender) SendOtp(to, code string) error {
	subject := "Your Shetu verification code"
	html := fmt.Sprintf("<p>Your Shetu verification code is:</p><p style=\"font-size:24px;font-weight:bold\">%s</p><p>It expires in 15 minutes.</p>", code)

	if !s.Enabled() {
		if !s.LogOtpFallback {
			return fmt.Errorf("email delivery is not configured (SMTP_HOST unset) and OTP log fallback is disabled")
		}
		slog.Info("verification otp (dev fallback, SMTP not configured)", "email", to, "code", code)
		return nil
	}

	return s.send(to, subject, html)
}

// send delivers an HTML message over SMTP.
func (s *Sender) send(to, subject, html string) error {
	msg := []byte("From: " + s.From + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		html)

	if err := s.deliver(to, msg); err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	return nil
}

// deliver is smtp.SendMail with a dial timeout and a deadline on the whole
// session, so a server that accepts but never answers cannot block forever.
func (s *Sender) deliver(to string, msg []byte) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", s.Host, s.Port), dialTimeout)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(sessionTimeout)); err != nil {
		conn.Close()
		return err
	}
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: s.Host}); err != nil {
			return err
		}
	}
	if s.Username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("smtp: server doesn't support AUTH")
		}
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(s.From); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (s *Sender) SendAccountDeletionNotice(to string, on time.Time) error {
	if !s.Enabled() {
		return fmt.Errorf("email delivery is not configured (SMTP_HOST unset)")
	}
	return s.send(to, "Your Shetu account will be deleted", deletionNoticeBody(on))
}

func deletionNoticeBody(on time.Time) string {
	return fmt.Sprintf("<p>Your Shetu account is scheduled for deletion on %s (UTC).</p><p>Sign in to Shetu before then to keep your account.</p>", on.UTC().Format("2 January 2006"))
}
