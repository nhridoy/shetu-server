package email

import (
	"crypto/tls"
	"errors"
	"fmt"
	"html"
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

// SendSecurityNotice tells the account owner about a security event (see securityNoticeBody).
func (s *Sender) SendSecurityNotice(to, kind, detail, ip string, at time.Time) error {
	if !s.Enabled() {
		return fmt.Errorf("email delivery is not configured (SMTP_HOST unset)")
	}
	subject, body := securityNoticeBody(kind, detail, ip, at)
	return s.send(to, subject, body)
}

func securityNoticeBody(kind, detail, ip string, at time.Time) (string, string) {
	const unexpected = "<p>If this wasn't you, change your password and sign out your other devices in Shetu.</p>"
	when := "<p>Time: " + html.EscapeString(at.UTC().Format("2 January 2006, 15:04")) + " UTC"
	if ip != "" {
		when += "<br>IP address: " + html.EscapeString(ip)
	}
	when += "</p>"
	subject, lead := "Shetu account activity", "<p>There was security activity on your Shetu account.</p>"
	switch kind {
	case "sign_in_new_device":
		subject, lead = "New sign-in to Shetu", "<p>A device that hasn't used your Shetu account before just signed in.</p>"
	case "password_changed":
		subject, lead = "Your Shetu password was changed", "<p>The password for your Shetu account was changed.</p>"
	case "recovery_used":
		subject, lead = "Your Shetu password was reset", "<p>Your Shetu password was reset with your recovery code, and all devices were signed out.</p>"
	case "device_revoked":
		subject, lead = "A device was signed out of Shetu", "<p>The device \""+html.EscapeString(detail)+"\" was signed out of your Shetu account from another device.</p>"
	case "devices_revoked_others":
		subject, lead = "Devices were signed out of Shetu", "<p>"+html.EscapeString(detail)+" other devices were signed out of your Shetu account.</p>"
	case "two_factor_failed":
		subject = "A Shetu two-factor code was wrong"
		switch detail {
		case "oauth":
			lead = "<p>Someone signed in with Google/GitHub but not your two-factor code.</p>"
		case "recovery":
			lead = "<p>Someone used your recovery code but not your two-factor code.</p>"
		default:
			lead = "<p>Someone entered your password but not your two-factor code.</p>"
		}
	case "two_factor_enabled":
		subject, lead = "Two-factor sign-in is on", "<p>Two-factor sign-in was turned on for your Shetu account.</p>"
	case "backup_code_used":
		subject, lead = "A Shetu backup code was used", "<p>One of your two-factor backup codes was just used.</p>"
	case "two_factor_disabled":
		subject, lead = "Two-factor sign-in is off", "<p>Two-factor sign-in was turned off for your Shetu account.</p>"
		if detail == "email" {
			lead = "<p>Two-factor sign-in was turned off for your Shetu account during a recovery-code reset, using a code sent to this address.</p>"
		}
	}
	return subject, lead + when + unexpected
}
