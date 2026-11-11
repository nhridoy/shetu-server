package email

import (
	"fmt"
	"log/slog"
	"net/smtp"
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

	msg := []byte("From: " + s.From + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		html)

	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}
	if err := smtp.SendMail(addr, auth, s.From, []string{to}, msg); err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}
	return nil
}
