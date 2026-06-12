package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SMTPConfig holds SMTP connection settings.
type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	TLSMode  string `json:"tls_mode"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func sendSMTP(cfg SMTPConfig, from string, to, cc, bcc []string, subject, body, inReplyTo string) ([]byte, error) {
	msgID := newMessageID(from)
	raw := buildMessage(from, to, cc, subject, body, msgID, inReplyTo)
	rcpts := append(append(to, cc...), bcc...)
	if err := smtpSend(cfg, from, rcpts, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func smtpSend(cfg SMTPConfig, from string, to []string, raw []byte) error {
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	switch cfg.TLSMode {
	case "tls":
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: cfg.Host})
		if err != nil {
			return fmt.Errorf("tls dial: %w", err)
		}
		c, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return err
		}
		defer c.Close()
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		return sendData(c, from, to, raw)
	case "plain":
		c, err := smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("dial: %w", err)
		}
		defer c.Close()
		return sendData(c, from, to, raw)
	default: // starttls
		conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
		if err != nil {
			return fmt.Errorf("dial: %w", err)
		}
		c, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return err
		}
		defer c.Close()
		if err := c.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		return sendData(c, from, to, raw)
	}
}

func sendData(c *smtp.Client, from string, to []string, raw []byte) error {
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func buildMessage(from string, to, cc []string, subject, body, msgID, inReplyTo string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	if len(cc) > 0 {
		b.WriteString("Cc: " + strings.Join(cc, ", ") + "\r\n")
	}
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Message-ID: " + msgID + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	if inReplyTo != "" {
		b.WriteString("In-Reply-To: " + inReplyTo + "\r\n")
		b.WriteString("References: " + inReplyTo + "\r\n")
	}
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return []byte(b.String())
}

func newMessageID(addr string) string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	domain := addr
	if parts := strings.SplitN(addr, "@", 2); len(parts) == 2 {
		domain = parts[1]
	}
	return fmt.Sprintf("<%d.%s@%s>", time.Now().UnixMilli(), hex.EncodeToString(b), domain)
}

func splitAddrs(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a := strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}
