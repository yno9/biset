package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gosmtp "github.com/emersion/go-smtp"
	"biset/vault"
)

// ── config ────────────────────────────────────────────────────────────────────

type Config struct {
	Address      string `json:"address"`
	Domain       string `json:"domain"`
	Port         int    `json:"port"`
	RelayHost    string `json:"relay_host"`
	DKIMSelector string `json:"dkim_selector"` // DNS: <selector>._domainkey.<domain>
}

var cfg Config

// ── incoming buffer ───────────────────────────────────────────────────────────

var (
	bufMu    sync.Mutex
	incoming []vault.Message
)

func bufferEmail(e vault.Message) {
	bufMu.Lock()
	incoming = append(incoming, e)
	bufMu.Unlock()
}

func drainBuffer() []vault.Message {
	bufMu.Lock()
	out := incoming
	incoming = nil
	bufMu.Unlock()
	return out
}

// ── SMTP server ───────────────────────────────────────────────────────────────

type backend struct{}

func (b *backend) NewSession(_ *gosmtp.Conn) (gosmtp.Session, error) {
	return &session{}, nil
}

type session struct {
	from string
	to   []string
}

func (s *session) AuthPlain(_, _ string) error { return nil }

func (s *session) Mail(from string, _ *gosmtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *session) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return err
	}

	body, _ := io.ReadAll(msg.Body)
	subject := msg.Header.Get("Subject")
	messageID := msg.Header.Get("Message-Id")
	inReplyTo := msg.Header.Get("In-Reply-To")

	fromAddr := &vault.Address{Email: s.from}
	if addr, err := mail.ParseAddress(msg.Header.Get("From")); err == nil {
		fromAddr.Name = addr.Name
		fromAddr.Email = addr.Address
	}

	var to []*vault.Address
	for _, t := range s.to {
		to = append(to, &vault.Address{Email: t})
	}

	now := time.Now()
	mbxID := vault.MakeMailboxID(cfg.Address)
	e := vault.NewTextMessage(
		vault.MakeMessageID(messageID, cfg.Address, now),
		"",
		mbxID,
		[]*vault.Address{fromAddr},
		to, nil,
		subject,
		strings.TrimSpace(string(body)),
		now,
		inReplyTo,
	)

	bufferEmail(e)
	notify("mail")
	return nil
}

func (s *session) Reset()        { s.from = ""; s.to = nil }
func (s *session) Logout() error { return nil }

func startSMTP() {
	port := cfg.Port
	if port == 0 {
		port = 25
	}
	be := &backend{}
	srv := gosmtp.NewServer(be)
	srv.Addr = fmt.Sprintf(":%d", port)
	srv.Domain = cfg.Domain
	srv.AllowInsecureAuth = true
	srv.EnableSMTPUTF8 = true
	log.Printf("[smtp] listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("smtp: %v", err)
	}
}

// ── send ──────────────────────────────────────────────────────────────────────

func sendEmail(e vault.Message, env vault.Envelope) error {
	from := env.MailFrom.Email
	var toList []string
	for _, r := range env.RcptTo {
		toList = append(toList, r.Email)
	}
	if len(toList) == 0 {
		return fmt.Errorf("no recipients")
	}

	body := vault.MessageBody(e)
	raw := buildRaw(from, toList, e.Subject, body)
	raw = injectAutocryptHeader(raw, from)
	vaultDir := os.Getenv("BISET_VAULT")
	if len(toList) == 1 {
		raw = encryptMessage(raw, vaultDir, toList[0])
	}
	dkimSel := cfg.DKIMSelector
	if dkimSel == "" {
		dkimSel = "biset"
	}
	raw = signDKIM(raw, cfg.Domain, dkimSel)

	target := cfg.RelayHost
	if target == "" {
		toDomain := strings.SplitN(toList[0], "@", 2)[1]
		mxs, err := net.LookupMX(toDomain)
		if err != nil || len(mxs) == 0 {
			return fmt.Errorf("no MX for %s", toDomain)
		}
		target = strings.TrimSuffix(mxs[0].Host, ".") + ":25"
	}
	conn, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	c, err := smtp.NewClient(conn, strings.SplitN(target, ":", 2)[0])
	if err != nil {
		return err
	}
	defer c.Close()
	c.Hello(cfg.Domain)  //nolint:errcheck
	c.Mail(from)         //nolint:errcheck
	for _, to := range toList {
		c.Rcpt(to) //nolint:errcheck
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	w.Write(raw) //nolint:errcheck
	w.Close()    //nolint:errcheck
	c.Quit()     //nolint:errcheck
	return nil
}

func buildRaw(from string, to []string, subject, body string) []byte {
	domain := cfg.Domain
	if domain == "" {
		if parts := strings.SplitN(from, "@", 2); len(parts) == 2 {
			domain = parts[1]
		}
	}
	rnd := make([]byte, 6)
	rand.Read(rnd) //nolint:errcheck
	msgID := fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), hex.EncodeToString(rnd), domain)

	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-Id: " + msgID + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// ── JSON-RPC ──────────────────────────────────────────────────────────────────

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      *int64    `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
	Method  string    `json:"method,omitempty"`
	Params  any       `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var (
	outMu sync.Mutex
	enc   = json.NewEncoder(os.Stdout)
)

func respond(id *int64, result any, err error) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id}
	if err != nil {
		resp.Error = &rpcError{Code: -32000, Message: err.Error()}
	} else {
		resp.Result = result
	}
	outMu.Lock()
	enc.Encode(resp) //nolint:errcheck
	outMu.Unlock()
}

func notify(event string) {
	outMu.Lock()
	enc.Encode(rpcResponse{ //nolint:errcheck
		JSONRPC: "2.0",
		Method:  "notify",
		Params:  map[string]string{"event": event},
	})
	outMu.Unlock()
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("dir: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("config: %v", err)
	}

	loadPGPEntity()
	loadDKIMKey()
	selector := cfg.DKIMSelector
	if selector == "" {
		selector = "biset"
	}
	writeDKIMRecordFile(dir, selector, cfg.Domain)
	go startSMTP()

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var req rpcRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		go handleRequest(req)
	}
}

func handleRequest(req rpcRequest) {
	switch req.Method {
	case "ping":
		respond(req.ID, "pong", nil)

	case "fetch":
		emails := drainBuffer()
		respond(req.ID, map[string]any{
			"emails":    emails,
			"mailboxes": []any{},
		}, nil)

	case "send":
		var params struct {
			Email    vault.Message  `json:"email"`
			Envelope vault.Envelope `json:"envelope"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			respond(req.ID, nil, err)
			return
		}
		err := sendEmail(params.Email, params.Envelope)
		respond(req.ID, map[string]any{"ok": err == nil}, err)

	default:
		respond(req.ID, nil, fmt.Errorf("unknown method: %s", req.Method))
	}
}
