package main

import (
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
	"time"

	gosmtp "github.com/emersion/go-smtp"
	jmap "git.sr.ht/~rockorager/go-jmap"
	jmapserver "github.com/yno9/go-jmapserver"
	"biset/vault"
)

// ── config ────────────────────────────────────────────────────────────────────

type Config struct {
	jmapserver.Config
	Address      string `json:"address"`
	Domain       string `json:"domain"`
	SMTPPort     int    `json:"smtp_port"`    // SMTP receive port (default 25)
	RelayHost    string `json:"relay_host"`   // optional outbound relay; empty = direct MX
	DKIMSelector string `json:"dkim_selector"` // DNS: <selector>._domainkey.<domain>
}

var cfg Config

// ── handler ───────────────────────────────────────────────────────────────────

type handler struct {
	store *jmapserver.Store
	hub   *jmapserver.Hub
}

func (h *handler) Capabilities() []jmap.URI {
	return []jmap.URI{
		"urn:ietf:params:jmap:mail",
		"urn:ietf:params:jmap:submission",
	}
}

func (h *handler) Accounts() []jmapserver.Account {
	return []jmapserver.Account{{ID: jmap.ID(cfg.Address), Name: cfg.Address}}
}

func (h *handler) Handle(method string, args json.RawMessage) (any, error) {
	switch method {
	case "Email/query":
		return h.emailQuery(args)
	case "Email/queryChanges":
		return h.store.HandleQueryChanges(jmap.ID(cfg.Address), args)
	case "Email/changes":
		return h.store.HandleEmailChanges(jmap.ID(cfg.Address), args)
	case "Email/get":
		return h.store.HandleEmailGet(jmap.ID(cfg.Address), args)
	case "Thread/get":
		return h.store.HandleThreadGet(jmap.ID(cfg.Address), args)
	case "Mailbox/get":
		return h.store.HandleMailboxGet(jmap.ID(cfg.Address), args)
	case "Mailbox/changes":
		return h.store.HandleMailboxChanges(jmap.ID(cfg.Address), args)
	case "Identity/get":
		return h.store.HandleIdentityGet(jmap.ID(cfg.Address))
	case "Identity/changes":
		return h.store.HandleIdentityChanges(jmap.ID(cfg.Address), args)
	case "Thread/changes":
		return h.store.HandleThreadChanges(jmap.ID(cfg.Address), args)
	case "Email/set":
		return h.emailSet(args)
	case "EmailSubmission/set":
		return h.emailSubmissionSet(args)
	default:
		return h.store.Dispatch(jmap.ID(cfg.Address), method, args)
	}
}

// ── Email/query ───────────────────────────────────────────────────────────────

func (h *handler) emailQuery(args json.RawMessage) (any, error) {
	for _, m := range drainBuffer() {
		h.store.Put(m) //nolint:errcheck
	}
	return h.store.HandleEmailQuery(jmap.ID(cfg.Address), args)
}

// ── Email/set ─────────────────────────────────────────────────────────────────

func (h *handler) emailSet(args json.RawMessage) (any, error) {
	var req struct {
		Create map[jmap.ID]json.RawMessage `json:"create"`
		Update map[jmap.ID]json.RawMessage `json:"update"`
	}
	json.Unmarshal(args, &req) //nolint:errcheck

	created := map[jmap.ID]any{}
	notCreated := map[jmap.ID]any{}
	updated := map[jmap.ID]any{}
	notUpdated := map[jmap.ID]any{}

	for key, rawMsg := range req.Create {
		var msg vault.Message
		if err := json.Unmarshal(rawMsg, &msg); err != nil {
			notCreated[key] = errObj("invalidProperties", err.Error())
			continue
		}
		if msg.ID == "" {
			msg.ID = newID()
		}
		receivedAt := time.Now().UTC()
		msg.ReceivedAt = &receivedAt
		h.store.PutPending(msg)
		created[key] = map[string]any{"id": msg.ID, "receivedAt": receivedAt.Format(time.RFC3339Nano)}
	}

	for msgID, rawPatch := range req.Update {
		var patch map[string]any
		if err := json.Unmarshal(rawPatch, &patch); err != nil {
			notUpdated[msgID] = errObj("invalidProperties", err.Error())
			continue
		}
		if err := h.store.PatchKeywords(msgID, patch); err != nil {
			log.Printf("store patch %s: %v", msgID, err)
		}
		updated[msgID] = map[string]any{}
	}

	return map[string]any{
		"accountId":    jmap.ID(cfg.Address),
		"oldState":     "0",
		"newState":     "1",
		"created":      created,
		"updated":      updated,
		"destroyed":    []jmap.ID{},
		"notCreated":   notCreated,
		"notUpdated":   notUpdated,
		"notDestroyed": map[string]any{},
	}, nil
}

// ── EmailSubmission/set ───────────────────────────────────────────────────────

func (h *handler) emailSubmissionSet(args json.RawMessage) (any, error) {
	var req struct {
		Create map[jmap.ID]struct {
			EmailID  jmap.ID         `json:"emailId"`
			Envelope *vault.Envelope `json:"envelope"`
		} `json:"create"`
	}
	json.Unmarshal(args, &req) //nolint:errcheck

	created := map[jmap.ID]any{}
	notCreated := map[jmap.ID]any{}

	for key, sub := range req.Create {
		msg, ok := h.store.TakePending(sub.EmailID)
		if !ok {
			msg, ok = h.store.Get(sub.EmailID)
		}
		if !ok {
			notCreated[key] = errObj("notFound", fmt.Sprintf("email %q not found", sub.EmailID))
			continue
		}
		if sub.Envelope == nil {
			notCreated[key] = errObj("invalidProperties", "envelope required")
			continue
		}
		if err := sendEmail(msg, *sub.Envelope); err != nil {
			notCreated[key] = errObj("serverFail", err.Error())
			continue
		}
		created[key] = map[string]any{
			"id":         newID(),
			"sendAt":     time.Now().UTC().Format(time.RFC3339),
			"undoStatus": "final",
		}
	}

	return map[string]any{
		"accountId":    jmap.ID(cfg.Address),
		"oldState":     "0",
		"newState":     "1",
		"created":      created,
		"notCreated":   notCreated,
		"updated":      map[string]any{},
		"notUpdated":   map[string]any{},
		"destroyed":    []string{},
		"notDestroyed": map[string]any{},
	}, nil
}

// ── incoming buffer ───────────────────────────────────────────────────────────

var bufCh = make(chan vault.Message, 256)

func bufferEmail(e vault.Message) {
	select {
	case bufCh <- e:
	default:
		log.Printf("incoming buffer full, dropping message %s", e.ID)
	}
}

func drainBuffer() []vault.Message {
	var out []vault.Message
	for {
		select {
		case m := <-bufCh:
			out = append(out, m)
		default:
			return out
		}
	}
}

// ── SMTP server ───────────────────────────────────────────────────────────────

type backend struct{ hub *jmapserver.Hub }

func (b *backend) NewSession(_ *gosmtp.Conn) (gosmtp.Session, error) {
	return &session{hub: b.hub}, nil
}

type session struct {
	hub  *jmapserver.Hub
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
	s.hub.Notify()
	return nil
}

func (s *session) Reset()        { s.from = ""; s.to = nil }
func (s *session) Logout() error { return nil }

func startSMTP(hub *jmapserver.Hub) {
	port := cfg.SMTPPort
	if port == 0 {
		port = 25
	}
	srv := gosmtp.NewServer(&backend{hub: hub})
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

// ── helpers ───────────────────────────────────────────────────────────────────

func errObj(typ, desc string) map[string]string {
	return map[string]string{"type": typ, "description": desc}
}

func newID() jmap.ID {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return jmap.ID(fmt.Sprintf("srv-%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b)))
}

// ── entry point ───────────────────────────────────────────────────────────────

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
	loadOrGenerateDKIMKey(dir)
	selector := cfg.DKIMSelector
	if selector == "" {
		selector = "biset"
	}
	writeDKIMRecordFile(dir, selector, cfg.Domain)

	store, err := jmapserver.NewStore(filepath.Join(dir, "data"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	hub := jmapserver.NewHub()
	h := &handler{store: store, hub: hub}
	store.PutMailboxes([]vault.Inbox{vault.DefaultInbox(cfg.Address)}) //nolint:errcheck

	go startSMTP(hub)

	log.Printf("smtp-host: jmap listening on %s:%d", cfg.Bind, cfg.Port)
	log.Fatal(jmapserver.Serve(cfg.Config, h, hub))
}
