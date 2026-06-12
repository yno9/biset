package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"biset/vault"
)

// ── config ────────────────────────────────────────────────────────────────────

type Config struct {
	Handle        string `json:"handle"`
	Domain        string `json:"domain"`
	Port          int    `json:"port"`
	Vault         string `json:"vault"`
	PrivateKeyPEM string `json:"private_key_pem"`
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

// ── keys ──────────────────────────────────────────────────────────────────────

var signingKey *rsa.PrivateKey

func loadOrGenerateKey() {
	// priority: env var > config field
	pemStr := os.Getenv("BISET_KEY_PEM")
	if pemStr == "" {
		pemStr = cfg.PrivateKeyPEM
	}
	if pemStr != "" {
		block, _ := pem.Decode([]byte(pemStr))
		if block != nil {
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if rk, ok := k.(*rsa.PrivateKey); ok {
					signingKey = rk
					return
				}
			}
		}
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	signingKey = k
	log.Printf("[ap] no key found — using ephemeral RSA key")
}

func publicKeyPEM() string {
	b, _ := x509.MarshalPKIXPublicKey(&signingKey.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}

// ── AP helpers ────────────────────────────────────────────────────────────────

var tagRe = regexp.MustCompile(`<[^>]+>`)
var mentionRe = regexp.MustCompile(`^(@\S+\s*)+`)

func apBase() string {
	scheme := "https"
	if strings.HasPrefix(cfg.Domain, "localhost") {
		scheme = "http"
	}
	return scheme + "://" + cfg.Domain
}

func identity() string { return cfg.Handle + "@" + cfg.Domain }
func actorURL() string { return apBase() + "/" + cfg.Handle }
func inboxURL() string { return actorURL() + "/inbox" }
func keyID() string    { return actorURL() + "#main-key" }

// ── receive ───────────────────────────────────────────────────────────────────

func handleInbox(body []byte) {
	var activity struct {
		Type   string          `json:"type"`
		Actor  string          `json:"actor"`
		Object json.RawMessage `json:"object"`
	}
	if err := json.Unmarshal(body, &activity); err != nil {
		return
	}
	if activity.Type != "Create" {
		return
	}

	var obj struct {
		Type      string `json:"type"`
		ID        string `json:"id"`
		Content   string `json:"content"`
		InReplyTo string `json:"inReplyTo"`
		Published string `json:"published"`
	}
	if err := json.Unmarshal(activity.Object, &obj); err != nil {
		return
	}
	if obj.Type != "Note" {
		return
	}

	text := tagRe.ReplaceAllString(obj.Content, "")
	text = strings.TrimSpace(text)
	text = mentionRe.ReplaceAllString(text, "")
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}

	from := actorURLToHandle(activity.Actor)
	if from == "" {
		from = activity.Actor
	}

	ts := time.Now()
	if obj.Published != "" {
		if t, err := time.Parse(time.RFC3339, obj.Published); err == nil {
			ts = t
		}
	}

	msgID := fmt.Sprintf("<%s@ap>", strings.ReplaceAll(obj.ID, "/", "-"))
	id := identity()
	mbxID := vault.MakeMailboxID(id)
	e := vault.NewTextMessage(
		vault.MakeMessageID(msgID, id, ts),
		"",
		mbxID,
		[]*vault.Address{{Email: from}},
		[]*vault.Address{{Email: id}}, nil,
		"",
		text,
		ts,
		obj.InReplyTo,
	)

	bufferEmail(e)
	notify("mail")
}

func actorURLToHandle(actorURL string) string {
	u, err := url.Parse(actorURL)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1] + "@" + u.Hostname()
}

// ── send ──────────────────────────────────────────────────────────────────────

type resolvedActor struct {
	actorURL string
	inboxURL string
}

var resolvedActorCache sync.Map

func resolveActor(handle string) (*resolvedActor, error) {
	if v, ok := resolvedActorCache.Load(handle); ok {
		return v.(*resolvedActor), nil
	}
	parts := strings.SplitN(handle, "@", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid handle: %q", handle)
	}
	wfURL := "https://" + parts[1] + "/.well-known/webfinger?resource=acct:" + handle
	resp, err := http.Get(wfURL) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("webfinger: %w", err)
	}
	defer resp.Body.Close()
	var wf struct {
		Links []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}
	json.NewDecoder(resp.Body).Decode(&wf) //nolint:errcheck
	var selfHref string
	for _, l := range wf.Links {
		if l.Rel == "self" {
			selfHref = l.Href
			break
		}
	}
	if selfHref == "" {
		return nil, fmt.Errorf("no self link for %s", handle)
	}
	req, _ := http.NewRequest("GET", selfHref, nil)
	req.Header.Set("Accept", "application/activity+json")
	aresp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("actor fetch: %w", err)
	}
	defer aresp.Body.Close()
	var actor struct {
		Inbox string `json:"inbox"`
	}
	json.NewDecoder(aresp.Body).Decode(&actor) //nolint:errcheck
	if actor.Inbox == "" {
		return nil, fmt.Errorf("no inbox for %s", handle)
	}
	ra := &resolvedActor{actorURL: selfHref, inboxURL: actor.Inbox}
	resolvedActorCache.Store(handle, ra)
	return ra, nil
}

func sendToActor(e vault.Message, env vault.Envelope) error {
	target := ""
	if len(env.RcptTo) > 0 {
		target = env.RcptTo[0].Email
	}
	if target == "" {
		return fmt.Errorf("no recipient")
	}

	resolved, err := resolveActor(target)
	if err != nil {
		return err
	}

	body := vault.MessageBody(e)
	ts := time.Now().UTC()
	noteID := fmt.Sprintf("%s/notes/%d", actorURL(), ts.UnixMilli())

	note := map[string]any{
		"@context":     "https://www.w3.org/ns/activitystreams",
		"type":         "Note",
		"id":           noteID,
		"attributedTo": actorURL(),
		"to":           []string{resolved.actorURL},
		"content":      "<p>" + htmlEscape(body) + "</p>",
		"published":    ts.Format(time.RFC3339),
	}
	if e.InReplyTo != nil && len(e.InReplyTo) > 0 {
		note["inReplyTo"] = e.InReplyTo[0]
	}

	createID := fmt.Sprintf("%s#create-%d", actorURL(), ts.UnixMilli())
	create := map[string]any{
		"@context":  "https://www.w3.org/ns/activitystreams",
		"type":      "Create",
		"id":        createID,
		"actor":     actorURL(),
		"to":        []string{resolved.actorURL},
		"object":    note,
		"published": ts.Format(time.RFC3339),
	}

	payload, err := json.Marshal(create)
	if err != nil {
		return err
	}

	return httpSignedPost(resolved.inboxURL, payload)
}

func httpSignedPost(targetURL string, body []byte) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	date := time.Now().UTC().Format(http.TimeFormat)
	hash := sha256.Sum256(body)
	digest := "SHA-256=" + base64.StdEncoding.EncodeToString(hash[:])

	signingString := strings.Join([]string{
		"(request-target): post " + u.Path,
		"host: " + u.Host,
		"date: " + date,
		"digest: " + digest,
	}, "\n")

	h := sha256.Sum256([]byte(signingString))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, h[:])
	if err != nil {
		return err
	}
	sigHeader := fmt.Sprintf(`keyId="%s",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="%s"`,
		keyID(), base64.StdEncoding.EncodeToString(sig))

	req, _ := http.NewRequest("POST", targetURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/activity+json")
	req.Header.Set("Date", date)
	req.Header.Set("Digest", digest)
	req.Header.Set("Signature", sigHeader)
	req.Header.Set("Host", u.Host)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s: %d %s", targetURL, resp.StatusCode, string(b))
	}
	return nil
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// ── HTTP server ───────────────────────────────────────────────────────────────

func startHTTP() {
	port := cfg.Port
	if port == 0 {
		port = 8080
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/webfinger", func(w http.ResponseWriter, r *http.Request) {
		resource := r.URL.Query().Get("resource")
		// resource = "acct:user@domain" — user may contain "@" (e.g. "y@4r.ma")
		// so split on the last "@" to get the host part
		acct := strings.TrimPrefix(resource, "acct:")
		lastAt := strings.LastIndex(acct, "@")
		if lastAt < 0 {
			http.Error(w, "not found", 404)
			return
		}
		user, host := acct[:lastAt], acct[lastAt+1:]
		if host != cfg.Domain || user != cfg.Handle {
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/jrd+json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"subject": "acct:" + identity(),
			"links": []map[string]string{{
				"rel":  "self",
				"type": "application/activity+json",
				"href": actorURL(),
			}},
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		parts := strings.Split(path, "/")

		// GET /<user> — actor
		if len(parts) == 1 && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/activity+json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"@context":          []string{"https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"},
				"type":              "Person",
				"id":                actorURL(),
				"preferredUsername": cfg.Handle,
				"inbox":             inboxURL(),
				"outbox":            actorURL() + "/outbox",
				"publicKey": map[string]string{
					"id":           keyID(),
					"owner":        actorURL(),
					"publicKeyPem": publicKeyPEM(),
				},
			})
			return
		}

		// POST /<user>/inbox
		if len(parts) == 2 && parts[1] == "inbox" && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if err := verifyHTTPSignature(r, body); err != nil {
				log.Printf("[ap] signature verification failed: %v", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			handleInbox(body)
			w.WriteHeader(202)
			return
		}

		http.NotFound(w, r)
	})

	addr := fmt.Sprintf(":%d", port)
	log.Printf("[ap] listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("ap http: %v", err)
	}
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

// ── inbox setup ──────────────────────────────────────────────────────────────

func ensureInbox() {
	vaultDir := cfg.Vault
	if vaultDir == "" {
		vaultDir = os.Getenv("BISET_VAULT")
	}
	if vaultDir == "" {
		return
	}
	vaultDir = strings.ReplaceAll(vaultDir, "~", os.Getenv("HOME"))
	inboxDir := filepath.Join(vaultDir, identity())
	if err := os.MkdirAll(inboxDir, 0755); err != nil {
		log.Printf("[ap] mkdir inbox: %v", err)
		return
	}
	newFile := filepath.Join(inboxDir, "_new.md")
	if _, err := os.Stat(newFile); os.IsNotExist(err) {
		content := "---\ncontact: \nprotocol: ap\nstatus: \n---\n"
		os.WriteFile(newFile, []byte(content), 0644) //nolint:errcheck
	}
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

	loadOrGenerateKey()
	ensureInbox()
	go startHTTP()

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
		err := sendToActor(params.Email, params.Envelope)
		respond(req.ID, map[string]any{"ok": err == nil}, err)

	default:
		respond(req.ID, nil, fmt.Errorf("unknown method: %s", req.Method))
	}
}
