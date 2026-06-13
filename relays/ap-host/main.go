package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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
	"strconv"
	"strings"
	"sync"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"biset/relays/core"
	"biset/vault"
)

// ── config ────────────────────────────────────────────────────────────────────

type Config struct {
	core.Config
	Domain        string `json:"domain"`
	PrivateKeyPEM string `json:"private_key_pem"`
	Vault         string `json:"vault"`
}

var cfg Config

// ── AP identity ───────────────────────────────────────────────────────────────

func apBase() string {
	if strings.HasPrefix(cfg.Domain, "localhost") {
		return "http://" + cfg.Domain
	}
	return "https://" + cfg.Domain
}

func identity() string { return cfg.RelayName + "@" + cfg.Domain }
func actorURL() string  { return apBase() + "/" + cfg.RelayName }
func inboxURL() string  { return actorURL() + "/inbox" }
func keyID() string     { return actorURL() + "#main-key" }

// ── keys ──────────────────────────────────────────────────────────────────────

var signingKey *rsa.PrivateKey

func loadOrGenerateKey() {
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

// ── handler ───────────────────────────────────────────────────────────────────

type handler struct {
	store *core.Store
}

func (h *handler) Capabilities() []jmap.URI {
	return []jmap.URI{
		"urn:ietf:params:jmap:mail",
		"urn:ietf:params:jmap:submission",
	}
}

func (h *handler) Accounts() []core.Account {
	return []core.Account{{ID: jmap.ID(identity()), Name: identity()}}
}

func (h *handler) Handle(method string, args json.RawMessage) (any, error) {
	switch method {
	case "Email/query":
		return h.emailQuery()
	case "Email/get":
		return h.emailGet(args)
	case "Mailbox/get":
		return h.mailboxGet()
	case "Email/set":
		return h.emailSet(args)
	case "EmailSubmission/set":
		return h.emailSubmissionSet(args)
	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}
}

func (h *handler) emailQuery() (any, error) {
	all := h.store.All()
	ids := make([]jmap.ID, len(all))
	for i, m := range all {
		ids[i] = m.ID
	}
	return map[string]any{
		"accountId":           jmap.ID(identity()),
		"queryState":          "0",
		"canCalculateChanges": false,
		"position":            0,
		"ids":                 ids,
		"total":               len(ids),
	}, nil
}

func (h *handler) emailGet(args json.RawMessage) (any, error) {
	var req struct {
		IDs []jmap.ID `json:"ids"`
	}
	json.Unmarshal(args, &req) //nolint:errcheck

	var list []vault.Message
	var notFound []jmap.ID
	for _, id := range req.IDs {
		if m, ok := h.store.Get(id); ok {
			list = append(list, m)
		} else {
			notFound = append(notFound, id)
		}
	}
	if list == nil {
		list = []vault.Message{}
	}
	if notFound == nil {
		notFound = []jmap.ID{}
	}
	return map[string]any{
		"accountId": jmap.ID(identity()),
		"state":     "0",
		"list":      list,
		"notFound":  notFound,
	}, nil
}

func feedsMailboxID() string { return vault.MakeMailboxID(identity() + "/feeds") }

func (h *handler) mailboxGet() (any, error) {
	return map[string]any{
		"accountId": jmap.ID(identity()),
		"state":     "0",
		"list": []any{
			vault.DefaultInbox(identity()),
			map[string]any{"id": feedsMailboxID(), "name": "feeds", "role": nil},
		},
		"notFound": []string{},
	}, nil
}

func (h *handler) emailSet(args json.RawMessage) (any, error) {
	var req struct {
		Create  map[jmap.ID]json.RawMessage `json:"create"`
		Update  map[jmap.ID]json.RawMessage `json:"update"`
		Destroy []jmap.ID                   `json:"destroy"`
	}
	json.Unmarshal(args, &req) //nolint:errcheck

	created := map[jmap.ID]any{}
	notCreated := map[jmap.ID]any{}
	updated := map[jmap.ID]any{}
	notUpdated := map[jmap.ID]any{}
	destroyed := []jmap.ID{}
	notDestroyed := map[jmap.ID]any{}

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

		if msg.MailboxIDs[jmap.ID(feedsMailboxID())] {
			target := ""
			if len(msg.To) > 0 && msg.To[0] != nil {
				target = msg.To[0].Email
			}
			if target == "" {
				notCreated[key] = errObj("invalidProperties", "missing to address for follow")
				continue
			}
			actID, err := sendFollow(target)
			if err != nil {
				notCreated[key] = errObj("serverFail", err.Error())
				continue
			}
			if msg.Keywords == nil {
				msg.Keywords = map[string]bool{}
			}
			msg.Keywords["$follow_pending"] = true
			if len(msg.MessageID) == 0 {
				msg.MessageID = []string{string(msg.ID)}
			}
			_ = actID
			if err := h.store.Put(msg); err != nil {
				notCreated[key] = errObj("serverFail", err.Error())
				continue
			}
			// Optimistically register so posts can be threaded immediately.
			if ra, err2 := resolveActor(target); err2 == nil {
				followedActors.Store(ra.actorURL, followEntry{handle: target, followMsgID: msg.ID})
			}
		} else {
			h.store.PutPending(msg)
		}
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

	for _, msgID := range req.Destroy {
		msg, ok := h.store.Get(msgID)
		if !ok {
			notDestroyed[msgID] = errObj("notFound", "not found")
			continue
		}
		if msg.MailboxIDs[jmap.ID(feedsMailboxID())] {
			target := ""
			if len(msg.To) > 0 && msg.To[0] != nil {
				target = msg.To[0].Email
			}
			if target != "" {
				if err := sendUnfollow(msg.ID, target); err != nil {
					log.Printf("[ap] unfollow %s: %v", target, err)
				}
			}
		}
		h.store.Delete(msgID)
		destroyed = append(destroyed, msgID)
	}

	return map[string]any{
		"accountId":    jmap.ID(identity()),
		"oldState":     "0",
		"newState":     "1",
		"created":      created,
		"updated":      updated,
		"destroyed":    destroyed,
		"notCreated":   notCreated,
		"notUpdated":   notUpdated,
		"notDestroyed": notDestroyed,
	}, nil
}

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

		target := ""
		if sub.Envelope != nil && len(sub.Envelope.RcptTo) > 0 && sub.Envelope.RcptTo[0] != nil {
			target = sub.Envelope.RcptTo[0].Email
		} else if len(msg.To) > 0 && msg.To[0] != nil {
			target = msg.To[0].Email
		}
		if target == "" {
			notCreated[key] = errObj("notFound", "no recipient")
			continue
		}

		if err := sendToActor(msg, target); err != nil {
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
		"accountId":    jmap.ID(identity()),
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

// ── receive (AP → store) ──────────────────────────────────────────────────────

var tagRe = regexp.MustCompile(`<[^>]+>`)
var mentionRe = regexp.MustCompile(`^(@\S+\s*)+`)

func handleInbox(body []byte, store *core.Store, hub *core.Hub) {
	var activity struct {
		Type   string          `json:"type"`
		Actor  string          `json:"actor"`
		Object json.RawMessage `json:"object"`
	}
	if err := json.Unmarshal(body, &activity); err != nil {
		return
	}

	switch activity.Type {
	case "Accept":
		handleAccept(activity.Actor, activity.Object, store, hub)
		return
	case "Create":
		handleCreate(activity.Actor, activity.Object, store, hub)
	default:
		log.Printf("[ap] inbox: unhandled activity type %q", activity.Type)
	}
}

func handleAccept(actor string, object json.RawMessage, store *core.Store, hub *core.Hub) {
	// Mark the follow record as accepted and register actor for feed routing.
	var obj struct {
		Type   string `json:"type"`
		Object string `json:"object"`
	}
	if err := json.Unmarshal(object, &obj); err != nil {
		return
	}
	if obj.Type != "Follow" {
		return
	}
	log.Printf("[ap] follow accepted by %s", actor)

	// Update keyword on matching follow record in store and register followEntry.
	for _, msg := range store.All() {
		if msg.MailboxIDs[jmap.ID(feedsMailboxID())] && len(msg.To) > 0 && msg.To[0] != nil {
			handle := msg.To[0].Email
			ra, err := resolveActor(handle)
			if err == nil && ra.actorURL == actor {
				patch := map[string]any{
					"keywords/$follow_pending":  nil,
					"keywords/$follow_accepted": true,
				}
				store.PatchKeywords(msg.ID, patch) //nolint:errcheck
				followedActors.Store(actor, followEntry{handle: handle, followMsgID: msg.ID})
				hub.Notify()
				break
			}
		}
	}
}

func handleCreate(actor string, object json.RawMessage, store *core.Store, hub *core.Hub) {
	var obj struct {
		Type      string `json:"type"`
		ID        string `json:"id"`
		Content   string `json:"content"`
		InReplyTo string `json:"inReplyTo"`
		Published string `json:"published"`
	}
	if err := json.Unmarshal(object, &obj); err != nil {
		return
	}
	if obj.Type != "Note" {
		return
	}

	text := tagRe.ReplaceAllString(obj.Content, "")
	text = strings.TrimSpace(text)

	// For DMs (mentions), strip leading @mentions.
	fe, isFollowed := followedActors.Load(actor)
	if !isFollowed {
		text = mentionRe.ReplaceAllString(text, "")
		text = strings.TrimSpace(text)
	}
	if text == "" {
		return
	}

	from := actorURLToHandle(actor)
	if from == "" {
		from = actor
	}

	ts := time.Now()
	if obj.Published != "" {
		if t, err := time.Parse(time.RFC3339, obj.Published); err == nil {
			ts = t
		}
	}

	msgID := fmt.Sprintf("<%s@ap>", strings.ReplaceAll(obj.ID, "/", "-"))
	id := identity()

	// Route to feeds mailbox if from a followed actor, otherwise inbox.
	mbxID := vault.MakeMailboxID(id)
	inReplyTo := obj.InReplyTo
	if isFollowed {
		mbxID = feedsMailboxID()
		// Thread all feed posts under the follow record so biset accumulates them in one file.
		entry := fe.(followEntry)
		inReplyTo = string(entry.followMsgID)
	}

	e := vault.NewTextMessage(
		vault.MakeMessageID(msgID, id, ts),
		"",
		mbxID,
		[]*vault.Address{{Email: from}},
		[]*vault.Address{{Email: id}}, nil,
		"",
		text,
		ts,
		inReplyTo,
	)

	if err := store.Put(e); err != nil {
		log.Printf("[ap] store put: %v", err)
		return
	}
	hub.Notify()
}

func vaultFeedsDir() string {
	if cfg.Vault == "" {
		return ""
	}
	return filepath.Join(cfg.Vault, identity(), "feeds")
}

func writeFeedPost(from string, ts time.Time, text string) {
	dir := vaultFeedsDir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[vault] mkdir: %v", err)
		return
	}
	safe := strings.ReplaceAll(from, "/", "_")
	path := filepath.Join(dir, safe+".md")

	entry := fmt.Sprintf("\n---\ndate: %s\n\n%s\n", ts.Format(time.RFC3339), text)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[vault] open %s: %v", path, err)
		return
	}
	defer f.Close()
	fi, _ := f.Stat()
	if fi.Size() == 0 {
		fmt.Fprintf(f, "# @%s\n", from)
	}
	fmt.Fprint(f, entry)
	log.Printf("[vault] wrote feed post to %s", path)
}

func actorURLToHandle(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1] + "@" + u.Hostname()
}

// ── send (store → AP) ─────────────────────────────────────────────────────────

type resolvedActor struct {
	actorURL string
	inboxURL string
}

var resolvedActorCache sync.Map

type followEntry struct {
	handle      string
	followMsgID jmap.ID
}

// followedActors maps actorURL → followEntry.
var followedActors sync.Map

func resolveActor(handle string) (*resolvedActor, error) {
	if v, ok := resolvedActorCache.Load(handle); ok {
		return v.(*resolvedActor), nil
	}
	parts := strings.SplitN(handle, "@", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid handle: %q", handle)
	}
	scheme := "https"
	if strings.HasPrefix(parts[1], "localhost") {
		scheme = "http"
	}
	wfURL := scheme + "://" + parts[1] + "/.well-known/webfinger?resource=acct:" + handle
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

func sendFollow(handle string) (string, error) {
	resolved, err := resolveActor(handle)
	if err != nil {
		return "", err
	}
	ts := time.Now().UTC()
	actID := fmt.Sprintf("%s/follows/%d", actorURL(), ts.UnixMilli())
	activity := map[string]any{
		"@context": "https://www.w3.org/ns/activitystreams",
		"type":     "Follow",
		"id":       actID,
		"actor":    actorURL(),
		"object":   resolved.actorURL,
	}
	payload, err := json.Marshal(activity)
	if err != nil {
		return "", err
	}
	log.Printf("[ap] follow → %s (%s)", handle, resolved.inboxURL)
	if err := httpSignedPost(resolved.inboxURL, payload); err != nil {
		return "", err
	}
	return actID, nil
}

func sendUnfollow(followMsgID jmap.ID, handle string) error {
	resolved, err := resolveActor(handle)
	if err != nil {
		return err
	}
	ts := time.Now().UTC()
	followActID := fmt.Sprintf("%s/follows/%s", actorURL(), string(followMsgID))
	activity := map[string]any{
		"@context": "https://www.w3.org/ns/activitystreams",
		"type":     "Undo",
		"id":       fmt.Sprintf("%s/undos/%d", actorURL(), ts.UnixMilli()),
		"actor":    actorURL(),
		"object": map[string]any{
			"type":   "Follow",
			"id":     followActID,
			"actor":  actorURL(),
			"object": resolved.actorURL,
		},
	}
	payload, err := json.Marshal(activity)
	if err != nil {
		return err
	}
	log.Printf("[ap] unfollow → %s (%s)", handle, resolved.inboxURL)
	followedActors.Delete(resolved.actorURL)
	return httpSignedPost(resolved.inboxURL, payload)
}

func sendToActor(msg vault.Message, target string) error {
	resolved, err := resolveActor(target)
	if err != nil {
		return err
	}

	body := vault.MessageBody(msg)
	ts := time.Now().UTC()
	noteID := fmt.Sprintf("%s/notes/%d", actorURL(), ts.UnixMilli())

	const public = "https://www.w3.org/ns/activitystreams#Public"
	mention := "@" + target
	note := map[string]any{
		"@context":     "https://www.w3.org/ns/activitystreams",
		"type":         "Note",
		"id":           noteID,
		"url":          noteID,
		"attributedTo": actorURL(),
		"to":           []string{public},
		"cc":           []string{resolved.actorURL},
		"content":      "<p>" + mention + " " + htmlEscape(body) + "</p>",
		"published":    ts.Format(time.RFC3339),
		"tag": []map[string]string{{
			"type": "Mention",
			"href": resolved.actorURL,
			"name": mention,
		}},
	}
	if len(msg.InReplyTo) > 0 {
		note["inReplyTo"] = msg.InReplyTo[0]
	}

	createID := fmt.Sprintf("%s#create-%d", actorURL(), ts.UnixMilli())
	create := map[string]any{
		"@context":  "https://www.w3.org/ns/activitystreams",
		"type":      "Create",
		"id":        createID,
		"actor":     actorURL(),
		"to":        []string{public},
		"cc":        []string{resolved.actorURL},
		"object":    note,
		"published": ts.Format(time.RFC3339),
	}

	payload, err := json.Marshal(create)
	if err != nil {
		return err
	}
	log.Printf("[ap] send → %s", resolved.inboxURL)
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

	hh := sha256.Sum256([]byte(signingString))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, hh[:])
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

// ── ActivityPub routes ────────────────────────────────────────────────────────

func logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[ap] %s %s", r.Method, r.URL.Path)
		next(w, r)
	}
}

func registerAPRoutes(mux *http.ServeMux, store *core.Store, hub *core.Hub) {
	mux.HandleFunc("/.well-known/webfinger", logRequest(func(w http.ResponseWriter, r *http.Request) {
		resource := r.URL.Query().Get("resource")
		acct := strings.TrimPrefix(resource, "acct:")
		lastAt := strings.LastIndex(acct, "@")
		if lastAt < 0 {
			http.Error(w, "not found", 404)
			return
		}
		user, host := acct[:lastAt], acct[lastAt+1:]
		if host != cfg.Domain || user != cfg.RelayName {
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
	}))

	mux.HandleFunc("/", logRequest(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		parts := strings.Split(path, "/")

		if len(parts) == 0 || parts[0] != cfg.RelayName {
			http.NotFound(w, r)
			return
		}

		// GET /<relayname>
		if len(parts) == 1 && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/activity+json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"@context":          []string{"https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"},
				"type":              "Person",
				"id":                actorURL(),
				"url":               actorURL(),
				"name":              cfg.RelayName,
				"preferredUsername": cfg.RelayName,
				"summary":           "",
				"inbox":             inboxURL(),
				"outbox":            actorURL() + "/outbox",
				"followers":         actorURL() + "/followers",
				"following":         actorURL() + "/following",
				"publicKey": map[string]string{
					"id":           keyID(),
					"owner":        actorURL(),
					"publicKeyPem": publicKeyPEM(),
				},
			})
			return
		}

		// POST /<relayname>/inbox
		if len(parts) == 2 && parts[1] == "inbox" && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if err := verifyHTTPSignature(r, body); err != nil {
				log.Printf("[ap] signature verification failed: %v", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			handleInbox(body, store, hub)
			w.WriteHeader(202)
			return
		}

		// GET /<relayname>/outbox|followers|following — 最小限のコレクション
		if len(parts) == 2 && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/activity+json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"@context":     "https://www.w3.org/ns/activitystreams",
				"type":         "OrderedCollection",
				"id":           actorURL() + "/" + parts[1],
				"totalItems":   0,
				"orderedItems": []any{},
			})
			return
		}

		http.NotFound(w, r)
	}))
}

// ── helpers ───────────────────────────────────────────────────────────────────

func errObj(typ, desc string) map[string]string {
	return map[string]string{"type": typ, "description": desc}
}

func newID() jmap.ID {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return jmap.ID(fmt.Sprintf("ap-%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b)))
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

	store, err := core.NewStore(filepath.Join(dir, "data"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	// Restore followedActors from persisted follow records.
	// Also patch follow records missing MessageID (needed for thread assignment).
	for _, msg := range store.All() {
		if !msg.MailboxIDs[jmap.ID(feedsMailboxID())] {
			continue
		}
		isFollow := msg.Keywords["$follow_accepted"] || msg.Keywords["$follow_pending"]
		if isFollow && len(msg.MessageID) == 0 {
			msg.MessageID = []string{string(msg.ID)}
			store.Put(msg) //nolint:errcheck
		}
		if msg.Keywords["$follow_accepted"] && len(msg.To) > 0 && msg.To[0] != nil {
			if ra, err := resolveActor(msg.To[0].Email); err == nil {
				followedActors.Store(ra.actorURL, followEntry{handle: msg.To[0].Email, followMsgID: msg.ID})
				log.Printf("[ap] restored follow: %s", msg.To[0].Email)
			}
		}
	}

	hub := core.NewHub()
	h := &handler{store: store}

	mux := core.NewMux(cfg.Config, h, hub)
	registerAPRoutes(mux, store, hub)

	if cfg.Port == 0 {
		cfg.Port = 8765
	}
	addr := ":" + strconv.Itoa(cfg.Port)
	log.Printf("[ap] listening on %s (ActivityPub + JMAP)", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
