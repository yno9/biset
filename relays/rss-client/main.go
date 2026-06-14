package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	jmapserver "github.com/yno9/go-jmapserver"
	"biset/vault"
)

// ── config ────────────────────────────────────────────────────────────────────

type Config struct {
	jmapserver.Config
	RelayName           string `json:"relayname"`
	PollIntervalMinutes int    `json:"poll_interval_minutes"`
}

// ── state ─────────────────────────────────────────────────────────────────────

type FeedState struct {
	Name      string   `json:"name"`
	SeenGUIDs []string `json:"seen_guids"`
}

type State struct {
	Feeds map[string]FeedState `json:"feeds"`
}

// ── handler ───────────────────────────────────────────────────────────────────

type handler struct {
	store     *jmapserver.Store
	hub       *jmapserver.Hub
	stateMu   sync.Mutex
	state     State
	statePath string
}

func (h *handler) Capabilities() []jmap.URI {
	return []jmap.URI{
		"urn:ietf:params:jmap:mail",
		"urn:ietf:params:jmap:submission",
	}
}

func (h *handler) Accounts() []jmapserver.Account {
	return []jmapserver.Account{{
		ID:   jmap.ID(cfg.RelayName),
		Name: cfg.RelayName,
	}}
}

func (h *handler) Handle(method string, args json.RawMessage) (any, error) {
	switch method {
	case "Email/query":
		return h.emailQuery(args)
	case "Email/queryChanges":
		h.pollAll()
		return h.store.HandleQueryChanges(jmap.ID(cfg.RelayName), args)
	case "Email/changes":
		return h.store.HandleEmailChanges(jmap.ID(cfg.RelayName), args)
	case "Email/get":
		return h.store.HandleEmailGet(jmap.ID(cfg.RelayName), args)
	case "Thread/get":
		return h.store.HandleThreadGet(jmap.ID(cfg.RelayName), args)
	case "Mailbox/get":
		return h.store.HandleMailboxGet(jmap.ID(cfg.RelayName), args)
	case "Mailbox/changes":
		return h.store.HandleMailboxChanges(jmap.ID(cfg.RelayName), args)
	case "Identity/get":
		return h.store.HandleIdentityGet(jmap.ID(cfg.RelayName))
	case "Identity/changes":
		return h.store.HandleIdentityChanges(jmap.ID(cfg.RelayName), args)
	case "Thread/changes":
		return h.store.HandleThreadChanges(jmap.ID(cfg.RelayName), args)
	case "Email/set":
		return h.emailSet(args)
	case "EmailSubmission/set":
		return h.emailSubmissionSet()
	default:
		return h.store.Dispatch(jmap.ID(cfg.RelayName), method, args)
	}
}

// ── Email/query ───────────────────────────────────────────────────────────────

func (h *handler) emailQuery(args json.RawMessage) (any, error) {
	h.pollAll()
	return h.store.HandleEmailQuery(jmap.ID(cfg.RelayName), args)
}

// ── Email/set ─────────────────────────────────────────────────────────────────

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
	destroyed := []jmap.ID{}
	notDestroyed := map[jmap.ID]any{}

	for key, rawMsg := range req.Create {
		var msg vault.Message
		if err := json.Unmarshal(rawMsg, &msg); err != nil {
			notCreated[key] = errObj("invalidProperties", err.Error())
			continue
		}
		feedURL := ""
		if len(msg.To) > 0 && msg.To[0] != nil {
			feedURL = msg.To[0].Email
		}
		if feedURL == "" {
			notCreated[key] = errObj("invalidProperties", "missing feed URL in To address")
			continue
		}
		h.addFeed(feedURL)
		created[key] = map[string]any{"id": jmap.ID("follow-" + feedURL), "receivedAt": time.Now().UTC().Format(time.RFC3339Nano)}
	}

	for msgID, rawPatch := range req.Update {
		var patch map[string]any
		if err := json.Unmarshal(rawPatch, &patch); err != nil {
			continue
		}
		h.store.PatchKeywords(msgID, patch) //nolint:errcheck
		updated[msgID] = map[string]any{}
	}

	for _, msgID := range req.Destroy {
		h.store.Delete(msgID)
		destroyed = append(destroyed, msgID)
	}

	return map[string]any{
		"accountId":    jmap.ID(cfg.RelayName),
		"oldState":     "0",
		"newState":     "1",
		"created":      created,
		"updated":      updated,
		"destroyed":    destroyed,
		"notCreated":   notCreated,
		"notUpdated":   map[string]any{},
		"notDestroyed": notDestroyed,
	}, nil
}

// ── EmailSubmission/set ───────────────────────────────────────────────────────

func (h *handler) emailSubmissionSet() (any, error) {
	return map[string]any{
		"accountId":    jmap.ID(cfg.RelayName),
		"oldState":     "0",
		"newState":     "0",
		"created":      map[string]any{},
		"notCreated":   map[string]any{},
		"updated":      map[string]any{},
		"notUpdated":   map[string]any{},
		"destroyed":    []string{},
		"notDestroyed": map[string]any{},
	}, nil
}

// ── state ─────────────────────────────────────────────────────────────────────

func (h *handler) loadState() {
	h.state = State{Feeds: map[string]FeedState{}}
	b, err := os.ReadFile(h.statePath)
	if err != nil {
		return
	}
	json.Unmarshal(b, &h.state) //nolint:errcheck
	if h.state.Feeds == nil {
		h.state.Feeds = map[string]FeedState{}
	}
}

func (h *handler) saveState() {
	b, _ := json.MarshalIndent(h.state, "", "  ")
	os.WriteFile(h.statePath, b, 0644) //nolint:errcheck
}

func (h *handler) addFeed(feedURL string) {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	if _, exists := h.state.Feeds[feedURL]; !exists {
		h.state.Feeds[feedURL] = FeedState{}
		h.saveState()
		log.Printf("[rss] added feed: %s", feedURL)
	}
}

// ── polling ───────────────────────────────────────────────────────────────────

func (h *handler) pollAll() {
	h.stateMu.Lock()
	feeds := make(map[string]FeedState, len(h.state.Feeds))
	for k, v := range h.state.Feeds {
		feeds[k] = v
	}
	h.stateMu.Unlock()

	for feedURL, state := range feeds {
		msgs, newGUIDs, err := fetchFeed(feedURL, state, cfg.RelayName)
		if err != nil {
			log.Printf("[rss] poll %s: %v", feedURL, err)
			continue
		}
		for _, m := range msgs {
			h.store.Put(m) //nolint:errcheck
		}
		if len(newGUIDs) > 0 {
			h.stateMu.Lock()
			fs := h.state.Feeds[feedURL]
			fs.SeenGUIDs = append(fs.SeenGUIDs, newGUIDs...)
			h.state.Feeds[feedURL] = fs
			h.saveState()
			h.stateMu.Unlock()
			h.hub.Notify()
		}
	}
}

func (h *handler) watch(ctx context.Context) {
	interval := time.Duration(cfg.PollIntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.pollAll()
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func errObj(typ, desc string) map[string]string {
	return map[string]string{"type": typ, "description": desc}
}

// ── entry point ───────────────────────────────────────────────────────────────

var cfg Config

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

	store, err := jmapserver.NewStore(filepath.Join(dir, "data"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	hub := jmapserver.NewHub()
	h := &handler{
		store:     store,
		hub:       hub,
		statePath: filepath.Join(dir, "state.json"),
	}
	h.loadState()
	store.PutMailboxes([]vault.Inbox{vault.DefaultInbox(cfg.RelayName + "/")}) //nolint:errcheck

	go h.watch(context.Background())

	log.Printf("rss-client: listening on %s:%d", cfg.Bind, cfg.Port)
	log.Fatal(jmapserver.Serve(cfg.Config, h, hub))
}
