package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"git.sr.ht/~rockorager/go-jmap/mail/mailbox"
	jmapserver "github.com/yno9/go-jmapserver"
	"biset/vault"
)

// ── config ────────────────────────────────────────────────────────────────────

type Config struct {
	jmapserver.Config
	Bind                string `json:"bind,omitempty"`
	Port                int    `json:"port,omitempty"`
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

func (h *handler) removeFeed(feedURL string) {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	if _, exists := h.state.Feeds[feedURL]; exists {
		delete(h.state.Feeds, feedURL)
		h.saveState()
		log.Printf("[rss] removed feed: %s", feedURL)
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
	store.OnSetMailbox(func(op string, id jmap.ID, mb *mailbox.Mailbox) error {
		switch op {
		case "create":
			if mb != nil && mb.Name != "" {
				h.addFeed(mb.Name)
			}
		case "destroy":
			for _, existing := range store.Mailboxes() {
				if existing.ID == id {
					h.removeFeed(existing.Name)
					break
				}
			}
		}
		return nil
	})
	store.PutMailboxes([]vault.Mailbox{vault.DefaultMailbox(cfg.RelayName + "/")}) //nolint:errcheck

	go h.watch(context.Background())

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = fmt.Sprintf("%s:%d", cfg.Bind, cfg.Port)
	}
	log.Printf("rss-client: listening on %s", cfg.ListenAddr)
	log.Fatal(jmapserver.Serve(cfg.Config, h, hub))
}
