// Package core provides the shared JMAP HTTP server infrastructure for biset nodes.
// Each node implements Handler with its protocol-specific logic; core handles
// HTTP, auth, session serving, and JMAP wire format (request parsing, result
// reference resolution, response encoding).
package core

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
)

// Hub broadcasts JMAP state-change events to SSE subscribers.
type Hub struct {
	mu   sync.Mutex
	subs map[chan struct{}]bool
}

func NewHub() *Hub {
	return &Hub{subs: map[chan struct{}]bool{}}
}

func (h *Hub) Notify() {
	h.mu.Lock()
	for ch := range h.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	h.mu.Unlock()
}

func (h *Hub) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	h.subs[ch] = true
	h.mu.Unlock()
	return ch
}

func (h *Hub) unsubscribe(ch chan struct{}) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

// Config is the base HTTP server config embedded by every node's config struct.
type Config struct {
	Port     int    `json:"port"`
	Bind     string `json:"bind,omitempty"` // default: all interfaces
	RelayName string `json:"relayname,omitempty"`
	Password string `json:"password,omitempty"`
}

// Account describes a JMAP account exposed by the node.
type Account struct {
	ID   jmap.ID
	Name string
}

// Handler is implemented by each node's protocol layer.
// core calls these methods; the node never touches HTTP or JMAP wire format.
type Handler interface {
	// Capabilities returns the JMAP URIs this node supports (e.g.
	// "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission").
	// "urn:ietf:params:jmap:core" is added automatically.
	Capabilities() []jmap.URI

	// Accounts returns one entry per configured account.
	Accounts() []Account

	// Handle executes a single JMAP method call.
	// args are already fully resolved (result references substituted).
	// Return (result, nil) on success; (nil, err) to send an error response.
	Handle(method string, args json.RawMessage) (any, error)
}

// Serve starts the JMAP HTTP server and blocks until it returns an error.
// hub may be nil; if non-nil, a /jmap/eventsource/ SSE endpoint is added.
func Serve(cfg Config, h Handler, hub *Hub) error {
	if cfg.Port == 0 {
		cfg.Port = 8765
	}
	addr := net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port))
	s := &srv{cfg: cfg, h: h}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jmap", s.auth(s.serveSession))
	mux.HandleFunc("/jmap/api/", s.auth(s.serveAPI))
	if hub != nil {
		mux.HandleFunc("/jmap/eventsource/", s.auth(func(w http.ResponseWriter, r *http.Request) {
			serveEventSource(w, r, hub)
		}))
	}
	return http.ListenAndServe(addr, mux)
}

func serveEventSource(w http.ResponseWriter, r *http.Request, hub *Hub) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "event: state\ndata: {\"changed\":{\"urn:ietf:params:jmap:mail\":null}}\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	ch := hub.subscribe()
	defer hub.unsubscribe(ch)
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ch:
			fmt.Fprint(w, "event: state\ndata: {\"changed\":{\"urn:ietf:params:jmap:mail\":null}}\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}

// ── internal ──────────────────────────────────────────────────────────────────

type srv struct {
	cfg Config
	h   Handler
}

func (s *srv) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.RelayName != "" {
			u, p, ok := r.BasicAuth()
			if !ok || u != s.cfg.RelayName || p != s.cfg.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="jmap"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func (s *srv) serveSession(w http.ResponseWriter, _ *http.Request) {
	caps := s.h.Capabilities()

	rawCaps := make(map[jmap.URI]json.RawMessage, len(caps)+1)
	rawCaps["urn:ietf:params:jmap:core"] = json.RawMessage(`{` +
		`"maxSizeUpload":50000000,` +
		`"maxConcurrentUpload":4,` +
		`"maxSizeRequest":10000000,` +
		`"maxConcurrentRequests":4,` +
		`"maxCallsInRequest":32,` +
		`"maxObjectsInGet":500,` +
		`"maxObjectsInSet":500,` +
		`"collationAlgorithms":[]` +
		`}`)
	acctCaps := make(map[jmap.URI]json.RawMessage, len(caps))
	for _, uri := range caps {
		rawCaps[uri] = json.RawMessage(`{}`)
		acctCaps[uri] = json.RawMessage(`{}`)
	}

	accounts := s.h.Accounts()
	jmapAccounts := make(map[jmap.ID]jmap.Account, len(accounts))
	primaryAccounts := make(map[jmap.URI]jmap.ID, len(caps))
	username := ""

	for i, a := range accounts {
		jmapAccounts[a.ID] = jmap.Account{
			Name:            a.Name,
			IsPersonal:      true,
			IsReadOnly:      false,
			RawCapabilities: acctCaps,
		}
		if i == 0 {
			username = a.Name
			for _, uri := range caps {
				primaryAccounts[uri] = a.ID
			}
		}
	}

	base := "http://" + net.JoinHostPort(s.cfg.Bind, strconv.Itoa(s.cfg.Port))
	if s.cfg.Bind == "" {
		base = "http://localhost:" + strconv.Itoa(s.cfg.Port)
	}
	sess := jmap.Session{
		RawCapabilities: rawCaps,
		Accounts:        jmapAccounts,
		PrimaryAccounts: primaryAccounts,
		Username:        username,
		APIURL:          base + "/jmap/api/",
		DownloadURL:     base + "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
		UploadURL:       base + "/jmap/upload/{accountId}/",
		EventSourceURL:  base + "/jmap/eventsource/",
		State:           "0",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sess) //nolint:errcheck
}

func (s *srv) serveAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		MethodCalls []json.RawMessage `json:"methodCalls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	results := map[string]json.RawMessage{} // callId → result JSON for result-reference resolution
	var responses []json.RawMessage

	for _, rawCall := range req.MethodCalls {
		var call [3]json.RawMessage
		if err := json.Unmarshal(rawCall, &call); err != nil {
			continue
		}
		var name, callID string
		json.Unmarshal(call[0], &name)   //nolint:errcheck
		json.Unmarshal(call[2], &callID) //nolint:errcheck

		resolvedArgs, err := resolveRefs(call[1], results)
		if err != nil {
			responses = append(responses, errorResponse(name, callID, "serverFail", err.Error()))
			continue
		}

		result, handleErr := s.h.Handle(name, resolvedArgs)
		if handleErr != nil {
			responses = append(responses, errorResponse(name, callID, "serverFail", handleErr.Error()))
			continue
		}

		if b, err := json.Marshal(result); err == nil {
			results[callID] = b
		}
		resultJSON, _ := json.Marshal(result)
		resp, _ := json.Marshal([]json.RawMessage{marshal(name), resultJSON, marshal(callID)})
		responses = append(responses, resp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"sessionState":    "0",
		"methodResponses": responses,
	})
}

func errorResponse(name, callID, errType, desc string) json.RawMessage {
	r, _ := json.Marshal([]json.RawMessage{
		marshal(name),
		marshal(map[string]string{"type": errType, "description": desc}),
		marshal(callID),
	})
	return r
}

func marshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// resolveRefs substitutes result-reference arguments (keys prefixed with "#").
func resolveRefs(args json.RawMessage, results map[string]json.RawMessage) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(args, &m); err != nil {
		return args, nil
	}
	hasRef := false
	for k := range m {
		if strings.HasPrefix(k, "#") {
			hasRef = true
			break
		}
	}
	if !hasRef {
		return args, nil
	}
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		if !strings.HasPrefix(k, "#") {
			out[k] = v
			continue
		}
		var ref struct {
			ResultOf string `json:"resultOf"`
			Path     string `json:"path"`
		}
		if err := json.Unmarshal(v, &ref); err != nil {
			return nil, fmt.Errorf("bad result reference %s: %w", k, err)
		}
		prev, ok := results[ref.ResultOf]
		if !ok {
			return nil, fmt.Errorf("no result for callId %q", ref.ResultOf)
		}
		resolved, err := jsonPath(prev, ref.Path)
		if err != nil {
			return nil, fmt.Errorf("path %q in %q: %w", ref.Path, ref.ResultOf, err)
		}
		out[k[1:]] = resolved
	}
	return json.Marshal(out)
}

// jsonPath extracts a value from JSON using a simple slash-delimited path (e.g. "/ids").
func jsonPath(data json.RawMessage, path string) (json.RawMessage, error) {
	var cur any
	if err := json.Unmarshal(data, &cur); err != nil {
		return nil, err
	}
	for _, p := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if p == "" {
			continue
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected object at %q", p)
		}
		cur, ok = m[p]
		if !ok {
			return nil, fmt.Errorf("key %q not found", p)
		}
	}
	return json.Marshal(cur)
}
