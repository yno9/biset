package core

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Manifest describes a Connector binary.
type Manifest struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Description  string   `json:"description"`
	Capabilities []string `json:"capabilities"`
	Protocols    []string `json:"protocols"` // e.g. ["imap", "smtp"]
}

// Manager discovers and manages Connector subprocesses.
type Manager struct {
	dir        string
	onChange   func()
	connectors []*Connector
}

func NewManager(dir string, onChange func()) *Manager {
	return &Manager{dir: dir, onChange: onChange}
}

func (m *Manager) SetOnChange(fn func()) {
	m.onChange = fn
	for _, c := range m.connectors {
		c.onChange = fn
	}
}

// Load scans the connectors directory and initializes Connector instances.
func (m *Manager) Load() error {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return fmt.Errorf("read connectors dir: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c, err := newConnector(filepath.Join(m.dir, e.Name()), m.onChange)
		if err != nil {
			log.Printf("connector %s: %v", e.Name(), err)
			continue
		}
		m.connectors = append(m.connectors, c)
	}
	return nil
}

// Start launches all Connector subprocesses in the background.
func (m *Manager) Start() {
	for _, c := range m.connectors {
		go c.runLoop()
	}
}

// Stop signals all Connector subprocesses to exit.
func (m *Manager) Stop() {
	for _, c := range m.connectors {
		c.stop()
	}
}

func (m *Manager) Connectors() []*Connector { return m.connectors }

// WaitReady blocks until all Connectors are ready or ctx is done.
func (m *Manager) WaitReady(ctx context.Context) {
	for _, c := range m.connectors {
		select {
		case <-c.readyCh:
		case <-ctx.Done():
			return
		}
	}
}

// ConnectorFor returns the first Connector that declares the given protocol.
func (m *Manager) ConnectorFor(protocol string) *Connector {
	for _, c := range m.connectors {
		for _, p := range c.manifest.Protocols {
			if p == protocol {
				return c
			}
		}
	}
	return nil
}

// ── Connector ─────────────────────────────────────────────────────────────────

// Connector wraps a running plugin subprocess and speaks JSON-RPC 2.0 over stdio.
type Connector struct {
	manifest Manifest
	dir      string
	onChange func()

	mu      sync.Mutex
	cmd     *exec.Cmd
	enc     *json.Encoder
	pending map[int64]chan rpcResponse
	nextID  atomic.Int64
	readyCh chan struct{} // closed once first ping succeeds
}

func newConnector(dir string, onChange func()) (*Connector, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var mf Manifest
	if err := json.Unmarshal(b, &mf); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &Connector{
		manifest: mf,
		dir:      dir,
		onChange: onChange,
		pending:  map[int64]chan rpcResponse{},
		readyCh:  make(chan struct{}),
	}, nil
}

func (c *Connector) Name() string { return c.manifest.Name }

func (c *Connector) Has(capability string) bool {
	for _, cap := range c.manifest.Capabilities {
		if cap == capability {
			return true
		}
	}
	return false
}

// runLoop starts the subprocess and restarts it on exit.
func (c *Connector) runLoop() {
	for {
		if err := c.run(); err != nil {
			log.Printf("[%s] %v — retrying in 5s", c.manifest.Name, err)
		}
		time.Sleep(5 * time.Second)
	}
}

// run starts the subprocess, runs the read loop, and returns when the process exits.
func (c *Connector) run() error {
	bin := filepath.Join(c.dir, c.manifest.Name)
	cmd := exec.Command(bin)
	cmd.Dir = c.dir
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	c.mu.Lock()
	c.cmd = cmd
	c.enc = json.NewEncoder(stdin)
	c.mu.Unlock()

	// start reader BEFORE ping so responses can be received
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024) // 4MB buffer
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for sc.Scan() {
		var msg rpcResponse
		if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
			continue
		}
		if msg.ID == nil {
			// notification from connector
			if msg.Method == "notify" && c.onChange != nil {
				c.onChange()
			}
			continue
		}
		c.mu.Lock()
		ch, ok := c.pending[*msg.ID]
		delete(c.pending, *msg.ID)
		c.mu.Unlock()
		if ok {
			ch <- msg
		}
		}
	}()

	if _, err := c.call("ping", nil); err != nil {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
		<-readerDone
		return fmt.Errorf("ping: %w", err)
	}

	// signal ready (once only)
	select {
	case <-c.readyCh:
	default:
		close(c.readyCh)
	}

	log.Printf("[%s] connected", c.manifest.Name)

	<-readerDone
	cmd.Wait() //nolint:errcheck
	c.failPending()
	return nil
}

func (c *Connector) stop() {
	c.mu.Lock()
	cmd := c.cmd
	c.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Signal(os.Interrupt) //nolint:errcheck
	}
}

func (c *Connector) failPending() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ch := range c.pending {
		ch <- rpcResponse{Error: &rpcError{Message: "connector exited"}}
		delete(c.pending, id)
	}
}

// ── JSON-RPC ──────────────────────────────────────────────────────────────────

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int64 `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *Connector) call(method string, params any) (json.RawMessage, error) {
	id := c.nextID.Add(1)
	ch := make(chan rpcResponse, 1)

	c.mu.Lock()
	c.pending[id] = ch
	err := c.enc.Encode(rpcRequest{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  method,
		Params:  params,
	})
	c.mu.Unlock()

	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, err
	}

	timeout := 30 * time.Second
	if method == "fetch" {
		timeout = 120 * time.Second
	}
	select {
	case resp := <-ch:
		if resp.Error != nil {
			return nil, fmt.Errorf("%s", resp.Error.Message)
		}
		return resp.Result, nil
	case <-time.After(timeout):
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("timeout")
	}
}

// ── public methods ────────────────────────────────────────────────────────────

func (c *Connector) Fetch() ([]Message, error) {
	result, err := c.call("fetch", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Messages []Message `json:"messages"`
	}
	if err := json.Unmarshal(result, &out); err != nil {
		return nil, err
	}
	return out.Messages, nil
}

func (c *Connector) Send(inbox, to, cc, bcc, subject, body, parentID string) error {
	_, err := c.call("send", map[string]string{
		"inbox":     inbox,
		"to":        to,
		"cc":        cc,
		"bcc":       bcc,
		"subject":   subject,
		"body":      body,
		"parent_id": parentID,
	})
	return err
}

func (c *Connector) Handle(inbox, messageID string, action Action) error {
	_, err := c.call("handle", map[string]string{
		"inbox":      inbox,
		"message_id": messageID,
		"action":     string(action),
	})
	return err
}
