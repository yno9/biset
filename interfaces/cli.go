package interfaces

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"biset/vault"
)

// WatchConfigFile watches a config file for changes and sends on the returned channel.
func WatchConfigFile(configPath string) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return
		}
		defer watcher.Close()
		watcher.Add(configPath) //nolint:errcheck
		for {
			select {
			case _, ok := <-watcher.Events:
				if !ok {
					return
				}
				select {
				case ch <- struct{}{}:
				default:
				}
			case <-watcher.Errors:
			}
		}
	}()
	return ch
}

// RunStatus prints vault status to stdout.
func RunStatus(cfg *vault.Config, isBisetProcess func(pid int) bool) {
	lockPath := filepath.Join(cfg.Vault, ".data", ".biset.lock")
	daemonStatus := "not running"
	if b, err := os.ReadFile(lockPath); err == nil {
		var pid int
		fmt.Sscanf(string(b), "%d", &pid)
		if pid > 0 && isBisetProcess(pid) {
			daemonStatus = fmt.Sprintf("running (pid %d)", pid)
		}
	}

	serveStatus := "not serving"
	if cfg.Server.Enabled() {
		addr := fmt.Sprintf("%s:%d", cfg.Server.Bind, cfg.Server.Port)
		if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
			c.Close()
			serveStatus = fmt.Sprintf("serving: %d", cfg.Server.Port)
		}
	}

	messages, _ := vault.ScanMessages(cfg.Vault)
	threads, _ := vault.ScanThreads(cfg.Vault)

	fmt.Printf("\nStatus\n")
	fmt.Printf("  %s\n", daemonStatus)
	fmt.Printf("  %s\n", serveStatus)
	fmt.Printf("  vault:    %s\n", cfg.Vault)
	fmt.Printf("  messages: %d\n", len(messages))
	fmt.Printf("  threads:  %d\n", len(threads))
}

type RelayAccountInfo struct {
	AccountID string
	Total     int
}

func shortErr(err error) string {
	s := err.Error()
	// strip URL prefix from net/http errors: `Get "...": <actual error>`
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

func PingRelay(n vault.RelayConfig) ([]RelayAccountInfo, error) {
	hc := &http.Client{Timeout: 5 * time.Second}

	doReq := func(method, url, body string) (*http.Response, error) {
		var reqBody *strings.Reader
		if body != "" {
			reqBody = strings.NewReader(body)
		} else {
			reqBody = strings.NewReader("")
		}
		req, err := http.NewRequest(method, url, reqBody)
		if err != nil {
			return nil, err
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if n.RelayName != "" {
			req.SetBasicAuth(n.RelayName, n.Password)
		} else if n.Token != "" {
			req.Header.Set("Authorization", "Bearer "+n.Token)
		}
		return hc.Do(req)
	}

	// 1. fetch session
	resp, err := doReq("GET", n.URL, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var sess struct {
		APIURL   string                     `json:"apiUrl"`
		Accounts map[string]json.RawMessage `json:"accounts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		return nil, err
	}

	// 2. query email count per account
	var out []RelayAccountInfo
	for accountID := range sess.Accounts {
		body, _ := json.Marshal(map[string]any{
			"using": []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"},
			"methodCalls": []any{
				[]any{"Email/query", map[string]any{"accountId": accountID, "limit": 0}, "q0"},
			},
		})
		r2, err := doReq("POST", sess.APIURL, string(body))
		if err != nil {
			out = append(out, RelayAccountInfo{AccountID: accountID, Total: -1})
			continue
		}
		defer r2.Body.Close()
		var apiResp struct {
			MethodResponses [][]json.RawMessage `json:"methodResponses"`
		}
		total := -1
		if json.NewDecoder(r2.Body).Decode(&apiResp) == nil && len(apiResp.MethodResponses) > 0 {
			var result struct {
				Total int `json:"total"`
			}
			if len(apiResp.MethodResponses[0]) >= 2 {
				json.Unmarshal(apiResp.MethodResponses[0][1], &result) //nolint:errcheck
				total = result.Total
			}
		}
		out = append(out, RelayAccountInfo{AccountID: accountID, Total: total})
	}
	return out, nil
}

// RunServerSet directly sets the JMAP server enabled state without interaction.
func RunServerSet(configPath string, enabled bool) {
	cfg, err := vault.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.Server.Port == 0 || cfg.Server.Bind == "" {
		fmt.Fprintln(os.Stderr, "server: port and bind must be set in config")
		os.Exit(1)
	}
	if enabled == cfg.Server.Serve {
		fmt.Println("No changes.")
		return
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	var rawServer map[string]json.RawMessage
	if err := json.Unmarshal(raw["server"], &rawServer); err != nil {
		rawServer = map[string]json.RawMessage{}
	}
	val, _ := json.Marshal(enabled)
	rawServer["serve"] = val
	raw["server"], _ = json.Marshal(rawServer)
	out, _ := json.MarshalIndent(raw, "", "  ")
	if err := os.WriteFile(configPath, out, 0644); err != nil {
		log.Fatalf("write config: %v", err)
	}
	if enabled {
		fmt.Println("Server Started.")
	} else {
		fmt.Println("Server stopped.")
	}
}

// RunServerToggle provides an interactive CLI to toggle the JMAP server on/off.
func RunServerToggle(configPath string) {
	cfg, err := vault.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.Server.Port == 0 || cfg.Server.Bind == "" {
		fmt.Fprintln(os.Stderr, "server: port and bind must be set in config")
		os.Exit(1)
	}

	current := "2"
	if cfg.Server.Serve {
		current = "1"
	}
	status := "off"
	if current == "1" {
		status = "on"
	}
	fmt.Printf("Server [%s] (%s:%d):\n", status, cfg.Server.Bind, cfg.Server.Port)
	fmt.Println("  1. on")
	fmt.Println("  2. off")
	fmt.Printf("Choice [%s]: ", current)
	var line string
	fmt.Fscanln(os.Stdin, &line)
	if line == "" {
		line = current
	}
	enabled := line == "1"
	if enabled == cfg.Server.Serve {
		fmt.Println("No changes.")
		return
	}

	b, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	var rawServer map[string]json.RawMessage
	if err := json.Unmarshal(raw["server"], &rawServer); err != nil {
		rawServer = map[string]json.RawMessage{}
	}
	val, _ := json.Marshal(enabled)
	rawServer["serve"] = val
	raw["server"], _ = json.Marshal(rawServer)
	out, _ := json.MarshalIndent(raw, "", "  ")
	if err := os.WriteFile(configPath, out, 0644); err != nil {
		log.Fatalf("write config: %v", err)
	}
	fmt.Println("Saved.")
}

