package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/fsnotify/fsnotify"
	"github.com/yd7a/biset/core"
)

var version = "dev"

// Config holds biset settings loaded from config.json.
type Config struct {
	Vault         string   `json:"vault"`
	ConnectorsDir string   `json:"connectors_dir"`
	Connectors    []string `json:"connectors"` // e.g. ["biset-imap", "biset-ap"]
}

func main() {
	// Parse subcommand and flags.
	// Usage:
	//   biset [up]          start daemon (watch+sync, macOS: tray)
	//   biset down          stop running daemon
	//   biset sync          one-shot sync and exit
	//   biset serve         run JMAP HTTP server + watch
	//   biset version       print version
	//
	// Flags: --port, --token, --interval, --daemon (internal)

	portFlag    := 1080
	tokenFlag   := ""
	intervalFlag := time.Minute
	daemonFlag  := false
	renderFlag  := false // hidden flag for re-rendering MD

	subcommand := "" // empty = no subcommand given → show help
	var configArgument string

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "up", "down", "sync", "serve", "version", "status", "config":
			subcommand = args[i]
		case "--help", "-help", "-h":
			subcommand = "help"
		case "--render", "-render", "render":
			renderFlag = true
			if subcommand == "" {
				subcommand = "up"
			}
		case "--daemon", "-daemon":
			daemonFlag = true
			if subcommand == "" {
				subcommand = "up"
			}
case "--port", "-port":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &portFlag)
			}
		case "--token", "-token":
			if i+1 < len(args) {
				i++
				tokenFlag = args[i]
			}
		case "--version", "-version":
			subcommand = "version"
		case "--interval", "-interval":
			if i+1 < len(args) {
				i++
				if d, err := time.ParseDuration(args[i]); err == nil {
					intervalFlag = d
				}
			}
		default:
			if len(args[i]) > 0 && args[i][0] != '-' && configArgument == "" {
				if strings.Contains(args[i], "/") || strings.HasSuffix(args[i], ".json") {
					configArgument = args[i]
					if subcommand == "" {
						subcommand = "up"
					}
				}
			}
		}
	}

	switch subcommand {
	case "version":
		fmt.Println(version)
		return
	case "help", "":
		fmt.Print(`
Your email. Local. Private.

USAGE
  biset <subcommand> [flags]

SUBCOMMANDS
  up      Start biset (sync + watch, macOS: menu bar icon)
  down    Stop running biset
  sync    Trigger a sync
  serve   Run JMAP HTTP server
  status  Show status
  config  Show or edit config
  version Print version

FLAGS
  --interval duration   Sync interval (default 1m)
  --port int            Port for "serve" (default 1080)
  --token string        Bearer token for "serve"

`[1:])
		return
	}

	configPath := configArgument
	if configPath != "" {
		if !filepath.IsAbs(configPath) {
			if abs, err := filepath.Abs(configPath); err == nil {
				configPath = abs
			}
		}
	} else {
		exe, err := os.Executable()
		if err != nil {
			log.Fatalf("cannot determine executable path: %v", err)
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		dir := filepath.Dir(exe)
		if strings.Contains(dir, ".app/Contents/MacOS") {
			dir = filepath.Dir(filepath.Dir(filepath.Dir(dir)))
		}
		configPath = filepath.Join(dir, "biset.json")
	}

	if subcommand == "config" {
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = os.Getenv("VISUAL")
		}
		if editor == "" {
			for _, e := range []string{"nano", "vim", "vi"} {
				if _, err := exec.LookPath(e); err == nil {
					editor = e
					break
				}
			}
		}

		// Build list of editable configs
		type configEntry struct {
			label string
			path  string
		}
		entries := []configEntry{{"biset.json", configPath}}
		installDir := filepath.Dir(configPath)
		connectorsDir := filepath.Join(installDir, "connectors")
		if dirs, err := os.ReadDir(connectorsDir); err == nil {
			for _, d := range dirs {
				if !d.IsDir() {
					continue
				}
				p := filepath.Join(connectorsDir, d.Name(), "config.json")
				if _, err := os.Stat(p); err == nil {
					entries = append(entries, configEntry{d.Name(), p})
				}
			}
		}

		// Menu
		fmt.Println("Select config to edit:")
		for i, e := range entries {
			fmt.Printf("  %d) %s\n", i+1, e.label)
		}
		fmt.Print("Choice [1]: ")
		var line string
		fmt.Fscanln(os.Stdin, &line)
		if line == "" {
			line = "1"
		}
		choice := 0
		fmt.Sscanf(line, "%d", &choice)
		if choice < 1 || choice > len(entries) {
			choice = 1
		}
		target := entries[choice-1].path

		if editor == "" {
			b, _ := os.ReadFile(target)
			fmt.Println(target)
			fmt.Println()
			fmt.Print(string(b))
			return
		}
		cmd := exec.Command(editor, target)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run() //nolint:errcheck
		return
	}

	if subcommand == "status" || subcommand == "down" {
		cfg, err := loadConfig(configPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		if subcommand == "status" {
			runStatus(cfg)
			return
		}
		// down
		quitPath := filepath.Join(cfg.Vault, "biset-quit.json")
		os.WriteFile(quitPath, []byte("{}"), 0644) //nolint:errcheck
		fmt.Println("biset: stopping daemon")
		lockPath := filepath.Join(cfg.Vault, ".data", ".biset.lock")
		for i := 0; i < 30; i++ {
			time.Sleep(100 * time.Millisecond)
			if _, err := os.Stat(lockPath); os.IsNotExist(err) {
				fmt.Println("biset: stopped")
				return
			}
		}
		return
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		runSetup(configPath)
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			return // setup cancelled
		}
	}

	// clean up leftover setup temp files
	cleanupTempFiles(filepath.Dir(configPath))

	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	connectorsDir := cfg.ConnectorsDir
	if connectorsDir == "" {
		home, _ := os.UserHomeDir()
		connectorsDir = filepath.Join(home, ".biset", "connectors")
	} else if !filepath.IsAbs(connectorsDir) {
		connectorsDir = filepath.Join(filepath.Dir(configPath), connectorsDir)
	}

	// For "up": refuse to start if daemon already running.
	// For "sync"/"serve": clear stale lock only.
	lockPath := filepath.Join(cfg.Vault, ".data", ".biset.lock")
	if b, err := os.ReadFile(lockPath); err == nil {
		var pid int
		fmt.Sscanf(string(b), "%d", &pid)
		if pid > 0 && isBisetProcess(pid) {
			if subcommand == "up" || subcommand == "" {
				fmt.Fprintf(os.Stderr, "biset: already running (pid %d)\n", pid)
				os.Exit(1)
			}
		} else {
			os.Remove(lockPath) //nolint:errcheck
		}
	}

	ensureConnectors(cfg, connectorsDir)
	core.ReThreadVault(cfg.Vault)

	var mgr *core.Manager
	triggerSync := func() {
		if mgr != nil {
			go runSync(cfg, mgr)
		}
	}
	mgr = core.NewManager(connectorsDir, triggerSync)
	if err := mgr.Load(); err != nil {
		log.Printf("connectors: %v", err)
	}
	defer mgr.Stop()

	// handle SIGTERM/SIGINT → stop connectors then exit
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		mgr.Stop()
		os.Exit(0)
	}()

	if renderFlag {
		runRender(cfg)
		return
	}

	switch subcommand {
	case "sync":
		mgr.Start()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		mgr.WaitReady(ctx)
		cancel()
		runSync(cfg, mgr)
		mgr.Stop()

	case "serve":
		mgr.Start()
		go runServeContext(context.Background(), cfg, portFlag, tokenFlag) //nolint:errcheck
		watchLoop(cfg, mgr, configPath, intervalFlag)

	default: // "up"
		mgr.Start()
		if runtime.GOOS == "darwin" {
			if !daemonFlag && isTTY() {
				exe, err := os.Executable()
				if err == nil {
					newArgs := append([]string{"--daemon"}, os.Args[1:]...)
					cmd := exec.Command(exe, newArgs...)
					cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
					devNull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
					cmd.Stdin = devNull
					cmd.Stdout = devNull
					cmd.Stderr = devNull
					if err := cmd.Start(); err == nil {
						fmt.Printf("biset: started (pid %d)\n", cmd.Process.Pid)
					}
					return
				}
			}
			if daemonFlag {
				devNull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
				os.Stdout = devNull
				os.Stderr = devNull
				log.SetOutput(devNull)
			}
			lockPath, ok := acquireLock(cfg.Vault)
			if !ok {
				fmt.Fprintln(os.Stderr, "biset: already running")
				os.Exit(1)
			}
			defer os.Remove(lockPath)
			RunTray(cfg, mgr, configPath, intervalFlag, 0)
		} else {
			lockPath, ok := acquireLock(cfg.Vault)
			if !ok {
				fmt.Fprintln(os.Stderr, "biset: already running")
				os.Exit(1)
			}
			defer os.Remove(lockPath)
			fmt.Printf("biset: started (pid %d)\n", os.Getpid())
			watchLoop(cfg, mgr, configPath, intervalFlag)
		}
	}
}

func watchLoop(cfg *Config, mgr *core.Manager, configPath string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	configChanged := watchConfigFile(configPath)

	runSync(cfg, mgr)
	for {
		select {
		case <-ticker.C:
			runSync(cfg, mgr)
		case <-configChanged:
			fmt.Println("config changed — reloading")
			if newCfg, err := loadConfig(configPath); err == nil {
				cfg = newCfg
			}
			runSync(cfg, mgr)
		}
	}
}

func runRender(cfg *Config) {
	entries, _ := os.ReadDir(cfg.Vault)
	for _, d := range entries {
		if !d.IsDir() {
			continue
		}
		inboxKey := d.Name()
		inboxDir := filepath.Join(cfg.Vault, inboxKey)
		// delete all MD files
		files, _ := os.ReadDir(inboxDir)
		deleted := 0
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".md") {
				os.Remove(filepath.Join(inboxDir, f.Name())) //nolint:errcheck
				deleted++
			}
		}
		core.RenderMissingMDs(cfg.Vault, inboxKey)
		files2, _ := os.ReadDir(inboxDir)
		rendered := 0
		for _, f := range files2 {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".md") {
				rendered++
			}
		}
		fmt.Printf("[%s] deleted %d, rendered %d\n", inboxKey, deleted, rendered)
	}
}

// ── connector installer ───────────────────────────────────────────────────────

func ensureConnectors(cfg *Config, connectorsDir string) {
	for _, name := range cfg.Connectors {
		dir := filepath.Join(connectorsDir, name)
		bin := filepath.Join(dir, name)
		if _, err := os.Stat(bin); err == nil {
			continue // already installed
		}
		fmt.Printf("installing %s...\n", name)
		if err := installConnector(name, dir); err != nil {
			log.Printf("install %s: %v", name, err)
		} else {
			fmt.Printf("installed %s\n", name)
		}
	}
}

func installConnector(name, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// binary
	if err := downloadFile(connectorBinURL(name), filepath.Join(dir, name), 0755); err != nil {
		return fmt.Errorf("download binary: %w", err)
	}

	// manifest.json
	if err := downloadFile(connectorFileURL(name, "manifest.json"), filepath.Join(dir, "manifest.json"), 0644); err != nil {
		return fmt.Errorf("download manifest: %w", err)
	}

	// config.json — only create if not already present
	cfgPath := filepath.Join(dir, "config.json")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := downloadFile(connectorFileURL(name, "config.example.json"), cfgPath, 0644); err != nil {
			log.Printf("[%s] no config.example.json in release — skipping", name)
		}
	}

	return nil
}

func connectorBinURL(name string) string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	return fmt.Sprintf("https://github.com/yno9/biset/releases/latest/download/%s-%s-%s", name, goos, goarch)
}

func connectorFileURL(name, file string) string {
	return fmt.Sprintf("https://github.com/yno9/biset/releases/latest/download/%s-%s", name, file)
}

func downloadFile(url, path string, mode os.FileMode) error {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, url)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// ── setup ─────────────────────────────────────────────────────────────────────

// setupURL is the setup page. In production, replace with the GitHub Pages URL.
const setupURL = "https://yno9.github.io/biset/setup.html"


func killExisting(exe string) {
	out, err := exec.Command("pgrep", "-x", filepath.Base(exe)).Output()
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var pid int
		fmt.Sscanf(line, "%d", &pid)
		if pid == 0 || pid == self {
			continue
		}
		if proc, err := os.FindProcess(pid); err == nil {
			proc.Signal(syscall.SIGTERM) //nolint:errcheck
		}
	}
	time.Sleep(300 * time.Millisecond)
}

func cleanupTempFiles(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "biset-dl-") ||
			n == "biset-connecting.json" ||
			n == "biset-status.json" ||
			n == "biset-proceed.json" ||
			n == "biset-quit.json" ||
			n == "biset-open-vault.json" {
			os.Remove(filepath.Join(dir, n)) //nolint:errcheck
		}
	}
}

func runSetup(configPath string) {
	configPathForSetup = configPath
	cleanupTempFiles(filepath.Dir(configPath))

	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)

	url := setupURL
	// dev override: if assets/setup.html exists next to the binary, use it
	localSetup := filepath.Join(exeDir, "assets", "setup.html")
	if _, err := os.Stat(localSetup); err == nil {
		url = "file://" + localSetup
	}

	fmt.Printf("Opening setup: %s\n", url)
	exec.Command("open", url).Start() //nolint:errcheck

	fmt.Println("Waiting for setup to complete...")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	defer watcher.Close()
	watcher.Add(filepath.Dir(configPath)) //nolint:errcheck

	statusPath := filepath.Join(filepath.Dir(configPath), "biset-status.json")
	proceedPath := filepath.Join(filepath.Dir(configPath), "biset-proceed.json")

	// process any trigger files already present before watcher started
	go func() {
		entries, _ := os.ReadDir(filepath.Dir(configPath))
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "biset-dl-") && strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, "-done.json") {
				watcher.Events <- fsnotify.Event{Name: filepath.Join(filepath.Dir(configPath), name), Op: fsnotify.Create}
			}
		}
	}()

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			name := filepath.Base(event.Name)
			if strings.HasPrefix(name, "biset-dl-") && strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, "-done.json") {
				b, _ := os.ReadFile(event.Name)
				os.Remove(event.Name) //nolint:errcheck
				go func() {
					var payload struct {
						Name string `json:"name"`
						URL  string `json:"url"`
					}
					json.Unmarshal(b, &payload) //nolint:errcheck
					connectorName := payload.Name
					dir := filepath.Join(filepath.Dir(configPath), "connectors", connectorName)
					os.MkdirAll(dir, 0755) //nolint:errcheck
					binPath := filepath.Join(dir, connectorName)
					var err error
					if connectorName == "biset-ui" {
						home, _ := os.UserHomeDir()
						uiDir := filepath.Join(home, "biset-ui")
						os.MkdirAll(uiDir, 0755) //nolint:errcheck
						err = downloadFile(payload.URL, filepath.Join(uiDir, "index.html"), 0644)
					} else if connectorName == "biset-serve" {
						err = installConnector(connectorName, dir)
					} else if payload.URL != "" {
						// custom binary URL from setup.js — still fetch manifest + config alongside
						if err = downloadFile(payload.URL, binPath, 0755); err == nil {
							if e := downloadFile(connectorFileURL(connectorName, "manifest.json"), filepath.Join(dir, "manifest.json"), 0644); e != nil {
								log.Printf("[%s] manifest download: %v", connectorName, e)
							}
							cfgPath := filepath.Join(dir, "config.json")
							if _, e := os.Stat(cfgPath); os.IsNotExist(e) {
								if e := downloadFile(connectorFileURL(connectorName, "config.example.json"), cfgPath, 0644); e != nil {
									log.Printf("[%s] config.example.json download: %v", connectorName, e)
								}
							}
						}
					} else {
						err = installConnector(connectorName, dir)
					}
					result := map[string]any{"ok": err == nil}
					if err != nil {
						result["error"] = err.Error()
					}
					rb, _ := json.Marshal(result)
					donePath := filepath.Join(filepath.Dir(configPath), fmt.Sprintf("biset-dl-%s-done.json", connectorName))
					os.WriteFile(donePath, rb, 0644) //nolint:errcheck
				}()
				continue
			}
			if name == "biset-connecting.json" {
				time.Sleep(200 * time.Millisecond)
				b, _ := os.ReadFile(event.Name)
				os.Remove(event.Name) //nolint:errcheck
				preview, connErr := testConnectionFromPayload(b)
				if connErr != "" {
					writeSetupStatus(statusPath, false, connErr, nil)
					continue
				}
				writeSetupStatus(statusPath, true, "", preview)
				// wait for proceed
				for {
					if _, err := os.Stat(proceedPath); err == nil {
						os.Remove(proceedPath) //nolint:errcheck
						fmt.Println("Setup complete — starting biset")
						return
					}
					time.Sleep(500 * time.Millisecond)
				}
			}
		case <-watcher.Errors:
		}
	}
}

func writeSetupStatus(path string, ok bool, msg string, preview map[string]int) {
	status := "ok"
	if !ok {
		status = "error"
	}
	data := map[string]any{"status": status, "message": msg}
	if preview != nil {
		data["preview"] = preview
	}
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0644) //nolint:errcheck
}

func testConnectionFromPayload(data []byte) (map[string]int, string) {
	type imapCfg struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		TLSMode  string `json:"tls_mode"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	type account struct {
		IMAP imapCfg `json:"imap"`
	}
	type connectorCfg struct {
		Accounts []account `json:"accounts"`
	}

	var payload struct {
		IMAPConnector *connectorCfg `json:"imap_connector"`
	}
	json.Unmarshal(data, &payload) //nolint:errcheck

	var cfg *connectorCfg
	if payload.IMAPConnector != nil && len(payload.IMAPConnector.Accounts) > 0 {
		cfg = payload.IMAPConnector
	} else {
		// fallback: read from connector config file
		if b, err := os.ReadFile(filepath.Join(filepath.Dir(configPathForSetup), "connectors", "biset-imap", "config.json")); err == nil {
			var fileCfg connectorCfg
			if json.Unmarshal(b, &fileCfg) == nil && len(fileCfg.Accounts) > 0 {
				cfg = &fileCfg
			}
		}
	}

	if cfg == nil {
		return map[string]int{}, ""
	}
	acct := cfg.Accounts[0]
	preview, err := countIMAPMailbox(acct.IMAP.Host, acct.IMAP.Port, acct.IMAP.TLSMode, acct.IMAP.Username, acct.IMAP.Password)
	if err != nil {
		return nil, fmt.Sprintf("Cannot connect to %s: %v", acct.IMAP.Host, err)
	}
	return preview, ""
}

var configPathForSetup string

func testConnectorConnection(dir string, _ *Config) (map[string]int, string) {
	// look for biset-imap connector config
	imapCfgPath := filepath.Join(dir, "connectors", "biset-imap", "config.json")
	b, err := os.ReadFile(imapCfgPath)
	if err != nil {
		return map[string]int{}, "" // no IMAP connector, ok
	}
	var connCfg struct {
		Accounts []struct {
			IMAP struct {
				Host     string `json:"host"`
				Port     int    `json:"port"`
				TLSMode  string `json:"tls_mode"`
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"imap"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(b, &connCfg); err != nil || len(connCfg.Accounts) == 0 {
		return map[string]int{}, ""
	}
	acct := connCfg.Accounts[0]
	preview, err := countIMAPMailbox(acct.IMAP.Host, acct.IMAP.Port, acct.IMAP.TLSMode, acct.IMAP.Username, acct.IMAP.Password)
	if err != nil {
		return nil, fmt.Sprintf("Cannot connect to %s: %v", acct.IMAP.Host, err)
	}
	return preview, ""
}

func countIMAPMailbox(host string, port int, tlsMode, username, password string) (map[string]int, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	opts := &imapclient.Options{TLSConfig: &tls.Config{ServerName: host}}
	var (
		c   *imapclient.Client
		err error
	)
	switch tlsMode {
	case "starttls":
		c, err = imapclient.DialStartTLS(addr, opts)
	case "plain":
		c, err = imapclient.DialInsecure(addr, nil)
	default:
		c, err = imapclient.DialTLS(addr, opts)
	}
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := c.Login(username, password).Wait(); err != nil {
		return nil, err
	}
	preview := map[string]int{}
	if data, err := c.Select("INBOX", nil).Wait(); err == nil {
		preview["inbox"] = int(data.NumMessages)
	}
	// detect Sent mailbox
	listCmd := c.List("", "*", &imap.ListOptions{ReturnSpecialUse: true})
	defer listCmd.Close()
	sentMailbox := ""
	for {
		mb := listCmd.Next()
		if mb == nil {
			break
		}
		for _, attr := range mb.Attrs {
			if strings.EqualFold(string(attr), `\Sent`) {
				sentMailbox = mb.Mailbox
			}
		}
		if sentMailbox == "" {
			lower := strings.ToLower(mb.Mailbox)
			if lower == "sent" || lower == "sent messages" || lower == "sent items" {
				sentMailbox = mb.Mailbox
			}
		}
	}
	if sentMailbox != "" {
		if data, err := c.Select(sentMailbox, nil).Wait(); err == nil {
			preview["sent"] = int(data.NumMessages)
		}
	}
	return preview, nil
}

// ── config ────────────────────────────────────────────────────────────────────

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if cfg.Vault == "" {
		cfg.Vault = filepath.Dir(path)
	} else if !filepath.IsAbs(cfg.Vault) {
		cfg.Vault = filepath.Join(filepath.Dir(path), cfg.Vault)
	}
	return &cfg, nil
}

// ── log ───────────────────────────────────────────────────────────────────────

type logConfig struct {
	Enabled  bool
	Level    string
	Accounts []string
	Max      int
}

func readLogConfig(vaultDir string) logConfig {
	cfg := logConfig{Enabled: true, Level: "all", Max: 1000}
	b, err := os.ReadFile(filepath.Join(vaultDir, "log.md"))
	if err != nil {
		return cfg
	}
	fm := core.ParseFrontmatter(string(b))
	if strings.TrimSpace(fm["enabled"]) == "false" {
		cfg.Enabled = false
	}
	if v := strings.TrimSpace(fm["level"]); v != "" {
		cfg.Level = v
	}
	if v := strings.TrimSpace(fm["accounts"]); v != "" {
		for _, a := range strings.Split(v, ",") {
			if s := strings.TrimSpace(a); s != "" {
				cfg.Accounts = append(cfg.Accounts, s)
			}
		}
	}
	if v := strings.TrimSpace(fm["max"]); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Max)
	}
	return cfg
}

func writeBisetLog(vaultDir, inboxKey string, lines []string) {
	if len(lines) == 0 {
		return
	}
	cfg := readLogConfig(vaultDir)
	if !cfg.Enabled {
		return
	}
	if len(cfg.Accounts) > 0 {
		found := false
		for _, a := range cfg.Accounts {
			if strings.EqualFold(a, inboxKey) {
				found = true
				break
			}
		}
		if !found {
			return
		}
	}

	logFile := filepath.Join(vaultDir, "log.md")
	accounts := strings.Join(cfg.Accounts, ", ")
	header := fmt.Sprintf("---\ncontact: biset\nsubject: log\nenabled: %v\nlevel: %s\naccounts: %s\nmax: %d\nstatus: \n---\n",
		cfg.Enabled, cfg.Level, accounts, cfg.Max)

	var existingLines []string
	if b, err := os.ReadFile(logFile); err == nil {
		c := string(b)
		if strings.HasPrefix(c, "---") {
			parts := strings.SplitN(c, "---", 3)
			if len(parts) >= 3 {
				c = strings.TrimLeft(parts[2], "\n")
			}
		}
		for _, l := range strings.Split(c, "\n") {
			if l != "" {
				existingLines = append(existingLines, l)
			}
		}
	}

	// Deduplicate: skip incoming lines already in existing log.
	existingSet := make(map[string]bool, len(existingLines))
	for _, l := range existingLines {
		existingSet[l] = true
	}
	var newLines []string
	for _, l := range lines {
		if !existingSet[l] {
			newLines = append(newLines, l)
		}
	}
	allLines := append(newLines, existingLines...)
	// sort descending by timestamp prefix
	for i := 1; i < len(allLines); i++ {
		for j := i; j > 0 && allLines[j] > allLines[j-1]; j-- {
			allLines[j], allLines[j-1] = allLines[j-1], allLines[j]
		}
	}
	if len(allLines) > cfg.Max {
		allLines = allLines[:cfg.Max]
	}

	result := header + "\n" + strings.Join(allLines, "\n") + "\n"
	core.WriteIfChanged(logFile, result)
}

// ── file helpers ──────────────────────────────────────────────────────────────

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ── status ────────────────────────────────────────────────────────────────────

func runStatus(cfg *Config) {
	lockPath := filepath.Join(cfg.Vault, ".data", ".biset.lock")
	daemonStatus := "not running"
	if b, err := os.ReadFile(lockPath); err == nil {
		var pid int
		fmt.Sscanf(string(b), "%d", &pid)
		if pid > 0 && isBisetProcess(pid) {
			daemonStatus = fmt.Sprintf("running (pid %d)", pid)
		}
	}

	emails, _ := core.ScanEmails(cfg.Vault)
	threads, _ := core.ScanThreads(cfg.Vault)

	fmt.Printf("biset:   %s\n", daemonStatus)
	fmt.Printf("vault:   %s\n", cfg.Vault)
	fmt.Printf("emails:  %d\n", len(emails))
	fmt.Printf("threads: %d\n", len(threads))
}

// ── process management ────────────────────────────────────────────────────────

func acquireLock(vaultDir string) (string, bool) {
	lockPath := filepath.Join(vaultDir, ".data", ".biset.lock")
	os.MkdirAll(filepath.Join(vaultDir, ".data"), 0755) //nolint:errcheck
	if b, err := os.ReadFile(lockPath); err == nil {
		var pid int
		fmt.Sscanf(string(b), "%d", &pid)
		if pid > 0 && isBisetProcess(pid) {
			return lockPath, false
		}
		os.Remove(lockPath) //nolint:errcheck
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return lockPath, false
	}
	fmt.Fprintf(f, "%d", os.Getpid())
	f.Close()
	return lockPath, true
}

func isBisetProcess(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil || proc.Signal(syscall.Signal(0)) != nil {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	out, err := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-o", "comm=").Output()
	if err != nil {
		return false
	}
	return filepath.Base(strings.TrimSpace(string(out))) == filepath.Base(exe)
}

// killExistingBiset sends SIGKILL to any biset process holding the vault lock.
func killExistingBiset(vaultDir string) {
	lockPath := filepath.Join(vaultDir, ".data", ".biset.lock")
	b, err := os.ReadFile(lockPath)
	if err != nil {
		return
	}
	var pid int
	fmt.Sscanf(string(b), "%d", &pid)
	if pid <= 0 || pid == os.Getpid() {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	if proc.Signal(syscall.Signal(0)) != nil {
		os.Remove(lockPath) //nolint:errcheck
		return
	}
	log.Printf("[main] killing existing biset pid=%d", pid)
	proc.Signal(syscall.SIGKILL) //nolint:errcheck
	time.Sleep(200 * time.Millisecond)
	os.Remove(lockPath) //nolint:errcheck
}

func watchConfigFile(configPath string) <-chan struct{} {
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
