package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"biset/interfaces"
	"biset/vault"
)

var version = "dev"


func main() {
	// Usage:
	//   biset [up]          start daemon (watch+sync, macOS: tray)
	//   biset down          stop running daemon
	//   biset sync          one-shot sync and exit
	//   biset version       print version

	intervalFlag := time.Minute
	fullSyncFlag := false

	subcommand := ""
	var configArgument string

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "up", "down", "sync", "version", "config", "notification", "update", "relays", "server":
			if subcommand == "" {
				subcommand = args[i]
			}
		case "--help", "-help", "-h":
			subcommand = "help"
		case "--daemon", "-daemon":
			if subcommand == "" {
				subcommand = "up"
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
		case "--full", "-full":
			fullSyncFlag = true
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
	case "help":
		fmt.Print(`
Your email. Local. Private.

USAGE
  biset <subcommand> [flags]

SUBCOMMANDS
  up            Start biset (sync + watch, macOS: menu bar icon)
  down          Stop running biset
  sync          Trigger a sync
  relays                   List relays
  relays up [name]          Start a local relay
  relays down [name]        Stop a local relay
  relays config [name]      Edit a local relay's config
  server up                Start JMAP server
  server down              Stop JMAP server
  config        Edit biset config
  notification  Enable/disable desktop notifications
  update        Update to latest version
  version       Print version

FLAGS
  --interval duration   Sync interval (default 1m)

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
		if editor == "" {
			b, _ := os.ReadFile(configPath)
			fmt.Println(configPath)
			fmt.Println()
			fmt.Print(string(b))
			return
		}
		cmd := exec.Command(editor, configPath)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run() //nolint:errcheck
		return
	}

	if subcommand == "notification" {
		interfaces.RunNotification(configPath)
		return
	}

	if subcommand == "update" {
		tmp, err := os.CreateTemp("", "biset-install-*.sh")
		if err != nil {
			fmt.Fprintf(os.Stderr, "update: %v\n", err)
			os.Exit(1)
		}
		defer os.Remove(tmp.Name())
		tmp.Close()
		curl := exec.Command("curl", "-fsSL",
			"https://github.com/yno9/biset/releases/latest/download/install.sh",
			"-o", tmp.Name())
		curl.Stderr = os.Stderr
		if err := curl.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "update: download failed: %v\n", err)
			os.Exit(1)
		}
		sh := exec.Command("sh", tmp.Name())
		sh.Stdin = os.Stdin
		sh.Stdout = os.Stdout
		sh.Stderr = os.Stderr
		if err := sh.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "update: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if subcommand == "" || subcommand == "down" || subcommand == "relays" || subcommand == "server" {
		cfg, err := vault.LoadConfig(configPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		if subcommand == "" {
			interfaces.RunStatus(cfg, isBisetProcess)
			fmt.Print(`
SUBCOMMANDS
  up                       Start biset
  down                     Stop biset
  sync                     Trigger a sync
  relays                   List relays
  relays up [name]          Start a local relay
  relays down [name]        Stop a local relay
  relays config [name]      Edit a local relay's config
  server up                Start JMAP server
  server down              Stop JMAP server
  config                   Edit biset config
`)
			return
		}
		if subcommand == "relays" {
			bisetDir := filepath.Dir(configPath)
			var nodeArgs []string
			found := false
			for _, a := range args {
				if a == "relays" {
					found = true
					continue
				}
				if found {
					nodeArgs = append(nodeArgs, a)
				}
			}
			runRelaysCommand(cfg, bisetDir, nodeArgs)
			return
		}
		if subcommand == "server" {
			bisetDir := filepath.Dir(configPath)
			var serverArgs []string
			found := false
			for _, a := range args {
				if a == "server" {
					found = true
					continue
				}
				if found {
					serverArgs = append(serverArgs, a)
				}
			}
			runServerCommand(cfg, bisetDir, configPath, serverArgs)
			return
		}
		// down
		stopManagedRelays(cfg, filepath.Dir(configPath))
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
		fmt.Fprintf(os.Stderr, "biset: config not found: %s\n", configPath)
		os.Exit(1)
	}

	cfg, err := vault.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// lock check
	lockPath := filepath.Join(cfg.Vault, ".data", ".biset.lock")
	if b, err := os.ReadFile(lockPath); err == nil {
		var pid int
		fmt.Sscanf(string(b), "%d", &pid)
		if pid > 0 && isBisetProcess(pid) {
			if subcommand == "up" {
				fmt.Fprintf(os.Stderr, "biset: already running (pid %d)\n", pid)
				os.Exit(1)
			}
		} else {
			os.Remove(lockPath) //nolint:errcheck
		}
	}

	vault.ReThreadVault(cfg.Vault)

	mgr := NewManager(cfg)

	bisetDir := filepath.Dir(configPath)
	keyPEM := loadOrGenerateKey(filepath.Join(bisetDir, "private_key.pem"))
	pgpKey := loadPGPKey(keyPEM)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		stopManagedRelays(cfg, bisetDir)
		os.Exit(0)
	}()

	switch subcommand {
	case "sync":
		_ = fullSyncFlag // TODO: reset node JMAP state when implemented
		runSync(cfg, mgr)

	default: // "up"
		startManagedRelays(cfg, bisetDir)
		mgr.WatchRelays()
		if cfg.Server.Enabled() {
			go startJMAPServer(cfg, pgpKey)
		}
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

func runServerCommand(cfg *vault.Config, bisetDir, configPath string, args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "up":
		if !cfg.Server.Enabled() {
			fmt.Fprintln(os.Stderr, "server: port and bind must be set in config")
			os.Exit(1)
		}
		lockPath, ok := acquireLock(cfg.Vault)
		if !ok {
			fmt.Fprintln(os.Stderr, "biset: already running")
			os.Exit(1)
		}
		defer os.Remove(lockPath)
		keyPEM := loadOrGenerateKey(filepath.Join(bisetDir, "private_key.pem"))
		pgpKey := loadPGPKey(keyPEM)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			<-sig
			os.Exit(0)
		}()
		fmt.Printf("biset server: started (pid %d) on %s:%d\n", os.Getpid(), cfg.Server.Bind, cfg.Server.Port)
		startJMAPServer(cfg, pgpKey)
	case "down":
		quitPath := filepath.Join(cfg.Vault, "biset-quit.json")
		os.WriteFile(quitPath, []byte("{}"), 0644) //nolint:errcheck
		fmt.Println("biset: stopping")
		lockPath := filepath.Join(cfg.Vault, ".data", ".biset.lock")
		for i := 0; i < 30; i++ {
			time.Sleep(100 * time.Millisecond)
			if _, err := os.Stat(lockPath); os.IsNotExist(err) {
				fmt.Println("biset: stopped")
				return
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "usage: biset server up|down\n")
		os.Exit(1)
	}
}

func watchLoop(cfg *vault.Config, mgr *Manager, configPath string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	configChanged := interfaces.WatchConfigFile(configPath)

	runSync(cfg, mgr)
	for {
		select {
		case <-ticker.C:
			runSync(cfg, mgr)
		case <-mgr.Changed():
			runSync(cfg, mgr)
		case <-configChanged:
			fmt.Println("config changed — reloading")
			if newCfg, err := vault.LoadConfig(configPath); err == nil {
				cfg = newCfg
			}
			runSync(cfg, mgr)
		}
	}
}
