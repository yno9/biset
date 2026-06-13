package main

import (
	"context"
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

Commands
  up                      Start biset (sync + watch, macOS: menu bar icon)
  down                    Stop running biset
  sync                    Trigger a sync
  relays                  List relays
  relays up [name]        Start a local relay
  relays down [name]      Stop a local relay
  relays config [name]    Edit a local relay's config
  server on               Start JMAP server
  server off              Stop JMAP server
  config                  Edit biset config
  notification            Enable/disable desktop notifications
  update                  Update to latest version
  version                 Print version

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
Commands
  up                      Start biset
  down                    Stop biset
  sync                    Trigger a sync
  relays                  List relays
  relays up [name]        Start a local relay
  relays down [name]      Stop a local relay
  relays config [name]    Edit a local relay's config
  server on               Start JMAP server
  server off              Stop JMAP server
  config                  Edit biset config
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
		runSync(cfg, mgr)
		if fullSyncFlag {
			vault.PurgeMessageCache(cfg.Vault)
			runSync(cfg, mgr)
			vault.CleanupOrphanedMDs(cfg.Vault)
		}

	default: // "up"
		if os.Getenv("BISET_DAEMON") == "" {
			logPath := filepath.Join(bisetDir, "biset.log")
			logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatalf("cannot open log file: %v", err)
			}
			cmd := exec.Command(os.Args[0], os.Args[1:]...)
			cmd.Env = append(os.Environ(), "BISET_DAEMON=1")
			cmd.Stdout = logFile
			cmd.Stderr = logFile
			if err := cmd.Start(); err != nil {
				log.Fatalf("cannot start daemon: %v", err)
			}
			fmt.Printf("biset: started (pid %d)\n", cmd.Process.Pid)
			return
		}
		startManagedRelays(cfg, bisetDir)
		mgr.WatchRelays()
		lockPath, ok := acquireLock(cfg.Vault)
		if !ok {
			fmt.Fprintln(os.Stderr, "biset: already running")
			os.Exit(1)
		}
		defer os.Remove(lockPath)
		watchLoop(cfg, mgr, configPath, pgpKey)
	}
}

func runServerCommand(cfg *vault.Config, bisetDir, configPath string, args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "on":
			interfaces.RunServerSet(configPath, true)
			return
		case "off":
			interfaces.RunServerSet(configPath, false)
			return
		}
	}
	fmt.Fprintf(os.Stderr, "Usage: biset server on|off\n")
	os.Exit(1)
}

func watchLoop(cfg *vault.Config, mgr *Manager, configPath string, pgpKey string) {
	configChanged := interfaces.WatchConfigFile(configPath)
	vaultAction, quit := WatchVaultEvents(cfg, configPath)

	var serverCancel context.CancelFunc
	startServer := func(c *vault.Config) {
		if serverCancel != nil {
			serverCancel()
		}
		ctx, cancel := context.WithCancel(context.Background())
		serverCancel = cancel
		go startJMAPServer(ctx, c, pgpKey)
	}
	stopServer := func() {
		if serverCancel != nil {
			serverCancel()
			serverCancel = nil
		}
	}

	if cfg.Server.Enabled() {
		startServer(cfg)
	}

	runSync(cfg, mgr)
	for {
		select {
		case <-mgr.Changed():
			runSync(cfg, mgr)
		case <-vaultAction:
			runSync(cfg, mgr)
		case <-configChanged:
			fmt.Println("config changed — reloading")
			if newCfg, err := vault.LoadConfig(configPath); err == nil {
				wasEnabled := cfg.Server.Enabled()
				cfg = newCfg
				switch {
				case !wasEnabled && cfg.Server.Enabled():
					startServer(cfg)
				case wasEnabled && !cfg.Server.Enabled():
					stopServer()
				}
			}
			runSync(cfg, mgr)
		case <-quit:
			stopServer()
			return
		}
	}
}
