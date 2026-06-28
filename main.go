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
	jmapserver "github.com/yno9/go-jmapserver"
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
		handleHelp()
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
		configPath = filepath.Join(dir, "config.json")
	}

	if subcommand == "config" {
		handleConfig(configPath)
		return
	}

	if subcommand == "update" {
		handleUpdate()
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

	// Run vault migrations before opening the Store so the Store sees the
	// post-migration on-disk state. Both helpers are one-shot (file marker
	// for ReThread; no-op when no legacy data for Migrate).
	vault.MigrateVault(cfg.Vault)
	vault.ReThreadVault(cfg.Vault, func(mailboxName string) vault.MailboxConfig {
		for _, r := range cfg.Relays {
			ic := r.MailboxConfigFor(mailboxName, r.AuthUser)
			if ic.FileFormat != "" || len(ic.Meta) > 0 || ic.MaxDisplay != 0 || ic.Notification != nil {
				return ic
			}
		}
		return vault.MailboxConfig{}
	})

	mgr := NewManager(cfg)

	bisetStore, err := jmapserver.NewStore(filepath.Join(cfg.Vault, ".data"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	bisetDir := filepath.Dir(configPath)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		stopManagedRelays(cfg, bisetDir)
		os.Exit(0)
	}()

	mgr.EnsureKeys()

	switch subcommand {
	case "sync":
		runSync(cfg, mgr, bisetStore)
		if fullSyncFlag {
			bisetStore.Purge()          // clear all stored messages (in-memory + on-disk)
			vault.PurgeState(cfg.Vault) // forget per-relay queryState → next fetch is full
			runSync(cfg, mgr, bisetStore)
			vault.CleanupOrphanedMDs(cfg.Vault, bisetStore.All(), func(mailboxName string) vault.MailboxConfig {
				return mgr.MailboxConfigFor(mailboxName, cfg)
			})
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
		watchLoop(cfg, mgr, configPath, bisetStore)
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

func watchLoop(cfg *vault.Config, mgr *Manager, configPath string, store *jmapserver.Store) {
	configChanged := interfaces.WatchConfigFile(configPath)
	vaultAction, quit := WatchVaultEvents(cfg, configPath)

	var serverCancel context.CancelFunc
	var notifyServer func()
	startServer := func(c *vault.Config) {
		if serverCancel != nil {
			serverCancel()
		}
		ctx, cancel := context.WithCancel(context.Background())
		serverCancel = cancel
		notifyServer = startJMAPServer(ctx, c, store, mgr)
	}
	stopServer := func() {
		if serverCancel != nil {
			serverCancel()
			serverCancel = nil
			notifyServer = nil
		}
	}
	sync := func() {
		runSync(cfg, mgr, store)
		if notifyServer != nil {
			notifyServer()
		}
	}

	if cfg.Server.Enabled() {
		startServer(cfg)
	}

	sync()
	for {
		select {
		case <-mgr.Changed():
			sync()
		case <-vaultAction:
			sync()
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
			sync()
		case <-quit:
			stopServer()
			return
		}
	}
}
