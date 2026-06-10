package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/yd7a/biset/core"
)

// StartWatcher sets up all sync triggers and returns immediately.
// onSync is called whenever any trigger fires; onQuit is called when biset-quit.json is written.
func StartWatcher(
	cfg *Config,
	mgr *core.Manager,
	configPath string,
	interval time.Duration,
	onSync func(notify bool),
	onQuit func(),
) {
	// Connector notifications — debounce/throttle is the connector's responsibility
	mgr.SetOnChange(func() { go onSync(true) })

	// Vault file watcher: status: send/seen or !b body → sync
	bisetDir := filepath.Dir(configPath)
	go watchVault(cfg.Vault, bisetDir, func() { go onSync(false) }, onQuit)

	// Periodic ticker — fallback for missed notifications
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			go onSync(false)
		}
	}()

	// Initial sync
	go onSync(false)
}

// watchVault monitors vault MD files for action frontmatter (status: send/seen, !b body).
// onAction is called when a matching file change is detected; onQuit when biset-quit.json appears.
func watchVault(vaultDir, bisetDir string, onAction func(), onQuit func()) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	defer watcher.Close()

	watcher.Add(vaultDir)  //nolint:errcheck
	watcher.Add(bisetDir)  //nolint:errcheck
	entries, _ := os.ReadDir(vaultDir)
	for _, d := range entries {
		if d.IsDir() {
			watcher.Add(filepath.Join(vaultDir, d.Name())) //nolint:errcheck
		}
	}

	debounce := time.NewTimer(0)
	<-debounce.C
	pending := false

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			base := filepath.Base(event.Name)
			if base == "biset-open-vault.json" && event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				os.Remove(event.Name) //nolint:errcheck
				openVault(vaultDir)
				continue
			}
			if base == "biset-quit.json" && event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				os.Remove(event.Name) //nolint:errcheck
				if onQuit != nil {
					onQuit()
				}
				return
			}
			if !strings.HasSuffix(event.Name, ".md") {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			b, err := os.ReadFile(event.Name)
			if err != nil {
				continue
			}
			fm := core.ParseFrontmatter(string(b))
			status := strings.TrimSpace(fm["status"])
			hasBangB := strings.Contains(core.ExtractBody(string(b)), "!b")
			if status != "send" && status != "seen" && !hasBangB {
				continue
			}
			if !pending {
				pending = true
				debounce.Reset(500 * time.Millisecond)
			}
		case <-debounce.C:
			if pending {
				pending = false
				onAction()
			}
		case <-watcher.Errors:
		}
	}
}
