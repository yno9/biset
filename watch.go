package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"biset/vault"
)

// WatchVaultEvents returns two channels: action fires when a vault MD file has
// an actionable status change; quit fires when biset-quit.json is created.
func WatchVaultEvents(cfg *vault.Config, configPath string) (action <-chan struct{}, quit <-chan struct{}) {
	ach := make(chan struct{}, 1)
	qch := make(chan struct{})
	bisetDir := filepath.Dir(configPath)
	go watchVault(cfg.Vault, bisetDir, func() {
		select {
		case ach <- struct{}{}:
		default:
		}
	}, func() {
		close(qch)
	})
	return ach, qch
}

// StartWatcher wires up periodic ticks, vault MD change detection and the
// relay SSE Changed() channel into a single onSync callback.
func StartWatcher(
	cfg *vault.Config,
	mgr *Manager,
	configPath string,
	interval time.Duration,
	onSync func(notify bool),
	onQuit func(),
) {
	go func() {
		for range mgr.Changed() {
			go onSync(true)
		}
	}()

	bisetDir := filepath.Dir(configPath)
	go watchVault(cfg.Vault, bisetDir, func() { go onSync(false) }, onQuit)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			go onSync(false)
		}
	}()

	go onSync(false)
}

// watchVault monitors the vault root for MD files whose `status:` frontmatter
// flips to an actionable value (send/seen/follow) or whose body contains the
// `!b` shorthand. Triggers onAction (debounced 500ms). Quits on the
// "biset-quit.json" sentinel under bisetDir.
func watchVault(vaultDir, bisetDir string, onAction func(), onQuit func()) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	defer watcher.Close()

	watcher.Add(vaultDir) //nolint:errcheck
	watcher.Add(bisetDir) //nolint:errcheck
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
			if base == "biset-quit.json" && event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				os.Remove(event.Name) //nolint:errcheck
				if onQuit != nil {
					onQuit()
				}
				return
			}
			// New directory under vault → start watching it (inbox dirs may be created at runtime).
			if event.Op&fsnotify.Create != 0 {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() && filepath.Dir(event.Name) == vaultDir {
					watcher.Add(event.Name) //nolint:errcheck
				}
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
			fm := vault.ParseFrontmatter(string(b))
			status := strings.TrimSpace(fm["status"])
			hasBangB := strings.Contains(vault.ExtractBody(string(b)), "!b")
			if status != "send" && status != "seen" && status != "follow" && !hasBangB {
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
