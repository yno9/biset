package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"github.com/fsnotify/fsnotify"
	"github.com/yd7a/biset/core"
)

//go:embed assets/icon.png
var iconData []byte

func RunTray(cfg *Config, mgr *core.Manager, configPath string, interval time.Duration) {
	systray.Run(func() { onTrayReady(cfg, mgr, configPath, interval) }, func() {})
}

func onTrayReady(cfg *Config, mgr *core.Manager, configPath string, interval time.Duration) {
	systray.SetTemplateIcon(iconData, iconData)
	systray.SetTooltip("biset")

	mSync := systray.AddMenuItem("Sync now", "")
	mStatus := systray.AddMenuItem("Last sync: —", "")
	mStatus.Disable()
	systray.AddSeparator()

	vaultDisplay := cfg.Vault
	if home, err := os.UserHomeDir(); err == nil {
		vaultDisplay = strings.Replace(cfg.Vault, home, "~", 1)
	}
	mVault := systray.AddMenuItem(vaultDisplay, cfg.Vault)

	// per-inbox items
	type inboxItem struct {
		key  string
		dir  string
		item *systray.MenuItem
	}
	var inboxItems []inboxItem
	if entries, err := os.ReadDir(cfg.Vault); err == nil {
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			dir := filepath.Join(cfg.Vault, e.Name())
			item := systray.AddMenuItem("- "+e.Name(), dir)
			inboxItems = append(inboxItems, inboxItem{e.Name(), dir, item})
		}
	}

	systray.AddSeparator()
	mChangeVault := systray.AddMenuItem("Change vault", "")
	mRestart := systray.AddMenuItem("Restart", "")
	mQuit := systray.AddMenuItem("Quit", "")

	// notifiedSet tracks message keys already sent as desktop notifications.
	notifiedSet := map[string]bool{}
	var notifiedMu sync.Mutex

	syncNow := func(notify bool) {
		mStatus.SetTitle("Syncing…")
		systray.SetTooltip("biset — syncing…")
		_, notifications := runSync(cfg, mgr)
		mStatus.SetTitle(fmt.Sprintf("Last sync: %s", time.Now().Format("15:04")))
		systray.SetTooltip("biset")
		if notify && len(notifications) > 0 {
			notifiedMu.Lock()
			var fresh []SyncNotification
			for _, n := range notifications {
				key := fmt.Sprintf("%d|%s", n.Ts, n.Contact)
				if !notifiedSet[key] {
					notifiedSet[key] = true
					fresh = append(fresh, n)
				}
			}
			notifiedMu.Unlock()
			if len(fresh) > 0 {
				newest := fresh[0]
				for _, n := range fresh[1:] {
					if n.Ts > newest.Ts {
						newest = n
					}
				}
				sendNotify("biset", newest.Contact, newest.Body)
			}
		}
	}

	// inbox click handlers
	for _, ai := range inboxItems {
		ai := ai
		go func() {
			for range ai.item.ClickedCh {
				openVault(ai.dir)
			}
		}()
	}

	// Wire IDLE notify → syncNow(true) with 2s debounce to avoid rapid re-syncs
	// when connectors emit multiple change events in quick succession.
	var (
		debounceTimer *time.Timer
		debounceMu    sync.Mutex
	)
	mgr.SetOnChange(func() {
		debounceMu.Lock()
		defer debounceMu.Unlock()
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
		debounceTimer = time.AfterFunc(2*time.Second, func() { syncNow(true) })
	})

	// Initial sync
	go syncNow(false)

	// Vault watcher for status: send + signal files
	bisetDir := filepath.Dir(configPath)
	go watchVaultSend(cfg.Vault, bisetDir, func() { go syncNow(false) })


	// Interval ticker
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Config watcher
	configChanged := watchConfigFile(configPath)

	for {
		select {
		case <-ticker.C:
			go syncNow(false)
		case <-configChanged:
			fmt.Println("config changed — reloading")
			if newCfg, err := loadConfig(configPath); err == nil {
				cfg = newCfg
			}
			go syncNow(false)
		case <-mSync.ClickedCh:
			go syncNow(false)
		case <-mVault.ClickedCh:
			openVault(cfg.Vault)
		case <-mChangeVault.ClickedCh:
			go func() {
				out, err := exec.Command("osascript", "-e",
					`choose folder with prompt "Select vault folder"`).Output()
				if err != nil {
					return
				}
				// osascript returns "alias Macintosh HD:Users:..." format
				path := strings.TrimSpace(string(out))
				path = strings.TrimPrefix(path, "alias ")
				// convert HFS path to POSIX
				posix, err := exec.Command("osascript", "-e",
					fmt.Sprintf(`POSIX path of "%s"`, path)).Output()
				if err != nil {
					return
				}
				newVault := strings.TrimRight(strings.TrimSpace(string(posix)), "/")
				// update config.json
				if c, err := loadConfig(configPath); err == nil {
					c.Vault = newVault
					if b, err := json.MarshalIndent(c, "", "  "); err == nil {
						os.WriteFile(configPath, b, 0644) //nolint:errcheck
						cfg.Vault = newVault
						vaultDisplay := newVault
						if home, err := os.UserHomeDir(); err == nil {
							vaultDisplay = strings.Replace(newVault, home, "~", 1)
						}
						mVault.SetTitle(vaultDisplay)
					}
				}
			}()
		case <-mRestart.ClickedCh:
			mgr.Stop()
			exe, _ := os.Executable()
			exec.Command(exe, os.Args[1:]...).Start() //nolint:errcheck
			systray.Quit()
			return
		case <-mQuit.ClickedCh:
			mgr.Stop()
			systray.Quit()
			return
		}
	}
}


func watchVaultSend(vaultDir, bisetDir string, onSend func()) {
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
			if filepath.Base(event.Name) == "biset-open-vault.json" &&
				event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				os.Remove(event.Name) //nolint:errcheck
				openVault(vaultDir)
				continue
			}
			if filepath.Base(event.Name) == "biset-quit.json" &&
				event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				os.Remove(event.Name) //nolint:errcheck
				systray.Quit()
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
			if strings.TrimSpace(fm["status"]) != "send" {
				continue
			}
			if !pending {
				pending = true
				debounce.Reset(500 * time.Millisecond)
			}
		case <-debounce.C:
			if pending {
				pending = false
				onSend()
			}
		case <-watcher.Errors:
		}
	}
}

func sendNotify(title, contact, body string) {
	msg := contact + ":\n" + body
	script := fmt.Sprintf(`display notification %q with title %q`, msg, title)
	exec.Command("osascript", "-e", script).Start() //nolint:errcheck
}

func openVault(vaultPath string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", vaultPath)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", vaultPath)
	default:
		cmd = exec.Command("xdg-open", vaultPath)
	}
	cmd.Start() //nolint:errcheck
}
