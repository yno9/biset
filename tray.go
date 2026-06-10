package main

import (
	"context"
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
	"github.com/yd7a/biset/core"
)

//go:embed assets/icon.png
var iconData []byte

func RunTray(cfg *Config, mgr *core.Manager, configPath string, interval time.Duration, servePort int) {
	systray.Run(func() { onTrayReady(cfg, mgr, configPath, interval, servePort) }, func() {})
}

func onTrayReady(cfg *Config, mgr *core.Manager, configPath string, interval time.Duration, servePort int) {
	systray.SetTemplateIcon(iconData, iconData)
	systray.SetTooltip("biset")

	vaultDisplay := cfg.Vault
	if home, err := os.UserHomeDir(); err == nil {
		vaultDisplay = strings.Replace(cfg.Vault, home, "~", 1)
	}
	mVault := systray.AddMenuItem(vaultDisplay, cfg.Vault)

	// serve toggle
	defaultPort := servePort
	if defaultPort == 0 {
		defaultPort = 1080
	}
	var serveCancel context.CancelFunc
	mServe := systray.AddMenuItem("Serve", "")
	if servePort > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		serveCancel = cancel
		go runServeContext(ctx, cfg, servePort, "") //nolint:errcheck
		mServe.SetTitle(fmt.Sprintf("Serving :%d", servePort))
		systray.SetTooltip(fmt.Sprintf("biset serve :%d", servePort))
	}
	go func() {
		for range mServe.ClickedCh {
			if serveCancel != nil {
				serveCancel()
				serveCancel = nil
				mServe.SetTitle("Serve")
				systray.SetTooltip("biset")
			} else {
				ctx, cancel := context.WithCancel(context.Background())
				serveCancel = cancel
				go runServeContext(ctx, cfg, defaultPort, "") //nolint:errcheck
				mServe.SetTitle(fmt.Sprintf("Serving :%d", defaultPort))
				systray.SetTooltip(fmt.Sprintf("biset serve :%d", defaultPort))
			}
		}
	}()

	mChangeVault := systray.AddMenuItem("Vault…", "")

	// Config submenu
	type configEntry struct{ label, path string }
	var configEntries []configEntry
	configEntries = append(configEntries, configEntry{"biset.json", configPath})
	installDir := filepath.Dir(configPath)
	if dirs, err := os.ReadDir(filepath.Join(installDir, "connectors")); err == nil {
		for _, d := range dirs {
			if !d.IsDir() {
				continue
			}
			p := filepath.Join(installDir, "connectors", d.Name(), "config.json")
			if _, err := os.Stat(p); err == nil {
				configEntries = append(configEntries, configEntry{d.Name(), p})
			}
		}
	}
	mConfig := systray.AddMenuItem("Config", "")
	var configSubItems []*systray.MenuItem
	for _, e := range configEntries {
		configSubItems = append(configSubItems, mConfig.AddSubMenuItem(e.label, e.path))
	}

	mQuit := systray.AddMenuItem("Quit", "")

	// notifiedSet tracks message keys already sent as desktop notifications.
	notifiedSet := map[string]bool{}
	var notifiedMu sync.Mutex

	syncNow := func(notify bool) {
		systray.SetTooltip("biset — syncing…")
		_, notifications := runSync(cfg, mgr)
		mVault.SetTitle(fmt.Sprintf("%s (%s)", vaultDisplay, time.Now().Format("15:04")))
		systray.SetTooltip("biset")
		if notify && len(notifications) > 0 {
			notifiedMu.Lock()
			var fresh []SyncNotification
			for _, n := range notifications {
				key := n.MessageID
				if key == "" {
					key = fmt.Sprintf("%d|%s", n.Ts, n.Contact)
				}
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

	for i, sub := range configSubItems {
		i, sub := i, sub
		go func() {
			for range sub.ClickedCh {
				exec.Command("open", "-t", configEntries[i].path).Start() //nolint:errcheck
			}
		}()
	}

	StartWatcher(cfg, mgr, configPath, interval, syncNow, func() { systray.Quit() })

	// Config watcher
	configChanged := watchConfigFile(configPath)

	for {
		select {
		case <-configChanged:
			fmt.Println("config changed — reloading")
			if newCfg, err := loadConfig(configPath); err == nil {
				cfg = newCfg
			}
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
		case <-mQuit.ClickedCh:
			mgr.Stop()
			systray.Quit()
			return
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
