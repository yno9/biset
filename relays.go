package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"biset/interfaces"
	"biset/vault"
)

func startManagedRelays(cfg *vault.Config, bisetDir string) {
	for _, r := range cfg.Relays {
		if r.Local == "" {
			continue
		}
		relayUp(cfg, bisetDir, r.Local)
	}
}

func stopManagedRelays(cfg *vault.Config, bisetDir string) {
	for _, r := range cfg.Relays {
		if r.Local == "" {
			continue
		}
		relayDown(bisetDir, r.Local)
	}
}

func runRelaysCommand(cfg *vault.Config, bisetDir string, args []string) {
	if len(args) == 0 {
		listRelays(cfg)
		return
	}
	sub := args[0]
	name := ""
	if len(args) > 1 {
		name = args[1]
	}
	switch sub {
	case "up":
		if name == "" {
			fmt.Fprintln(os.Stderr, "usage: biset relays up <name>")
			os.Exit(1)
		}
		local := localForRelay(cfg, name)
		if local == "" {
			fmt.Fprintf(os.Stderr, "local relay %q not found in config\n", name)
			os.Exit(1)
		}
		relayUp(cfg, bisetDir, local)
	case "down":
		if name == "" {
			fmt.Fprintln(os.Stderr, "usage: biset relays down <name>")
			os.Exit(1)
		}
		local := localForRelay(cfg, name)
		if local == "" {
			fmt.Fprintf(os.Stderr, "local relay %q not found in config\n", name)
			os.Exit(1)
		}
		relayDown(bisetDir, local)
	case "config":
		if name == "" {
			fmt.Fprintln(os.Stderr, "usage: biset relays config <name>")
			os.Exit(1)
		}
		local := localForRelay(cfg, name)
		if local == "" {
			fmt.Fprintf(os.Stderr, "local relay %q not found in config\n", name)
			os.Exit(1)
		}
		relayConfig(bisetDir, local)
	default:
		fmt.Fprintf(os.Stderr, "unknown relays subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func localForRelay(cfg *vault.Config, name string) string {
	for _, r := range cfg.Relays {
		if r.Local != "" && (r.RelayName == name || r.Local == name) {
			return r.Local
		}
	}
	return ""
}

func shortRelayErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

func listRelays(cfg *vault.Config) {
	if len(cfg.Relays) == 0 {
		fmt.Println("no relays configured")
		return
	}

	var locals, remotes []vault.RelayConfig
	for _, r := range cfg.Relays {
		if r.Local != "" {
			locals = append(locals, r)
		} else {
			remotes = append(remotes, r)
		}
	}

	printRelayList := func(relays []vault.RelayConfig) {
		for _, r := range relays {
			name := r.RelayName
			if name == "" {
				name = r.URL
			}
			info, err := interfaces.PingRelay(r)
			if err != nil {
				fmt.Printf("- %s  disconnected: %s\n", name, shortRelayErr(err))
			} else {
				fmt.Printf("- %s  connected\n", name)
				for _, a := range info {
					if a.Total >= 0 {
						fmt.Printf("  - %s (%d)\n", a.AccountID, a.Total)
					} else {
						fmt.Printf("  - %s\n", a.AccountID)
					}
				}
			}
			fmt.Println()
		}
	}

	if len(locals) > 0 {
		fmt.Println("\nLocal relays:")
		printRelayList(locals)
	}
	if len(remotes) > 0 {
		fmt.Println("Remote relays:")
		printRelayList(remotes)
	}
}

func relayConfig(bisetDir, local string) {
	configPath := filepath.Join(relayDir(bisetDir, local), "config.json")
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
}

func relayDir(bisetDir, local string) string {
	return filepath.Join(bisetDir, "relays", local)
}

func relayBin(bisetDir, local string) string {
	return filepath.Join(relayDir(bisetDir, local), "biset-"+local)
}

func relayPIDFile(bisetDir, local string) string {
	return filepath.Join(relayDir(bisetDir, local), "pid")
}

func relayUp(cfg *vault.Config, bisetDir, local string) {
	binPath := relayBin(bisetDir, local)
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "binary not found: %s\n", binPath)
		os.Exit(1)
	}

	pidFile := relayPIDFile(bisetDir, local)
	if b, err := os.ReadFile(pidFile); err == nil {
		var pid int
		fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid)
		if pid > 0 && isRelayRunning(pid) {
			fmt.Printf("%s: already running (pid %d)\n", local, pid)
			return
		}
	}

	dir := relayDir(bisetDir, local)
	cmd := newRelayCmd(binPath, dir)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start %s: %v\n", local, err)
		os.Exit(1)
	}
	os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644) //nolint:errcheck
	fmt.Printf("%s: started (pid %d)\n", local, cmd.Process.Pid)
}

func relayDown(bisetDir, local string) {
	pidFile := relayPIDFile(bisetDir, local)
	b, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: not running (no pid file)\n", local)
		return
	}
	var pid int
	fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid)
	if pid <= 0 {
		fmt.Fprintf(os.Stderr, "%s: invalid pid file\n", local)
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil || !isRelayRunning(pid) {
		os.Remove(pidFile) //nolint:errcheck
		fmt.Printf("%s: not running\n", local)
		return
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "%s: kill: %v\n", local, err)
		return
	}
	os.Remove(pidFile) //nolint:errcheck
	fmt.Printf("%s: stopped\n", local)
}

func isRelayRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
