package main

import (
	"fmt"
	"os"
	"os/exec"
)

// handleHelp prints the top-level CLI usage.
func handleHelp() {
	fmt.Print(`Your email. Local. Private.

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

`)
}

// handleConfig opens configPath in $EDITOR (falls back to nano/vim/vi or
// stdout). Returns after the editor exits.
func handleConfig(configPath string) {
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

// handleUpdate downloads and runs the latest install.sh. Exits the process on
// failure (the user explicitly asked to upgrade — no recovery path).
func handleUpdate() {
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
}
