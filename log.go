package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"biset/vault"
)

// writeSyncLog formats one line per message ("ts from → to") and appends the
// batch to vault/log.md via writeBisetLog. Skips when messages is empty.
func writeSyncLog(vaultDir, mailboxName string, messages []vault.Message) {
	if len(messages) == 0 {
		return
	}
	var lines []string
	mbxID := jmap.ID(vault.MakeMailboxID(mailboxName))
	for _, m := range messages {
		ts := vault.TimeVal(m.ReceivedAt).Local().Format("2006-01-02 15:04")
		from := vault.MessageFromAddr(m)
		if name := vault.MessageFromName(m); name != "" {
			from = name
		}
		var to string
		if m.MailboxIDs[mbxID] && !strings.EqualFold(vault.MessageFromAddr(m), mailboxName) {
			to = mailboxName
		} else if len(m.To) > 0 && m.To[0] != nil {
			to = m.To[0].Email
		} else {
			to = "?"
		}
		lines = append(lines, fmt.Sprintf("%s %s → %s", ts, from, to))
	}
	writeBisetLog(vaultDir, mailboxName, lines)
}

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
	fm := vault.ParseFrontmatter(string(b))
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

func writeBisetLog(vaultDir, mailboxName string, lines []string) {
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
			if strings.EqualFold(a, mailboxName) {
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
	for i := 1; i < len(allLines); i++ {
		for j := i; j > 0 && allLines[j] > allLines[j-1]; j-- {
			allLines[j], allLines[j-1] = allLines[j-1], allLines[j]
		}
	}
	if len(allLines) > cfg.Max {
		allLines = allLines[:cfg.Max]
	}

	result := header + "\n" + strings.Join(allLines, "\n") + "\n"
	vault.WriteIfChanged(logFile, result)
}
