package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/yd7a/biset/core"
)

// SyncNotification holds info for a desktop notification.
type SyncNotification struct {
	Contact string
	Body    string
	Ts      int64
}

func runSync(cfg *Config, mgr *core.Manager) (int, []SyncNotification) {
	lockPath, ok := acquireLock(cfg.Vault)
	if !ok {
		log.Printf("sync already running — skipping")
		return 0, nil
	}
	defer os.Remove(lockPath)

	if err := os.MkdirAll(cfg.Vault, 0755); err != nil {
		log.Printf("mkdir vault: %v", err)
		return 0, nil
	}

	// 1. flush outgoing
	flushOutgoing(cfg.Vault, mgr)

	// 2. flush actions
	flushActions(cfg.Vault, mgr)

	// 3. fetch from all connectors
	var allMessages []core.Message
	for _, c := range mgr.Connectors() {
		if !c.Has("fetch") {
			continue
		}
		msgs, err := c.Fetch()
		if err != nil {
			log.Printf("[%s] fetch: %v", c.Name(), err)
			continue
		}
		allMessages = append(allMessages, msgs...)
	}

	// 4. deduplicate
	allMessages = deduplicateMessages(allMessages)
	fmt.Printf("fetched %d messages\n", len(allMessages))

	// collect notifications (received messages newer than 5 minutes ago)
	cutoff := time.Now().Add(-5 * time.Minute).UnixMilli()
	var notifications []SyncNotification
	for _, m := range allMessages {
		if isInboxMessage(m) && m.Ts >= cutoff {
			body := []rune(m.Body)
			if len(body) > 80 {
				body = body[:80]
			}
			notifications = append(notifications, SyncNotification{
				Contact: m.From,
				Body:    string(body),
				Ts:      m.Ts,
			})
		}
	}

	// 5. group, merge, render
	totalUpdated := 0
	if len(allMessages) > 0 {
		byInbox := groupByInbox(allMessages)
		for inboxKey, msgs := range byInbox {
			inboxDir := filepath.Join(cfg.Vault, inboxKey)
			threads := core.GroupThreads(msgs)
			for _, t := range threads {
				merged := core.MergeWithExisting(t, inboxDir)
				updated := writeThread(cfg.Vault, inboxKey, merged)
				totalUpdated += updated
			}
			core.RenderMissingMDs(cfg.Vault, inboxKey)
			core.EnsureNewFile(cfg.Vault, inboxKey)
			writeSyncLog(cfg.Vault, inboxKey, msgs)
		}
	}

	fmt.Printf("done — updated: %d\n", totalUpdated)
	return totalUpdated, notifications
}

// writeThread renders a thread to MD and JSON, preserving compose drafts.
func writeThread(vaultDir, inboxKey string, t core.Thread) int {
	updated := 0

	// JSON
	jsonPath, jsonContent, err := core.RenderJSON(vaultDir, inboxKey, t)
	if err != nil {
		log.Printf("render json: %v", err)
	} else {
		os.MkdirAll(filepath.Dir(jsonPath), 0755) //nolint:errcheck
		if core.WriteIfChanged(jsonPath, string(jsonContent)) {
			updated++
		}
	}

	// MD
	mdPath, mdContent := core.RenderMD(vaultDir, inboxKey, t)
	contentStr := string(mdContent)
	if existing, err := os.ReadFile(mdPath); err == nil {
		if draft := core.ExtractBody(string(existing)); draft != "" {
			contentStr = core.InjectBody(contentStr, draft)
		}
	}
	os.MkdirAll(filepath.Dir(mdPath), 0755) //nolint:errcheck
	if core.WriteIfChanged(mdPath, contentStr) {
		updated++
	}

	return updated
}

// groupByInbox separates messages by inbox key (from Meta or From field).
func groupByInbox(msgs []core.Message) map[string][]core.Message {
	result := map[string][]core.Message{}
	for _, m := range msgs {
		inbox := m.Meta["inbox_key"]
		if inbox == "" {
			inbox = m.From
		}
		result[inbox] = append(result[inbox], m)
	}
	return result
}

func isInboxMessage(m core.Message) bool {
	return m.Meta[core.MetaMyRole] != ""
}

// ── outgoing ──────────────────────────────────────────────────────────────────

func flushOutgoing(vaultDir string, mgr *core.Manager) int {
	count := 0
	entries, _ := os.ReadDir(vaultDir)
	for _, d := range entries {
		if !d.IsDir() {
			continue
		}
		inboxKey := d.Name()
		inboxDir := filepath.Join(vaultDir, inboxKey)
		files, _ := os.ReadDir(inboxDir)
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".md") {
				continue
			}
			if flushMDSend(filepath.Join(inboxDir, f.Name()), inboxKey, mgr) {
				count++
			}
		}
	}
	// also scan vault root
	rootFiles, _ := os.ReadDir(vaultDir)
	for _, f := range rootFiles {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".md") {
			continue
		}
		if flushMDSend(filepath.Join(vaultDir, f.Name()), "", mgr) {
			count++
		}
	}
	return count
}

func flushMDSend(filePath, inboxKey string, mgr *core.Manager) bool {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	fm := core.ParseFrontmatter(string(content))
	if strings.TrimSpace(fm["status"]) != string(core.ActionSend) {
		return false
	}

	// resolve inbox
	inbox := strings.TrimSpace(fm["inbox"])
	if inbox == "" {
		inbox = inboxKey
	}

	body := core.ExtractBody(string(content))
	if body == "" {
		log.Printf("skip %s: no body", filepath.Base(filePath))
		return false
	}

	contact := strings.TrimSpace(fm["contact"])
	if contact == "" {
		log.Printf("skip %s: no contact", filepath.Base(filePath))
		return false
	}

	protocol := strings.TrimSpace(fm["protocol"])
	if protocol == "" {
		protocol = "smtp"
	}

	c := mgr.ConnectorFor(protocol)
	if c == nil {
		log.Printf("skip %s: no connector for protocol %q", filepath.Base(filePath), protocol)
		return false
	}

	subject := strings.Trim(fm["subject"], "\"")
	parentID := wrapAngle(fm["in"])
	if parentID == "" {
		parentID = wrapAngle(fm["id"]) // fallback to thread id (e.g. claude)
	}
	cc := strings.TrimSpace(fm["cc"])
	bcc := strings.TrimSpace(fm["bcc"])

	if err := c.Send(inbox, contact, cc, bcc, subject, body, parentID); err != nil {
		log.Printf("send error %s: %v", filepath.Base(filePath), err)
		return false
	}

	if filepath.Base(filePath) == "_new.md" {
		os.WriteFile(filePath, []byte(core.NewFileTemplate), 0644) //nolint:errcheck
	} else {
		cleared := core.ClearBody(string(content))
		cleared = strings.Replace(cleared, "status: send", "status: ", 1)
		os.WriteFile(filePath, []byte(cleared), 0644) //nolint:errcheck
	}

	fmt.Printf("sent: %s → %s\n", filepath.Base(filePath), contact)
	return true
}

// ── actions ───────────────────────────────────────────────────────────────────

func flushActions(vaultDir string, mgr *core.Manager) int {
	count := 0
	inboxDirs, _ := os.ReadDir(vaultDir)
	for _, d := range inboxDirs {
		if !d.IsDir() {
			continue
		}
		inboxKey := d.Name()
		dirPath := filepath.Join(vaultDir, inboxKey)
		entries, _ := os.ReadDir(dirPath)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			filePath := filepath.Join(dirPath, e.Name())
			b, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			fm := core.ParseFrontmatter(string(b))
			status := core.Action(strings.TrimSpace(fm["status"]))
			if status == "" || status == core.ActionSend {
				continue
			}

			protocol := strings.TrimSpace(fm["protocol"])
			if protocol == "" {
				protocol = "smtp"
			}
			c := mgr.ConnectorFor(protocol)
			messageID := wrapAngle(fm["in"])
			if c != nil && messageID != "" {
				if err := c.Handle(inboxKey, messageID, status); err != nil {
					log.Printf("action error %s: %v", e.Name(), err)
					continue
				}
			}
			os.Remove(filePath) //nolint:errcheck
			base := strings.TrimSuffix(e.Name(), ".md") + ".json"
			os.Remove(filepath.Join(dirPath, ".data", base)) //nolint:errcheck
			fmt.Printf("%s: %s\n", status, e.Name())
			count++
		}
	}
	return count
}

// ── helpers ───────────────────────────────────────────────────────────────────

func deduplicateMessages(msgs []core.Message) []core.Message {
	seen := map[string]bool{}
	out := msgs[:0:len(msgs)]
	for _, m := range msgs {
		key := m.MessageID
		if key == "" {
			key = fmt.Sprintf("%d|%s", m.Ts, m.From)
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, m)
		}
	}
	return out
}

func wrapAngle(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "<") {
		s = "<" + s + ">"
	}
	return s
}

func acquireLock(vaultDir string) (string, bool) {
	lockPath := filepath.Join(vaultDir, ".biset.lock")
	if b, err := os.ReadFile(lockPath); err == nil {
		var pid int
		fmt.Sscanf(string(b), "%d", &pid)
		if pid > 0 && isBisetProcess(pid) {
			return lockPath, false
		}
		os.Remove(lockPath) //nolint:errcheck
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return lockPath, false
	}
	fmt.Fprintf(f, "%d", os.Getpid())
	f.Close()
	return lockPath, true
}

func isBisetProcess(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil || proc.Signal(syscall.Signal(0)) != nil {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	out, err := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-o", "comm=").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == filepath.Base(exe)
}

// ── log ───────────────────────────────────────────────────────────────────────

func writeSyncLog(vaultDir, inboxKey string, msgs []core.Message) {
	if len(msgs) == 0 {
		return
	}
	var lines []string
	for _, m := range msgs {
		ts := time.UnixMilli(m.Ts).Local().Format("2006-01-02 15:04")
		from := m.From
		if name := m.Meta[core.MetaFromName]; name != "" {
			from = name
		}
		var to string
		if m.Meta[core.MetaMyRole] != "" {
			// received: to = inbox
			to = inboxKey
		} else {
			// sent: to = first recipient
			to = firstAddr(m.Meta[core.MetaToAddrs])
			if to == "" {
				to = "?"
			}
		}
		lines = append(lines, fmt.Sprintf("%s %s → %s", ts, from, to))
	}
	writeBisetLog(vaultDir, inboxKey, lines)
}

func firstAddr(jsonArr string) string {
	if jsonArr == "" {
		return ""
	}
	var addrs []string
	if err := json.Unmarshal([]byte(jsonArr), &addrs); err == nil && len(addrs) > 0 {
		return addrs[0]
	}
	return jsonArr
}
