package vault

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
)

// ── mtime ─────────────────────────────────────────────────────────────────────

func latestMessageTime(messages []Message) time.Time {
	var t time.Time
	for _, m := range messages {
		if rv := TimeVal(m.ReceivedAt); rv.After(t) {
			t = rv
		}
	}
	return t
}

func SetMDMtime(mdPath string, messages []Message) {
	t := latestMessageTime(messages)
	if t.IsZero() {
		return
	}
	os.Chtimes(mdPath, t, t) //nolint:errcheck
}

// ── rendering ─────────────────────────────────────────────────────────────────

func RenderMD(vaultDir, mailboxName string, messages []Message, cfg MailboxConfig) (string, []byte) {
	if len(messages) == 0 {
		return "", nil
	}
	sorted := make([]Message, len(messages))
	copy(sorted, messages)
	sort.Slice(sorted, func(i, j int) bool {
		return TimeVal(sorted[i].ReceivedAt).After(TimeVal(sorted[j].ReceivedAt))
	})

	if cfg.MaxDisplay > 0 && len(sorted) > cfg.MaxDisplay {
		sorted = sorted[:cfg.MaxDisplay]
	}

	content := mdContent(mailboxName, sorted, cfg.EffectiveMeta())

	contact := threadContact(mailboxName, sorted)
	seen := isSeen(mailboxName, sorted)
	expanded := expandFileFormat(cfg.EffectiveFileFormat(), contact, ThreadShortID(sorted))
	if !seen {
		dir, base := filepath.Split(expanded)
		expanded = dir + "_" + base
	}
	path := filepath.Join(vaultDir, mailboxName, expanded)
	return path, []byte(content)
}

func expandFileFormat(tmpl, contact, shortID string) string {
	s := strings.ReplaceAll(tmpl, "{contact}", SafeFilename(contact))
	s = strings.ReplaceAll(s, "{shortId}", shortID)
	return s
}

func ThreadShortID(messages []Message) string {
	oldest := messages[0]
	for _, m := range messages {
		if TimeVal(m.ReceivedAt).Before(TimeVal(oldest.ReceivedAt)) {
			oldest = m
		}
	}
	return TimeVal(oldest.ReceivedAt).Local().Format("01021504")
}

// findContactMD finds an existing MD file for a contact in a sub-mailbox
// (where filenames have no shortID suffix): _contact.md or contact.md.
func findContactMD(inboxDir, contact string) string {
	safe := SafeFilename(contact)
	for _, name := range []string{"_" + safe + ".md", safe + ".md"} {
		p := filepath.Join(inboxDir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func FindThreadMD(inboxDir, shortThr string) string {
	var found string
	filepath.WalkDir(inboxDir, func(path string, d fs.DirEntry, err error) error { //nolint:errcheck
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".md") {
			return nil
		}
		base := strings.TrimPrefix(name, "_")
		// default format: contact_shortThr.md; subdir format: shortThr.md
		if strings.HasSuffix(base, "_"+shortThr+".md") || base == shortThr+".md" {
			found = path
			return fs.SkipAll
		}
		return nil
	})
	return found
}

func threadContact(mailboxName string, messages []Message) string {
	for _, m := range messages {
		from := MessageFromAddr(m)
		if !strings.EqualFold(from, mailboxName) {
			return from
		}
		for _, a := range m.To {
			if a != nil && !strings.EqualFold(a.Email, mailboxName) {
				return a.Email
			}
		}
		for _, a := range m.CC {
			if a != nil && !strings.EqualFold(a.Email, mailboxName) {
				return a.Email
			}
		}
	}
	return mailboxName
}

func isSeen(mailboxName string, messages []Message) bool {
	for _, m := range messages {
		if !strings.EqualFold(MessageFromAddr(m), mailboxName) && !MessageIsSeen(m) {
			return false
		}
	}
	return true
}

func mdContent(mailboxName string, messages []Message, meta []string) string {
	latest := messages[0]
	threadID := string(latest.ThreadID)
	contact := threadContact(mailboxName, messages)

	fm := []string{"---"}
	for _, field := range meta {
		switch field {
		case "subject":
			if latest.Subject != "" {
				fm = append(fm, fmt.Sprintf("subject: \"%s\"", strings.ReplaceAll(latest.Subject, `"`, `\"`)))
			}
		case "contact":
			fm = append(fm, fmt.Sprintf("contact: %s", contact))
		case "id":
			if threadID != "" {
				fm = append(fm, fmt.Sprintf("id: %s", threadID))
			}
		case "status":
			fm = append(fm, "status: ")
		case "cc":
			if len(latest.CC) > 0 {
				addrs := make([]string, 0, len(latest.CC))
				for _, a := range latest.CC {
					if a != nil {
						addrs = append(addrs, a.Email)
					}
				}
				if len(addrs) > 0 {
					fm = append(fm, fmt.Sprintf("cc: %s", strings.Join(addrs, ", ")))
				}
			}
		case "bcc":
			if len(latest.BCC) > 0 {
				addrs := make([]string, 0, len(latest.BCC))
				for _, a := range latest.BCC {
					if a != nil {
						addrs = append(addrs, a.Email)
					}
				}
				if len(addrs) > 0 {
					fm = append(fm, fmt.Sprintf("bcc: %s", strings.Join(addrs, ", ")))
				}
			}
		}
	}
	fm = append(fm, "---", "")

	msgs := make([]string, 0, len(messages))
	for _, m := range messages {
		from := MessageFromAddr(m)
		ts := TimeVal(m.ReceivedAt).Local().Format("2006-01-02-15:04")
		msgs = append(msgs, fmt.Sprintf("- - -\n%s %s\n\n%s", ts, from, MessageBody(m)))
	}

	return strings.Join(fm, "\n") + "\n\n\n" + strings.Join(msgs, "\n\n")
}

// ThreadView is the minimal data RenderMissingMDs needs: a thread ID with the
// messages it contains. Callers (typically sync.go) fetch these from the JMAP
// store and pass them in, keeping render free of file I/O for messages/threads.
type ThreadView struct {
	ID       ID
	Messages []Message
}

// RenderMissingMDs renders MD files for threads missing one in the given mailbox.
// Caller supplies the threads (with their messages) from the JMAP store.
func RenderMissingMDs(vaultDir, mailboxName string, cfg MailboxConfig, threads []ThreadView) {
	mbxID := jmap.ID(MakeMailboxID(mailboxName))
	for _, t := range threads {
		var inboxMsgs []Message
		for _, m := range t.Messages {
			if m.MailboxIDs[mbxID] && m.ThreadID == t.ID {
				inboxMsgs = append(inboxMsgs, m)
			}
		}
		if len(inboxMsgs) == 0 {
			continue
		}
		inboxDir := filepath.Join(vaultDir, mailboxName)
		alreadyExists := false
		if cfg.IsSimplified() {
			contact := threadContact(mailboxName, inboxMsgs)
			alreadyExists = findContactMD(inboxDir, contact) != ""
		} else {
			alreadyExists = FindThreadMD(inboxDir, ThreadShortID(inboxMsgs)) != ""
		}
		if alreadyExists {
			continue
		}
		mdPath, content := RenderMD(vaultDir, mailboxName, inboxMsgs, cfg)
		if mdPath == "" {
			continue
		}
		if _, statErr := os.Stat(mdPath); statErr == nil {
			log.Printf("[RenderMissingMDs] SKIP (exists) inbox=%s thread=%s", mailboxName, string(t.ID)[:min(30, len(string(t.ID)))])
			continue
		}
		log.Printf("[RenderMissingMDs] WRITE inbox=%s thread=%s msgs=%d", mailboxName, string(t.ID)[:min(30, len(string(t.ID)))], len(inboxMsgs))
		os.MkdirAll(filepath.Dir(mdPath), 0755) //nolint:errcheck
		WriteIfChanged(mdPath, string(content))
		SetMDMtime(mdPath, inboxMsgs)
	}
}

// ── frontmatter / body helpers ────────────────────────────────────────────────

func ParseFrontmatter(content string) map[string]string {
	fm := map[string]string{}
	lines := strings.SplitN(content, "---", 3)
	if len(lines) < 3 {
		return fm
	}
	for _, line := range strings.Split(lines[1], "\n") {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			fm[strings.TrimSpace(parts[0])] = strings.Trim(strings.TrimSpace(parts[1]), `"`)
		}
	}
	return fm
}

func ExtractBody(content string) string {
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return ""
	}
	after := strings.TrimLeft(parts[2], "\n")
	if strings.HasPrefix(after, "- - -") {
		return ""
	}
	idx := strings.Index(after, "\n- - -")
	var body string
	if idx < 0 {
		body = after
	} else {
		body = after[:idx]
	}
	return strings.TrimSpace(body)
}

func InjectBody(content, body string) string {
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return content
	}
	rest := strings.TrimLeft(parts[2], "\n")
	return parts[0] + "---" + parts[1] + "---\n" + body + "\n\n" + rest
}

func ClearBody(content string) string {
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return content
	}
	after := strings.TrimLeft(parts[2], "\n")
	fm := parts[0] + "---" + parts[1] + "---\n"
	if strings.HasPrefix(after, "- - -") {
		return fm + "\n\n\n" + after
	}
	idx := strings.Index(after, "\n- - -")
	if idx < 0 {
		return fm
	}
	return fm + "\n\n\n" + after[idx+1:]
}

func NewFileContent() string {
	return "---\ncontact: \nstatus: \n---\n"
}

// CleanupOrphanedInboxes removes biset-managed vault directories (those with
// _new.md) that are no longer tracked by any relay in state. Only runs when
// state has at least one relay entry to avoid false-positive deletions on first
// run.
func CleanupOrphanedInboxes(vaultDir string, state *State, respondedRelays map[string][]string) {
	if len(state.Relays) == 0 {
		return
	}

	// Build complete set of known mailboxNames across all relays in state,
	// merged with what responded relays are returning now.
	// Normalize trailing slashes: mailboxName "rss/" maps to directory "rss".
	known := map[string]bool{}
	addKnown := func(k string) {
		known[k] = true
		known[strings.TrimSuffix(k, "/")] = true
	}
	for _, rs := range state.Relays {
		for _, k := range rs.MailboxNames {
			addKnown(k)
		}
	}
	for _, keys := range respondedRelays {
		for _, k := range keys {
			addKnown(k)
		}
	}

	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		key := e.Name()
		subDir := filepath.Join(vaultDir, key)
		if _, err := os.Stat(filepath.Join(subDir, "_new.md")); err != nil {
			continue // not biset-managed
		}
		if known[key] {
			continue
		}
		log.Printf("[vault] removing orphaned inbox: %s", key)
		if err := os.RemoveAll(subDir); err != nil {
			log.Printf("[vault] remove %s: %v", key, err)
		}
	}
}

// CleanupOrphanedMDs removes _*.md files in vault mailboxes that no longer
// correspond to any message in the given list (caller fetches from the JMAP
// store, so vault stays out of the message-CRUD business).
func CleanupOrphanedMDs(vaultDir string, messages []Message, inboxCfg func(string) MailboxConfig) {
	// Build set of expected MD paths from current messages.
	byInbox := map[string][]Message{}
	for _, m := range messages {
		key := MailboxNameFromID(MessageMailboxID(m))
		if key == "" {
			continue
		}
		byInbox[key] = append(byInbox[key], m)
	}

	expected := map[string]bool{}
	for mailboxName, msgs := range byInbox {
		threads := GroupByThread(msgs)
		for _, t := range threads {
			threadMsgs := make([]Message, 0, len(t.EmailIDs))
			for _, m := range msgs {
				for _, id := range t.EmailIDs {
					if m.ID == id {
						threadMsgs = append(threadMsgs, m)
					}
				}
			}
			mdPath, _ := RenderMD(vaultDir, mailboxName, threadMsgs, inboxCfg(mailboxName))
			if mdPath != "" {
				expected[mdPath] = true
			}
		}
	}

	// Scan vault for _*.md files not in expected set.
	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		scanInboxForOrphans(vaultDir, e.Name(), expected)
	}
}

func scanInboxForOrphans(vaultDir, mailboxName string, expected map[string]bool) {
	dir := filepath.Join(vaultDir, mailboxName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			scanInboxForOrphans(vaultDir, mailboxName+"/"+e.Name(), expected)
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".md") || name == "_new.md" {
			continue
		}
		fullPath := filepath.Join(dir, name)
		if !expected[fullPath] {
			log.Printf("[vault] removing orphaned MD: %s/%s", mailboxName, name)
			os.Remove(fullPath) //nolint:errcheck
		}
	}
}

func EnsureNewFile(vaultDir, mailboxName string, cfg MailboxConfig) {
	dir := filepath.Join(vaultDir, mailboxName)
	os.MkdirAll(dir, 0755) //nolint:errcheck
	p := filepath.Join(dir, "_new.md")
	if cfg.IsSimplified() {
		os.Remove(p) //nolint:errcheck
		return
	}
	if _, err := os.Stat(p); os.IsNotExist(err) {
		os.WriteFile(p, []byte(NewFileContent()), 0644) //nolint:errcheck
	}
}

// ── WriteThreadMD ─────────────────────────────────────────────────────────────

func WriteThreadMD(vaultDir, mailboxName string, messages []Message, cfg MailboxConfig) bool {
	if len(messages) == 0 {
		return false
	}

	sorted := make([]Message, len(messages))
	copy(sorted, messages)
	sort.Slice(sorted, func(i, j int) bool {
		return TimeVal(sorted[i].ReceivedAt).After(TimeVal(sorted[j].ReceivedAt))
	})

	// Messages and threads are stored by the JMAP store (sync.go's store.Put);
	// we no longer write parallel message.json/thread.json copies from the
	// render layer — they would just shadow Store's authoritative files.

	mdPath, mdBytes := RenderMD(vaultDir, mailboxName, sorted, cfg)
	if mdPath == "" {
		return false
	}
	content := string(mdBytes)

	inboxDir := filepath.Join(vaultDir, mailboxName)
	contact := threadContact(mailboxName, sorted)
	var oldMDPath string
	if cfg.IsSimplified() {
		oldMDPath = findContactMD(inboxDir, contact)
	} else {
		oldMDPath = FindThreadMD(inboxDir, ThreadShortID(sorted))
	}
	readFrom := oldMDPath
	if readFrom == "" {
		readFrom = mdPath
	}
	if existing, err := os.ReadFile(readFrom); err == nil {
		if draft := ExtractBody(string(existing)); draft != "" {
			content = InjectBody(content, draft)
		}
	}

	if oldMDPath != "" && oldMDPath != mdPath {
		os.Remove(oldMDPath) //nolint:errcheck
	}

	os.MkdirAll(filepath.Dir(mdPath), 0755) //nolint:errcheck
	written := WriteIfChanged(mdPath, content)
	SetMDMtime(mdPath, sorted)
	return written
}

// ── draft helpers ─────────────────────────────────────────────────────────────

func SetFMField(content, key, value string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, key+":") {
			lines[i] = key + ": " + value
			return strings.Join(lines, "\n")
		}
	}
	return content
}

