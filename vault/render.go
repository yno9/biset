package vault

import (
	"fmt"
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

func RenderMD(vaultDir, inboxKey string, messages []Message) (string, []byte) {
	if len(messages) == 0 {
		return "", nil
	}
	sorted := make([]Message, len(messages))
	copy(sorted, messages)
	sort.Slice(sorted, func(i, j int) bool {
		return TimeVal(sorted[i].ReceivedAt).After(TimeVal(sorted[j].ReceivedAt))
	})

	content := mdContent(inboxKey, sorted)

	contact := threadContact(inboxKey, sorted)
	seen := isSeen(inboxKey, sorted)
	prefix := ""
	if !seen {
		prefix = "_"
	}
	filename := fmt.Sprintf("%s%s_%s.md", prefix, SafeFilename(contact), ThreadShortID(sorted))
	path := filepath.Join(vaultDir, inboxKey, filename)
	return path, []byte(content)
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

func FindThreadMD(inboxDir, shortThr string) string {
	entries, err := os.ReadDir(inboxDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		base := strings.TrimPrefix(name, "_")
		if strings.HasSuffix(base, "_"+shortThr+".md") {
			return filepath.Join(inboxDir, name)
		}
	}
	return ""
}

func threadContact(inboxKey string, messages []Message) string {
	for _, m := range messages {
		from := MessageFromAddr(m)
		if !strings.EqualFold(from, inboxKey) {
			return from
		}
		for _, a := range m.To {
			if a != nil && !strings.EqualFold(a.Email, inboxKey) {
				return a.Email
			}
		}
		for _, a := range m.CC {
			if a != nil && !strings.EqualFold(a.Email, inboxKey) {
				return a.Email
			}
		}
	}
	return inboxKey
}

func isSeen(inboxKey string, messages []Message) bool {
	for _, m := range messages {
		if !strings.EqualFold(MessageFromAddr(m), inboxKey) && !MessageIsSeen(m) {
			return false
		}
	}
	return true
}

func mdContent(inboxKey string, messages []Message) string {
	latest := messages[0]
	threadID := string(latest.ThreadID)

	contact := threadContact(inboxKey, messages)
	subject := latest.Subject
	fm := []string{
		"---",
		fmt.Sprintf("subject: \"%s\"", strings.ReplaceAll(subject, `"`, `\"`)),
		fmt.Sprintf("contact: %s", contact),
		fmt.Sprintf("id: %s", strings.TrimPrefix(threadID, "thr-")),
		"status: ",
		"---",
		"",
	}

	msgs := make([]string, 0, len(messages))
	for _, m := range messages {
		from := MessageFromAddr(m)
		ts := TimeVal(m.ReceivedAt).Local().Format("2006-01-02 15:04")
		msgs = append(msgs, fmt.Sprintf("- - -\n%s %s\n\n%s", ts, from, MessageBody(m)))
	}

	return strings.Join(fm, "\n") + "\n\n\n" + strings.Join(msgs, "\n\n")
}

// RenderMissingMDs renders MD files for threads missing one in the given inbox.
func RenderMissingMDs(vaultDir, inboxKey string) {
	threads, err := ScanThreads(vaultDir)
	if err != nil {
		return
	}
	mbxID := jmap.ID(MakeMailboxID(inboxKey))
	for _, t := range threads {
		msgs := ReadMessagesForThread(vaultDir, t.ID)
		var inboxMsgs []Message
		for _, m := range msgs {
			if m.MailboxIDs[mbxID] {
				inboxMsgs = append(inboxMsgs, m)
			}
		}
		if len(inboxMsgs) == 0 {
			continue
		}
		inboxDir := filepath.Join(vaultDir, inboxKey)
		if FindThreadMD(inboxDir, ThreadShortID(inboxMsgs)) != "" {
			continue
		}
		mdPath, content := RenderMD(vaultDir, inboxKey, inboxMsgs)
		if mdPath == "" {
			continue
		}
		if _, statErr := os.Stat(mdPath); statErr == nil {
			log.Printf("[RenderMissingMDs] SKIP (exists) inbox=%s thread=%s", inboxKey, string(t.ID)[:min(30, len(string(t.ID)))])
			continue
		}
		log.Printf("[RenderMissingMDs] WRITE inbox=%s thread=%s msgs=%d", inboxKey, string(t.ID)[:min(30, len(string(t.ID)))], len(inboxMsgs))
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

	// Build complete set of known inboxKeys across all relays in state,
	// merged with what responded relays are returning now.
	known := map[string]bool{}
	for _, rs := range state.Relays {
		for _, k := range rs.InboxKeys {
			known[k] = true
		}
	}
	for _, keys := range respondedRelays {
		for _, k := range keys {
			known[k] = true
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

// CleanupOrphanedMDs removes _*.md files in vault inboxes that no longer
// correspond to any message in .data/messages/.
func CleanupOrphanedMDs(vaultDir string) {
	messages, err := ScanMessages(vaultDir)
	if err != nil {
		return
	}

	// Build set of expected MD paths from current messages.
	byInbox := map[string][]Message{}
	for _, m := range messages {
		key := InboxKeyFromMailboxID(MessageMailboxID(m))
		if key == "" {
			continue
		}
		byInbox[key] = append(byInbox[key], m)
	}

	expected := map[string]bool{}
	for inboxKey, msgs := range byInbox {
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
			mdPath, _ := RenderMD(vaultDir, inboxKey, threadMsgs)
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

func scanInboxForOrphans(vaultDir, inboxKey string, expected map[string]bool) {
	dir := filepath.Join(vaultDir, inboxKey)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			scanInboxForOrphans(vaultDir, inboxKey+"/"+e.Name(), expected)
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".md") || name == "_new.md" {
			continue
		}
		fullPath := filepath.Join(dir, name)
		if !expected[fullPath] {
			log.Printf("[vault] removing orphaned MD: %s/%s", inboxKey, name)
			os.Remove(fullPath) //nolint:errcheck
		}
	}
}

func EnsureNewFile(vaultDir, inboxKey string) {
	dir := filepath.Join(vaultDir, inboxKey)
	os.MkdirAll(dir, 0755) //nolint:errcheck
	p := filepath.Join(dir, "_new.md")
	if strings.Contains(inboxKey, "/") {
		os.Remove(p) //nolint:errcheck
		return
	}
	if _, err := os.Stat(p); os.IsNotExist(err) {
		os.WriteFile(p, []byte(NewFileContent()), 0644) //nolint:errcheck
	}
}

// ── WriteThreadMD ─────────────────────────────────────────────────────────────

func WriteThreadMD(vaultDir, inboxKey string, messages []Message) bool {
	if len(messages) == 0 {
		return false
	}

	sorted := make([]Message, len(messages))
	copy(sorted, messages)
	sort.Slice(sorted, func(i, j int) bool {
		return TimeVal(sorted[i].ReceivedAt).After(TimeVal(sorted[j].ReceivedAt))
	})

	for _, m := range sorted {
		WriteMessage(vaultDir, m) //nolint:errcheck
	}

	threadID := sorted[0].ThreadID
	eIDs := make([]jmap.ID, len(sorted))
	for i, m := range sorted {
		eIDs[i] = m.ID
	}
	WriteThread(vaultDir, Thread{ID: threadID, EmailIDs: eIDs}) //nolint:errcheck

	mdPath, mdBytes := RenderMD(vaultDir, inboxKey, sorted)
	if mdPath == "" {
		return false
	}
	content := string(mdBytes)

	inboxDir := filepath.Join(vaultDir, inboxKey)
	oldMDPath := FindThreadMD(inboxDir, ThreadShortID(sorted))
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

func CreateDraftMD(vaultDir, inboxKey, contact, subject, body, threadID, inReplyTo string) (string, error) {
	if threadID == "" && inReplyTo != "" {
		threadID = FindThreadByMessageID(vaultDir, inReplyTo)
	}

	inboxDir := filepath.Join(vaultDir, inboxKey)
	if err := os.MkdirAll(inboxDir, 0755); err != nil {
		return "", err
	}

	mdPath := ""
	if threadID != "" {
		if msgs := ReadMessagesForThread(vaultDir, jmap.ID(threadID)); len(msgs) > 0 {
			mdPath = FindThreadMD(inboxDir, ThreadShortID(msgs))
		}
	}

	if mdPath != "" {
		b, err := os.ReadFile(mdPath)
		if err != nil {
			return "", err
		}
		content := SetFMField(string(b), "status", "send")
		content = InjectBody(content, body)
		if err := os.WriteFile(mdPath, []byte(content), 0644); err != nil {
			return "", err
		}
	} else {
		if threadID == "" {
			threadID = fmt.Sprintf("thr-ts-%d", time.Now().UnixMilli())
		}
		mbxID := MakeMailboxID(inboxKey)
		filename := fmt.Sprintf("%s_%s.md", SafeFilename(contact), time.Now().Local().Format("01021504"))
		mdPath = filepath.Join(inboxDir, filename)
		fm := fmt.Sprintf("---\nsubject: \"%s\"\ncontact: %s\nmailboxId: %s\nthreadId: %s\nseen: true\nstatus: send\n---\n%s\n\n",
			strings.ReplaceAll(subject, `"`, `\"`), contact, mbxID, threadID, body)
		if err := os.WriteFile(mdPath, []byte(fm), 0644); err != nil {
			return "", err
		}
	}

	return fmt.Sprintf("msg-draft-%d", time.Now().UnixMilli()), nil
}
