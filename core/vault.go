package core

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ── rendering ─────────────────────────────────────────────────────────────────

// RenderMD writes a thread as a Markdown file to the vault.
func RenderMD(vaultDir, inboxKey string, t Thread) (string, []byte) {
	filename := mdFilename(inboxKey, t)
	content := mdContent(inboxKey, t)
	return filepath.Join(vaultDir, filepath.FromSlash(filename)), []byte(content)
}

// RenderJSON writes a thread as a JSON file to the vault.
func RenderJSON(vaultDir, inboxKey string, t Thread) (string, []byte, error) {
	oldest := t.Messages[len(t.Messages)-1]
	ts := time.UnixMilli(oldest.Ts).Local().Format("200601021504")
	contact := threadContact(inboxKey, t)
	filename := fmt.Sprintf("%s_%s.json", ts, SafeFilename(contact))
	path := filepath.Join(vaultDir, inboxKey, ".data", filename)
	b, err := jsonContent(inboxKey, t)
	return path, b, err
}

func mdFilename(inboxKey string, t Thread) string {
	oldest := t.Messages[len(t.Messages)-1]
	ts := time.UnixMilli(oldest.Ts).Local().Format("200601021504")
	contact := threadContact(inboxKey, t)
	return inboxKey + "/" + fmt.Sprintf("%s_%s.md", ts, SafeFilename(contact))
}

func threadContact(inboxKey string, t Thread) string {
	for _, m := range t.Messages {
		if !strings.EqualFold(m.From, inboxKey) {
			return m.From
		}
		var addrs []string
		for _, raw := range []string{m.Meta[MetaToAddrs], m.Meta[MetaCcAddrs]} {
			if raw == "" {
				continue
			}
			var parsed []string
			if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
				for _, a := range parsed {
					if !strings.EqualFold(a, inboxKey) {
						addrs = append(addrs, a)
					}
				}
			}
		}
		if len(addrs) > 0 {
			return strings.Join(addrs, ", ")
		}
	}
	return inboxKey
}

func mdContent(inboxKey string, t Thread) string {
	latestMsgID := ""
	subject := ""
	contact := ""
	ccAddrs := ""
	for _, m := range t.Messages {
		if latestMsgID == "" {
			latestMsgID = m.MessageID
		}
		if subject == "" {
			subject = m.Meta[MetaSubject]
		}
		if contact == "" {
			if !strings.EqualFold(m.From, inboxKey) {
				contact = m.From
			} else {
				var addrs []string
				for _, raw := range []string{m.Meta[MetaToAddrs], m.Meta[MetaCcAddrs]} {
					if raw == "" {
						continue
					}
					var parsed []string
					if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
						for _, a := range parsed {
							if !strings.EqualFold(a, inboxKey) {
								addrs = append(addrs, a)
							}
						}
					}
				}
				if len(addrs) > 0 {
					contact = strings.Join(addrs, ", ")
				}
			}
		}
		if ccAddrs == "" {
			ccAddrs = m.Meta[MetaCcAddrs]
		}
	}
	if contact == "" {
		contact = inboxKey
	}

	protocol := ""
	for _, m := range t.Messages {
		if m.Meta[MetaAPID] != "" {
			protocol = "ap"
			break
		}
		if m.Meta["protocol"] != "" {
			protocol = m.Meta["protocol"]
			break
		}
	}

	// thread is unseen if any inbox message is unseen
	seen := true
	for _, m := range t.Messages {
		if m.Meta[MetaMyRole] != "" && !m.Seen {
			seen = false
			break
		}
	}

	fm := []string{
		"---",
		fmt.Sprintf("inbox: %s", inboxKey),
		fmt.Sprintf("contact: %s", contact),
	}
	if cc := jsonArrayToYAML(ccAddrs); cc != "" {
		fm = append(fm, fmt.Sprintf("cc: %s", cc))
	}
	fm = append(fm,
		fmt.Sprintf("subject: \"%s\"", strings.ReplaceAll(subject, `"`, `\"`)),
		fmt.Sprintf("id: %s", strings.Trim(t.ID, "<>")),
		fmt.Sprintf("in: %s", strings.Trim(latestMsgID, "<>")),
	)
	if protocol != "" {
		fm = append(fm, fmt.Sprintf("protocol: %s", protocol))
	}
	fm = append(fm, fmt.Sprintf("seen: %v", seen), "status: ", "---", "")

	msgs := make([]string, 0, len(t.Messages))
	for _, m := range t.Messages {
		from := m.From
		if name := m.Meta[MetaFromName]; name != "" {
			from = fmt.Sprintf("%s(%s)", name, m.From)
		}
		ts := time.UnixMilli(m.Ts).Local().Format("2006-01-02 15:04")
		msgs = append(msgs, fmt.Sprintf("# %s %s\n\n%s", ts, from, m.Body))
	}

	return strings.Join(fm, "\n") + "\n" + strings.Join(msgs, "\n\n")
}

func jsonArrayToYAML(s string) string {
	if s == "" || s == "null" {
		return ""
	}
	var addrs []string
	if err := json.Unmarshal([]byte(s), &addrs); err != nil || len(addrs) == 0 {
		return s
	}
	if len(addrs) == 1 {
		return addrs[0]
	}
	lines := make([]string, len(addrs))
	for i, a := range addrs {
		lines[i] = "  - " + a
	}
	return "\n" + strings.Join(lines, "\n")
}

func jsonContent(inboxKey string, t Thread) ([]byte, error) {
	type msgOut struct {
		From      string            `json:"from"`
		FromName  string            `json:"from_name,omitempty"`
		Body      string            `json:"body"`
		Time      string            `json:"time"` // local RFC3339
		MessageID string            `json:"message_id,omitempty"`
		ParentID  string            `json:"parent_id,omitempty"`
		Seen      bool              `json:"seen"`
		Meta      map[string]string `json:"meta,omitempty"`
	}
	type threadOut struct {
		ID       string   `json:"thread_id"`
		LastTime string   `json:"last_time"` // local RFC3339
		Messages []msgOut `json:"messages"`
	}
	type out struct {
		Inbox  string    `json:"inbox"`
		Status string    `json:"status"`
		Reply  string    `json:"reply"`
		Thread threadOut `json:"thread"`
	}

	mOuts := make([]msgOut, 0, len(t.Messages))
	for _, m := range t.Messages {
		body := strings.Map(func(r rune) rune {
			if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
				return -1
			}
			return r
		}, m.Body)
		mOuts = append(mOuts, msgOut{
			From:      m.From,
			FromName:  m.Meta[MetaFromName],
			Body:      body,
			Time:      time.UnixMilli(m.Ts).Local().Format(time.RFC3339),
			MessageID: m.MessageID,
			ParentID:  m.ParentID,
			Seen:      m.Seen,
			Meta:      m.Meta,
		})
	}

	return json.MarshalIndent(out{
		Inbox: inboxKey,
		Thread: threadOut{
			ID:       t.ID,
			LastTime: time.UnixMilli(LatestTs(t)).Local().Format(time.RFC3339),
			Messages: mOuts,
		},
	}, "", "  ")
}

// ── vault file helpers ────────────────────────────────────────────────────────

func WriteIfChanged(path, content string) bool {
	if b, err := os.ReadFile(path); err == nil && string(b) == content {
		return false
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		log.Printf("write %s: %v", path, err)
		return false
	}
	return true
}

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

// ExtractBody returns the compose area between frontmatter and first "# " heading.
func ExtractBody(content string) string {
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return ""
	}
	after := strings.TrimLeft(parts[2], "\n")
	if strings.HasPrefix(after, "# ") {
		return ""
	}
	idx := strings.Index(after, "\n# ")
	var body string
	if idx < 0 {
		body = after
	} else {
		body = after[:idx]
	}
	return strings.TrimSpace(body)
}

// InjectBody inserts a draft into the compose area.
func InjectBody(content, body string) string {
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return content
	}
	rest := strings.TrimLeft(parts[2], "\n")
	return parts[0] + "---" + parts[1] + "---\n" + body + "\n\n" + rest
}

// ClearBody removes the compose area.
func ClearBody(content string) string {
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return content
	}
	after := strings.TrimLeft(parts[2], "\n")
	if strings.HasPrefix(after, "# ") {
		return content
	}
	fm := parts[0] + "---" + parts[1] + "---\n"
	idx := strings.Index(after, "\n# ")
	if idx < 0 {
		return fm
	}
	return fm + "\n" + after[idx+1:]
}

const NewFileTemplate = "---\ncontact: \nstatus: \n---\n"

func EnsureNewFile(vaultDir, inboxKey string) {
	p := filepath.Join(vaultDir, inboxKey, "_new.md")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		os.WriteFile(p, []byte(NewFileTemplate), 0644) //nolint:errcheck
	}
}

// ── thread merging ────────────────────────────────────────────────────────────

// MergeWithExisting reads the existing JSON file for the thread and merges
// historical messages with newly fetched ones.
func MergeWithExisting(t Thread, inboxDir string) Thread {
	var fallbacks []string
	for _, m := range t.Messages {
		if m.ParentID != "" {
			fallbacks = append(fallbacks, m.ParentID)
		}
		if m.MessageID != "" {
			fallbacks = append(fallbacks, m.MessageID)
		}
	}
	dataDir := filepath.Join(inboxDir, ".data")
	jsonPath := FindExistingThreadFile(dataDir, t.ID, ".json", fallbacks...)
	if jsonPath == "" {
		return t
	}

	b, err := os.ReadFile(jsonPath)
	if err != nil {
		return t
	}

	existing := threadFromJSON(b)
	if existing == nil {
		return t
	}

	seen := map[string]bool{}
	for _, m := range t.Messages {
		key := m.MessageID
		if key == "" {
			key = fmt.Sprintf("%d", m.Ts)
		}
		seen[key] = true
	}

	var historical []Message
	for _, m := range existing.Messages {
		key := m.MessageID
		if key == "" {
			key = fmt.Sprintf("%d", m.Ts)
		}
		if seen[key] {
			continue
		}
		historical = append(historical, m)
	}

	if len(historical) == 0 {
		return t
	}

	all := append(t.Messages, historical...)
	deduped := all[:0:len(all)]
	seenMsg := map[string]bool{}
	for _, m := range all {
		key := m.MessageID
		if key == "" {
			key = fmt.Sprintf("%d|%s", m.Ts, m.From)
		}
		if !seenMsg[key] {
			seenMsg[key] = true
			deduped = append(deduped, m)
		}
	}
	all = deduped
	sort.Slice(all, func(i, j int) bool { return all[i].Ts > all[j].Ts })

	threadID := t.ID
	if existing.ID != "" {
		threadID = existing.ID
	}
	return Thread{ID: threadID, Messages: all}
}

func threadFromJSON(b []byte) *Thread {
	var data struct {
		Thread struct {
			ID       string `json:"thread_id"`
			Messages []struct {
				From      string            `json:"from"`
				FromName  string            `json:"from_name"`
				Body      string            `json:"body"`
				Time      string            `json:"time"`
				MessageID string            `json:"message_id"`
				ParentID  string            `json:"parent_id"`
				Seen      bool              `json:"seen"`
				Meta      map[string]string `json:"meta"`
			} `json:"messages"`
		} `json:"thread"`
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil
	}
	msgs := make([]Message, 0, len(data.Thread.Messages))
	for _, m := range data.Thread.Messages {
		meta := m.Meta
		if meta == nil {
			meta = map[string]string{}
		}
		if m.FromName != "" {
			meta[MetaFromName] = m.FromName
		}
		var ts int64
		if t, err := time.Parse(time.RFC3339, m.Time); err == nil {
			ts = t.UnixMilli()
		}
		msgs = append(msgs, Message{
			From:      m.From,
			Body:      m.Body,
			Ts:        ts,
			MessageID: m.MessageID,
			ParentID:  m.ParentID,
			Seen:      m.Seen,
			Meta:      meta,
		})
	}
	return &Thread{ID: data.Thread.ID, Messages: msgs}
}

// FindExistingThreadFile scans dir for a file whose content matches the thread_id
// or any fallback message IDs.
func FindExistingThreadFile(dir, threadID, ext string, fallbackIDs ...string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	needles := []string{strings.Trim(threadID, "<>")}
	for _, id := range fallbackIDs {
		if id != "" {
			needles = append(needles, strings.Trim(id, "<>"))
		}
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ext) {
			continue
		}
		filePath := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		content := string(b)
		for _, needle := range needles {
			if needle != "" && strings.Contains(content, needle) {
				return filePath
			}
		}
	}
	return ""
}

// RenderMissingMDs scans .data/ for JSON files without a corresponding MD and renders them.
func RenderMissingMDs(vaultDir, inboxKey string) {
	inboxDir := filepath.Join(vaultDir, inboxKey)
	dataDir := filepath.Join(inboxDir, ".data")
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		mdName := strings.TrimSuffix(e.Name(), ".json") + ".md"
		if _, err := os.Stat(filepath.Join(inboxDir, mdName)); err == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dataDir, e.Name()))
		if err != nil {
			continue
		}
		t := threadFromJSON(b)
		if t == nil {
			os.Remove(filepath.Join(dataDir, e.Name())) //nolint:errcheck
			continue
		}
		_, content := RenderMD(vaultDir, inboxKey, *t)
		filePath := filepath.Join(inboxDir, mdName)
		os.MkdirAll(filepath.Dir(filePath), 0755) //nolint:errcheck
		WriteIfChanged(filePath, string(content))
	}
}
