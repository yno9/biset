package core

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ── mtime ─────────────────────────────────────────────────────────────────────

func latestEmailTime(emails []Email) time.Time {
	var t time.Time
	for _, e := range emails {
		if e.ReceivedAt.After(t) {
			t = e.ReceivedAt
		}
	}
	return t
}

func SetMDMtime(mdPath string, emails []Email) {
	t := latestEmailTime(emails)
	if t.IsZero() {
		return
	}
	os.Chtimes(mdPath, t, t) //nolint:errcheck
}

// ── rendering ─────────────────────────────────────────────────────────────────

// RenderMD renders emails as a Markdown thread file.
// Returns the target path and content bytes; does not write to disk.
func RenderMD(vaultDir, inboxKey string, emails []Email) (string, []byte) {
	if len(emails) == 0 {
		return "", nil
	}
	sorted := make([]Email, len(emails))
	copy(sorted, emails)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ReceivedAt.After(sorted[j].ReceivedAt)
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

// ThreadShortID returns mmddHHMM of the oldest email in the thread.
func ThreadShortID(emails []Email) string {
	oldest := emails[0]
	for _, e := range emails {
		if e.ReceivedAt.Before(oldest.ReceivedAt) {
			oldest = e
		}
	}
	return oldest.ReceivedAt.Local().Format("01021504")
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

func threadContact(inboxKey string, emails []Email) string {
	for _, e := range emails {
		from := EmailFromAddr(e)
		if !strings.EqualFold(from, inboxKey) {
			return from
		}
		for _, a := range e.To {
			if !strings.EqualFold(a.Email, inboxKey) {
				return a.Email
			}
		}
		for _, a := range e.Cc {
			if !strings.EqualFold(a.Email, inboxKey) {
				return a.Email
			}
		}
	}
	return inboxKey
}

func isSeen(inboxKey string, emails []Email) bool {
	for _, e := range emails {
		if !strings.EqualFold(EmailFromAddr(e), inboxKey) && !EmailIsSeen(e) {
			return false
		}
	}
	return true
}

func mdContent(inboxKey string, emails []Email) string {
	latest := emails[0]
	threadID := latest.ThreadID

	protocol := ""
	for _, e := range emails {
		if bv, ok := e.BodyValues["biset-protocol"]; ok {
			protocol = bv.Value
			break
		}
	}

	contact := threadContact(inboxKey, emails)
	subject := latest.Subject
	fm := []string{
		"---",
		fmt.Sprintf("subject: \"%s\"", strings.ReplaceAll(subject, `"`, `\"`)),
		fmt.Sprintf("contact: %s", contact),
		fmt.Sprintf("id: %s", strings.TrimPrefix(threadID, "thr-")),
	}
	if protocol != "" {
		fm = append(fm, fmt.Sprintf("protocol: %s", protocol))
	}
	fm = append(fm, "status: ", "---", "")

	msgs := make([]string, 0, len(emails))
	for _, e := range emails {
		from := EmailFromAddr(e)
		ts := e.ReceivedAt.Local().Format("2006-01-02 15:04")
		msgs = append(msgs, fmt.Sprintf("- - -\n%s %s\n\n%s", ts, from, EmailBody(e)))
	}

	return strings.Join(fm, "\n") + "\n\n\n" + strings.Join(msgs, "\n\n")
}


// RenderMissingMDs renders MD files for threads missing one in the given inbox.
func RenderMissingMDs(vaultDir, inboxKey string) {
	threads, err := ScanThreads(vaultDir)
	if err != nil {
		return
	}
	mbxID := MakeMailboxID(inboxKey)
	for _, t := range threads {
		emails := ReadEmailsForThread(vaultDir, t.ID)
		var inboxEmails []Email
		for _, e := range emails {
			if e.MailboxIDs[mbxID] {
				inboxEmails = append(inboxEmails, e)
			}
		}
		if len(inboxEmails) == 0 {
			continue
		}
		inboxDir := filepath.Join(vaultDir, inboxKey)
		if FindThreadMD(inboxDir, ThreadShortID(inboxEmails)) != "" {
			continue
		}
		mdPath, content := RenderMD(vaultDir, inboxKey, inboxEmails)
		if mdPath == "" {
			continue
		}
		if _, statErr := os.Stat(mdPath); statErr == nil {
			log.Printf("[RenderMissingMDs] SKIP (exists) inbox=%s thread=%s mdPath=%s", inboxKey, t.ID[:min(30, len(t.ID))], filepath.Base(mdPath))
			continue
		} else {
			log.Printf("[RenderMissingMDs] stat err=%v inbox=%s thread=%s mdPath=%s", statErr, inboxKey, t.ID[:min(30, len(t.ID))], mdPath)
		}
		log.Printf("[RenderMissingMDs] WRITE inbox=%s thread=%s emails=%d mdPath=%s", inboxKey, t.ID[:min(30, len(t.ID))], len(inboxEmails), filepath.Base(mdPath))
		os.MkdirAll(filepath.Dir(mdPath), 0755) //nolint:errcheck
		WriteIfChanged(mdPath, string(content))
		SetMDMtime(mdPath, inboxEmails)
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

// ExtractBody returns the compose area between frontmatter and first "- - -" separator.
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

const NewFileTemplate = "---\ncontact: \nstatus: \n---\n"

func EnsureNewFile(vaultDir, inboxKey string) {
	p := filepath.Join(vaultDir, inboxKey, "_new.md")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		os.WriteFile(p, []byte(NewFileTemplate), 0644) //nolint:errcheck
	}
}

// ── WriteThreadMD — canonical JSON→MD bridge ──────────────────────────────────

// WriteThreadMD writes email JSONs, the thread index, and re-renders the MD
// file from JSON. Returns true if the MD file was written (created or changed).
func WriteThreadMD(vaultDir, inboxKey string, emails []Email) bool {
	if len(emails) == 0 {
		return false
	}

	sorted := make([]Email, len(emails))
	copy(sorted, emails)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ReceivedAt.After(sorted[j].ReceivedAt)
	})

	for _, e := range sorted {
		WriteEmail(vaultDir, e) //nolint:errcheck
	}

	threadID := sorted[0].ThreadID
	emailIDs := make([]string, len(sorted))
	for i, e := range sorted {
		emailIDs[i] = e.ID
	}
	WriteThread(vaultDir, Thread{ID: threadID, EmailIDs: emailIDs}) //nolint:errcheck

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
