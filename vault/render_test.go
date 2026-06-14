package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
)

func makeMessage(id, threadID, inboxKey string, ts time.Time, body string) Message {
	mbxID := jmap.ID(MakeMailboxID(inboxKey))
	return NewTextMessage(id, threadID, string(mbxID),
		[]*Address{{Email: "from@example.com"}},
		[]*Address{{Email: inboxKey}},
		nil, "Subject", body, ts, "")
}

func TestThreadShortID(t *testing.T) {
	ts, _ := time.ParseInLocation("2006-01-02 15:04", "2024-03-15 10:30", time.Local)
	m := makeMessage("id", "thr", "user@example.com", ts, "body")
	got := ThreadShortID([]Message{m})
	if got != "03151030" {
		t.Errorf("ThreadShortID = %q, want 03151030", got)
	}
}

func TestThreadShortIDPicksOldest(t *testing.T) {
	ts1 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.Local)
	ts2 := time.Date(2024, 6, 1, 12, 0, 0, 0, time.Local)
	m1 := makeMessage("id1", "thr", "u@x.com", ts1, "first")
	m2 := makeMessage("id2", "thr", "u@x.com", ts2, "second")
	got := ThreadShortID([]Message{m2, m1})
	if got != ts1.Format("01021504") {
		t.Errorf("ThreadShortID = %q, want %q", got, ts1.Format("01021504"))
	}
}

func TestFindThreadMD(t *testing.T) {
	dir := t.TempDir()
	ts, _ := time.ParseInLocation("2006-01-02 15:04", "2024-03-15 10:30", time.Local)
	m := makeMessage("id", "thr", "user@example.com", ts, "body")
	shortID := ThreadShortID([]Message{m})

	os.WriteFile(filepath.Join(dir, "contact_"+shortID+".md"), []byte("content"), 0644)
	os.WriteFile(filepath.Join(dir, "_contact_"+shortID+".md"), []byte("content"), 0644)

	// finds unsigned
	got := FindThreadMD(dir, shortID)
	if got == "" {
		t.Error("expected to find file")
	}
	if !strings.Contains(got, shortID) {
		t.Errorf("path doesn't contain shortID: %q", got)
	}
}

func TestFindThreadMDNotFound(t *testing.T) {
	dir := t.TempDir()
	if got := FindThreadMD(dir, "99991234"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestFindThreadMDInvalidDir(t *testing.T) {
	if got := FindThreadMD("/nonexistent/dir", "12345678"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestParseFrontmatter(t *testing.T) {
	content := `---
subject: "Hello World"
contact: user@example.com
status:
---
body here`
	fm := ParseFrontmatter(content)
	if fm["subject"] != "Hello World" {
		t.Errorf("subject = %q", fm["subject"])
	}
	if fm["contact"] != "user@example.com" {
		t.Errorf("contact = %q", fm["contact"])
	}
	if fm["status"] != "" {
		t.Errorf("status = %q", fm["status"])
	}
}

func TestParseFrontmatterNoFM(t *testing.T) {
	fm := ParseFrontmatter("just some text")
	if len(fm) != 0 {
		t.Errorf("expected empty map, got %v", fm)
	}
}

func TestParseFrontmatterEmpty(t *testing.T) {
	fm := ParseFrontmatter("")
	if len(fm) != 0 {
		t.Error("expected empty map")
	}
}

func TestExtractBody(t *testing.T) {
	content := `---
subject: test
status:
---
my body text

- - -
2024-01-01 10:00 from@example.com

message body`
	got := ExtractBody(content)
	if got != "my body text" {
		t.Errorf("ExtractBody = %q", got)
	}
}

func TestExtractBodyNoDivider(t *testing.T) {
	content := `---
subject: test
---

my body text`
	got := ExtractBody(content)
	if got != "my body text" {
		t.Errorf("ExtractBody = %q", got)
	}
}

func TestExtractBodyNoFM(t *testing.T) {
	got := ExtractBody("no frontmatter")
	if got != "" {
		t.Errorf("ExtractBody = %q, want empty", got)
	}
}

func TestExtractBodyEmpty(t *testing.T) {
	content := `---
subject: test
---

- - -
some message`
	got := ExtractBody(content)
	if got != "" {
		t.Errorf("ExtractBody with no pre-divider body = %q, want empty", got)
	}
}

func TestInjectBody(t *testing.T) {
	content := `---
subject: test
---

- - -
existing message`
	got := InjectBody(content, "new draft body")
	if !strings.Contains(got, "new draft body") {
		t.Errorf("InjectBody missing body: %q", got)
	}
	if !strings.Contains(got, "- - -") {
		t.Errorf("InjectBody missing divider: %q", got)
	}
}

func TestInjectBodyNoFM(t *testing.T) {
	got := InjectBody("no frontmatter", "body")
	if got != "no frontmatter" {
		t.Errorf("InjectBody without FM = %q", got)
	}
}

func TestClearBody(t *testing.T) {
	content := `---
subject: test
---
my draft body

- - -
old message`
	got := ClearBody(content)
	if strings.Contains(got, "my draft body") {
		t.Errorf("ClearBody should remove draft body: %q", got)
	}
	if !strings.Contains(got, "- - -") {
		t.Errorf("ClearBody should keep thread: %q", got)
	}
}

func TestClearBodyNoFM(t *testing.T) {
	got := ClearBody("no frontmatter")
	if got != "no frontmatter" {
		t.Errorf("ClearBody without FM = %q", got)
	}
}

func TestNewFileContent(t *testing.T) {
	got := NewFileContent()
	if !strings.Contains(got, "---") {
		t.Error("missing frontmatter delimiters")
	}
	if !strings.Contains(got, "contact:") {
		t.Error("missing contact field")
	}
	if !strings.Contains(got, "status:") {
		t.Error("missing status field")
	}
}

func TestSetFMField(t *testing.T) {
	content := "---\nsubject: old\nstatus: \n---\n"
	got := SetFMField(content, "status", "send")
	if !strings.Contains(got, "status: send") {
		t.Errorf("SetFMField = %q", got)
	}
	// key not found → unchanged
	got2 := SetFMField(content, "nonexistent", "val")
	if got2 != content {
		t.Errorf("SetFMField with missing key changed content")
	}
}

func TestRenderMD(t *testing.T) {
	dir := t.TempDir()
	inboxKey := "user@example.com"
	os.MkdirAll(filepath.Join(dir, inboxKey), 0755)
	ts := time.Now()
	m := makeMessage("msg-1", "thr-1", inboxKey, ts, "hello")
	m.ThreadID = jmap.ID("thr-1")

	path, content := RenderMD(dir, inboxKey, []Message{m}, InboxConfig{})
	if path == "" {
		t.Fatal("RenderMD returned empty path")
	}
	if len(content) == 0 {
		t.Fatal("RenderMD returned empty content")
	}
	if !strings.Contains(string(content), "hello") {
		t.Errorf("content missing body: %s", content)
	}
}

func TestRenderMDEmpty(t *testing.T) {
	path, content := RenderMD("/tmp", "inbox", nil, InboxConfig{})
	if path != "" || content != nil {
		t.Error("RenderMD(empty) should return empty")
	}
}

func TestEnsureNewFile(t *testing.T) {
	dir := t.TempDir()
	inboxKey := "user@example.com"
	EnsureNewFile(dir, inboxKey, InboxConfig{})
	p := filepath.Join(dir, inboxKey, "_new.md")
	if _, err := os.Stat(p); err != nil {
		t.Errorf("_new.md not created: %v", err)
	}
	// second call is idempotent
	EnsureNewFile(dir, inboxKey, InboxConfig{})
	if _, err := os.Stat(p); err != nil {
		t.Errorf("_new.md removed on second call")
	}
}

func TestEnsureNewFileSubInbox(t *testing.T) {
	dir := t.TempDir()
	// sub-inbox (simplified format) should not create _new.md
	EnsureNewFile(dir, "a/b", InboxConfig{FileFormat: "{contact}.md"})
	p := filepath.Join(dir, "a", "b", "_new.md")
	if _, err := os.Stat(p); err == nil {
		t.Error("sub-inbox should not have _new.md")
	}
}

func TestWriteThreadMD(t *testing.T) {
	dir := t.TempDir()
	inboxKey := "user@example.com"
	os.MkdirAll(filepath.Join(dir, inboxKey), 0755)
	ts := time.Now()
	m := makeMessage("msg-write", "thr-write", inboxKey, ts, "write body")
	m.ThreadID = jmap.ID("thr-write")

	written := WriteThreadMD(dir, inboxKey, []Message{m}, InboxConfig{})
	if !written {
		t.Error("expected written=true")
	}

	// same messages → no change
	written2 := WriteThreadMD(dir, inboxKey, []Message{m}, InboxConfig{})
	if written2 {
		t.Error("expected written=false on identical content")
	}
}

func TestWriteThreadMDEmpty(t *testing.T) {
	dir := t.TempDir()
	if WriteThreadMD(dir, "inbox", nil, InboxConfig{}) {
		t.Error("expected false for empty messages")
	}
}

func TestSetMDMtime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	os.WriteFile(path, []byte("content"), 0644)

	ts := time.Date(2020, 1, 15, 12, 0, 0, 0, time.UTC)
	m := Message{ReceivedAt: TimePtr(ts)}
	SetMDMtime(path, []Message{m})

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !fi.ModTime().Equal(ts) {
		t.Errorf("mtime = %v, want %v", fi.ModTime(), ts)
	}
}

func TestSetMDMtimeNoMessages(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	os.WriteFile(path, []byte("content"), 0644)
	fi1, _ := os.Stat(path)
	SetMDMtime(path, nil)
	fi2, _ := os.Stat(path)
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Error("mtime should not change with empty messages")
	}
}

func TestCleanupOrphanedInboxes(t *testing.T) {
	dir := t.TempDir()
	// create managed inbox (has _new.md)
	managed := filepath.Join(dir, "old@inbox.com")
	os.MkdirAll(managed, 0755)
	os.WriteFile(filepath.Join(managed, "_new.md"), []byte(NewFileContent()), 0644)

	state := NewState()
	state.UpdateRelay("relay1", []string{"known@inbox.com"})

	CleanupOrphanedInboxes(dir, state, map[string][]string{
		"relay1": {"known@inbox.com"},
	})

	if _, err := os.Stat(managed); err == nil {
		t.Error("expected orphaned inbox to be removed")
	}
}

func TestCleanupOrphanedInboxesEmptyState(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "user@example.com")
	os.MkdirAll(managed, 0755)
	os.WriteFile(filepath.Join(managed, "_new.md"), []byte(NewFileContent()), 0644)

	state := NewState() // empty state → skip cleanup
	CleanupOrphanedInboxes(dir, state, nil)

	if _, err := os.Stat(managed); err != nil {
		t.Error("inbox should NOT be removed when state is empty")
	}
}
