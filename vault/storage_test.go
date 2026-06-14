package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
)

func makeVaultDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

func TestMessageFilePath(t *testing.T) {
	got := MessageFilePath("/vault", jmap.ID("msg-abc"))
	want := filepath.Join("/vault", ".data", "messages", "msg-abc.json")
	if got != want {
		t.Errorf("MessageFilePath = %q, want %q", got, want)
	}
}

func TestThreadFilePath(t *testing.T) {
	got := ThreadFilePath("/vault", jmap.ID("thr-abc"))
	want := filepath.Join("/vault", ".data", "threads", "thr-abc.json")
	if got != want {
		t.Errorf("ThreadFilePath = %q, want %q", got, want)
	}
}

func TestMailboxesFilePath(t *testing.T) {
	got := MailboxesFilePath("/vault")
	want := filepath.Join("/vault", ".data", "mailboxes.json")
	if got != want {
		t.Errorf("MailboxesFilePath = %q, want %q", got, want)
	}
}

func TestSubmissionFilePath(t *testing.T) {
	got := SubmissionFilePath("/vault", "sub-1")
	want := filepath.Join("/vault", ".data", "submissions", "sub-1.json")
	if got != want {
		t.Errorf("SubmissionFilePath = %q, want %q", got, want)
	}
}

func TestWriteReadMessage(t *testing.T) {
	dir := makeVaultDir(t)
	ts := time.Now().UTC().Truncate(time.Millisecond)
	m := Message{
		ID:         jmap.ID("msg-test"),
		Subject:    "Hello",
		ReceivedAt: TimePtr(ts),
	}
	changed, err := WriteMessage(dir, m)
	if err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	if !changed {
		t.Error("expected changed=true on first write")
	}

	got, err := ReadMessage(dir, m.ID)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if got.ID != m.ID {
		t.Errorf("ID = %q", got.ID)
	}
	if got.Subject != m.Subject {
		t.Errorf("Subject = %q", got.Subject)
	}

	// write same content → not changed
	changed2, _ := WriteMessage(dir, m)
	if changed2 {
		t.Error("expected changed=false on identical write")
	}
}

func TestReadMessageNotFound(t *testing.T) {
	dir := makeVaultDir(t)
	_, err := ReadMessage(dir, "missing")
	if err == nil {
		t.Error("expected error")
	}
}

func TestDeleteMessage(t *testing.T) {
	dir := makeVaultDir(t)
	m := Message{ID: jmap.ID("msg-del")}
	WriteMessage(dir, m)
	if err := DeleteMessage(dir, m.ID); err != nil {
		t.Fatalf("DeleteMessage: %v", err)
	}
	if _, err := ReadMessage(dir, m.ID); err == nil {
		t.Error("expected error after delete")
	}
}

func TestScanMessages(t *testing.T) {
	dir := makeVaultDir(t)
	ts := time.Now()
	WriteMessage(dir, Message{ID: jmap.ID("msg-1"), ReceivedAt: TimePtr(ts)})
	WriteMessage(dir, Message{ID: jmap.ID("msg-2"), ReceivedAt: TimePtr(ts)})

	msgs, err := ScanMessages(dir)
	if err != nil {
		t.Fatalf("ScanMessages: %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("len = %d, want 2", len(msgs))
	}
}

func TestScanMessagesEmpty(t *testing.T) {
	dir := makeVaultDir(t)
	msgs, err := ScanMessages(dir)
	if err == nil && len(msgs) != 0 {
		t.Error("expected empty or error on missing dir")
	}
}

func TestPurgeMessageCache(t *testing.T) {
	dir := makeVaultDir(t)
	ts := time.Now()
	WriteMessage(dir, Message{ID: jmap.ID("msg-purge"), ReceivedAt: TimePtr(ts)})
	PurgeMessageCache(dir)
	msgs, _ := ScanMessages(dir)
	if len(msgs) != 0 {
		t.Errorf("expected empty after purge, got %d", len(msgs))
	}
}

func TestWriteReadThread(t *testing.T) {
	dir := makeVaultDir(t)
	th := Thread{
		ID:       jmap.ID("thr-test"),
		EmailIDs: []jmap.ID{"msg-1", "msg-2"},
	}
	changed, err := WriteThread(dir, th)
	if err != nil {
		t.Fatalf("WriteThread: %v", err)
	}
	if !changed {
		t.Error("expected changed")
	}

	got, err := ReadThread(dir, th.ID)
	if err != nil {
		t.Fatalf("ReadThread: %v", err)
	}
	if got.ID != th.ID {
		t.Errorf("ID = %q", got.ID)
	}
	if len(got.EmailIDs) != 2 {
		t.Errorf("EmailIDs len = %d", len(got.EmailIDs))
	}
}

func TestDeleteThread(t *testing.T) {
	dir := makeVaultDir(t)
	th := Thread{ID: jmap.ID("thr-del")}
	WriteThread(dir, th)
	if err := DeleteThread(dir, th.ID); err != nil {
		t.Fatalf("DeleteThread: %v", err)
	}
	if _, err := ReadThread(dir, th.ID); err == nil {
		t.Error("expected error after delete")
	}
}

func TestScanThreads(t *testing.T) {
	dir := makeVaultDir(t)
	WriteThread(dir, Thread{ID: jmap.ID("thr-1")})
	WriteThread(dir, Thread{ID: jmap.ID("thr-2")})

	threads, err := ScanThreads(dir)
	if err != nil {
		t.Fatalf("ScanThreads: %v", err)
	}
	if len(threads) != 2 {
		t.Errorf("len = %d, want 2", len(threads))
	}
}

func TestReadMessagesForThread(t *testing.T) {
	dir := makeVaultDir(t)
	ts := time.Now()
	m1 := Message{ID: jmap.ID("msg-a"), ThreadID: jmap.ID("thr-x"), ReceivedAt: TimePtr(ts)}
	m2 := Message{ID: jmap.ID("msg-b"), ThreadID: jmap.ID("thr-x"), ReceivedAt: TimePtr(ts)}
	WriteMessage(dir, m1)
	WriteMessage(dir, m2)
	th := Thread{ID: jmap.ID("thr-x"), EmailIDs: []jmap.ID{"msg-a", "msg-b"}}
	WriteThread(dir, th)

	msgs := ReadMessagesForThread(dir, jmap.ID("thr-x"))
	if len(msgs) != 2 {
		t.Errorf("len = %d, want 2", len(msgs))
	}
}

func TestReadMessagesForThreadNotFound(t *testing.T) {
	dir := makeVaultDir(t)
	msgs := ReadMessagesForThread(dir, jmap.ID("thr-missing"))
	if len(msgs) != 0 {
		t.Errorf("expected nil, got %v", msgs)
	}
}

func TestWriteSubmissionAndScan(t *testing.T) {
	dir := makeVaultDir(t)
	sub := PendingSubmission{
		ID:      "sub-1",
		InboxKey: "inbox",
		Created:  time.Now(),
	}
	if err := WriteSubmission(dir, sub); err != nil {
		t.Fatalf("WriteSubmission: %v", err)
	}
	subs, err := ScanSubmissions(dir)
	if err != nil {
		t.Fatalf("ScanSubmissions: %v", err)
	}
	if len(subs) != 1 || subs[0].ID != "sub-1" {
		t.Errorf("subs = %+v", subs)
	}
}

func TestScanSubmissionsEmpty(t *testing.T) {
	dir := makeVaultDir(t)
	subs, err := ScanSubmissions(dir)
	if err != nil {
		t.Fatalf("ScanSubmissions: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("expected empty, got %v", subs)
	}
}

func TestDeleteSubmission(t *testing.T) {
	dir := makeVaultDir(t)
	sub := PendingSubmission{ID: "sub-del", Created: time.Now()}
	WriteSubmission(dir, sub)
	if err := DeleteSubmission(dir, sub.ID); err != nil {
		t.Fatalf("DeleteSubmission: %v", err)
	}
	subs, _ := ScanSubmissions(dir)
	if len(subs) != 0 {
		t.Errorf("expected 0 after delete, got %d", len(subs))
	}
}

func TestWriteReadInboxes(t *testing.T) {
	dir := makeVaultDir(t)
	inboxes := []Inbox{DefaultInbox("a@b.com"), DefaultInbox("c@d.com")}
	if err := WriteInboxes(dir, inboxes); err != nil {
		t.Fatalf("WriteInboxes: %v", err)
	}
	got := ReadInboxes(dir)
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
}

func TestReadInboxesNotFound(t *testing.T) {
	dir := makeVaultDir(t)
	got := ReadInboxes(dir)
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestWriteIfChanged(t *testing.T) {
	dir := makeVaultDir(t)
	path := filepath.Join(dir, "test.txt")

	if !WriteIfChanged(path, "hello") {
		t.Error("expected changed=true on new file")
	}
	if WriteIfChanged(path, "hello") {
		t.Error("expected changed=false on same content")
	}
	if !WriteIfChanged(path, "world") {
		t.Error("expected changed=true on different content")
	}
}

func TestGetInboxesFromDir(t *testing.T) {
	dir := makeVaultDir(t)
	os.MkdirAll(filepath.Join(dir, "inbox1"), 0755)
	os.MkdirAll(filepath.Join(dir, ".hidden"), 0755)

	got := GetInboxes(dir)
	if len(got) != 1 {
		t.Errorf("len = %d, want 1 (inbox1 only)", len(got))
	}
}

func TestGetInboxesFromStorage(t *testing.T) {
	dir := makeVaultDir(t)
	inboxes := []Inbox{DefaultInbox("a@b.com")}
	WriteInboxes(dir, inboxes)
	got := GetInboxes(dir)
	if len(got) != 1 {
		t.Errorf("len = %d, want 1", len(got))
	}
}


func TestGetIdentities(t *testing.T) {
	dir := makeVaultDir(t)
	os.MkdirAll(filepath.Join(dir, "user@example.com"), 0755)
	os.MkdirAll(filepath.Join(dir, ".hidden"), 0755)

	ids := GetIdentities(dir)
	if len(ids) != 1 {
		t.Errorf("len = %d, want 1", len(ids))
	}
	if ids[0].Email != "user@example.com" {
		t.Errorf("Email = %q", ids[0].Email)
	}
}

func TestFindThreadByMessageID(t *testing.T) {
	dir := makeVaultDir(t)
	ts := time.Now()
	m := Message{
		ID:        jmap.ID("msg-x"),
		ThreadID:  jmap.ID("thr-y"),
		MessageID: []string{"<root@x.com>"},
		ReceivedAt: TimePtr(ts),
	}
	WriteMessage(dir, m)

	got := FindThreadByMessageID(dir, "<root@x.com>")
	if got != "thr-y" {
		t.Errorf("FindThreadByMessageID = %q, want thr-y", got)
	}
	if FindThreadByMessageID(dir, "<missing@x.com>") != "" {
		t.Error("expected empty for missing")
	}
}
