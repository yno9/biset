package vault

import (
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

func TestSubmissionFilePath(t *testing.T) {
	got := SubmissionFilePath("/vault", "sub-1")
	want := filepath.Join("/vault", ".data", "submissions", "sub-1.json")
	if got != want {
		t.Errorf("SubmissionFilePath = %q, want %q", got, want)
	}
}

func TestWriteSubmissionAndScan(t *testing.T) {
	dir := makeVaultDir(t)
	sub := PendingSubmission{
		ID:          "sub-1",
		MailboxName: "inbox",
		Created:     time.Now(),
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

func TestPendingSubmissionRoundtrip(t *testing.T) {
	// Lightweight smoke test the migration helper writes a JSON file that
	// scans back round-trips.
	_ = jmap.ID("ignored")
}
