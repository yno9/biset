package vault

import (
	"strings"
	"testing"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
)

func TestTimePtr(t *testing.T) {
	now := time.Now()
	p := TimePtr(now)
	if p == nil {
		t.Fatal("TimePtr returned nil")
	}
	if !p.Equal(now) {
		t.Errorf("TimePtr value mismatch")
	}
}

func TestTimeVal(t *testing.T) {
	now := time.Now()
	if got := TimeVal(&now); !got.Equal(now) {
		t.Error("TimeVal mismatch")
	}
	if got := TimeVal(nil); !got.IsZero() {
		t.Errorf("TimeVal(nil) = %v, want zero", got)
	}
}

func TestMakeMessageID(t *testing.T) {
	ts := time.Unix(1_000_000, 0)
	// with messageID
	got := MakeMessageID("<abc@example.com>", "inbox", ts)
	if got != "msg-abc@example.com" {
		t.Errorf("MakeMessageID with messageID = %q", got)
	}
	// slash in messageID gets replaced
	got = MakeMessageID("<a/b@c>", "inbox", ts)
	if got != "msg-a_b@c" {
		t.Errorf("MakeMessageID slash = %q", got)
	}
	// no messageID → timestamp based
	got = MakeMessageID("", "a/b", ts)
	if !strings.HasPrefix(got, "msg-a-b-") {
		t.Errorf("MakeMessageID fallback = %q", got)
	}
}

func TestMakeMailboxID(t *testing.T) {
	tests := []struct{ in, want string }{
		{"inbox", "mbx-inbox"},
		{"a/b", "mbx-a~b"},
		{"", "mbx-"},
		{"a/b/c", "mbx-a~b~c"},
	}
	for _, tt := range tests {
		if got := MakeMailboxID(tt.in); got != tt.want {
			t.Errorf("MakeMailboxID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestInboxKeyFromMailboxID(t *testing.T) {
	tests := []struct{ in, want string }{
		{"mbx-inbox", "inbox"},
		{"mbx-a~b", "a/b"},
		{"mbx-a~b~c", "a/b/c"},
		{"mbx-", ""},
	}
	for _, tt := range tests {
		if got := InboxKeyFromMailboxID(tt.in); got != tt.want {
			t.Errorf("InboxKeyFromMailboxID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMakeMailboxIDRoundtrip(t *testing.T) {
	keys := []string{"inbox", "a/b", "a/b/c", "user@example.com"}
	for _, k := range keys {
		mbxID := MakeMailboxID(k)
		got := InboxKeyFromMailboxID(mbxID)
		if got != k {
			t.Errorf("roundtrip(%q) = %q", k, got)
		}
	}
}

func TestMakeThreadID(t *testing.T) {
	got := MakeThreadID("<root@example.com>")
	if got != "thr-root@example.com" {
		t.Errorf("MakeThreadID = %q", got)
	}
	// slash replaced
	got = MakeThreadID("<a/b@c>")
	if got != "thr-a_b@c" {
		t.Errorf("MakeThreadID slash = %q", got)
	}
	// empty → ts-based
	got = MakeThreadID("")
	if !strings.HasPrefix(got, "thr-ts-") {
		t.Errorf("MakeThreadID empty = %q", got)
	}
}

func TestMessageIDFromMsgID(t *testing.T) {
	tests := []struct{ in, want string }{
		{"msg-abc@x.com", "<abc@x.com>"},
		{"msg-", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := MessageIDFromMsgID(tt.in); got != tt.want {
			t.Errorf("MessageIDFromMsgID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func testAddr(email string) *Address { return &Address{Email: email} }

func TestNewTextMessage(t *testing.T) {
	ts := time.Now()
	from := []*Address{testAddr("a@b.com")}
	to := []*Address{testAddr("c@d.com")}
	m := NewTextMessage("id1", "thr1", "mbx1", from, to, nil, "subj", "hello world", ts, "")
	if string(m.ID) != "id1" {
		t.Errorf("ID = %q", m.ID)
	}
	if m.Subject != "subj" {
		t.Errorf("Subject = %q", m.Subject)
	}
	if MessageBody(m) != "hello world" {
		t.Errorf("Body = %q", MessageBody(m))
	}
	if len(m.InReplyTo) != 0 {
		t.Errorf("InReplyTo should be empty")
	}

	// with inReplyTo
	m2 := NewTextMessage("id2", "thr1", "mbx1", from, to, nil, "re", "body", ts, "<parent@x.com>")
	if len(m2.InReplyTo) != 1 || m2.InReplyTo[0] != "<parent@x.com>" {
		t.Errorf("InReplyTo = %v", m2.InReplyTo)
	}
}

func TestNewTextMessageLongBody(t *testing.T) {
	body := strings.Repeat("x", 300)
	m := NewTextMessage("id", "t", "m", nil, nil, nil, "", body, time.Now(), "")
	if len([]rune(m.Preview)) != 256 {
		t.Errorf("Preview len = %d", len([]rune(m.Preview)))
	}
}

func TestMessageBody(t *testing.T) {
	m := NewTextMessage("id", "t", "m", nil, nil, nil, "", "hello", time.Now(), "")
	if MessageBody(m) != "hello" {
		t.Errorf("MessageBody = %q", MessageBody(m))
	}
	// empty message
	if MessageBody(Message{}) != "" {
		t.Error("MessageBody on empty Message")
	}
}

func TestMessageFromAddr(t *testing.T) {
	m := Message{From: []*Address{{Email: "a@b.com"}}}
	if MessageFromAddr(m) != "a@b.com" {
		t.Errorf("MessageFromAddr = %q", MessageFromAddr(m))
	}
	if MessageFromAddr(Message{}) != "" {
		t.Error("MessageFromAddr on empty")
	}
	m2 := Message{From: []*Address{nil}}
	if MessageFromAddr(m2) != "" {
		t.Error("MessageFromAddr with nil addr")
	}
}

func TestMessageFromName(t *testing.T) {
	m := Message{From: []*Address{{Email: "a@b.com", Name: "Alice"}}}
	if MessageFromName(m) != "Alice" {
		t.Errorf("MessageFromName = %q", MessageFromName(m))
	}
	if MessageFromName(Message{}) != "" {
		t.Error("MessageFromName on empty")
	}
}

func TestMessageIsSeen(t *testing.T) {
	m := Message{Keywords: map[string]bool{"$seen": true}}
	if !MessageIsSeen(m) {
		t.Error("expected seen")
	}
	m2 := Message{Keywords: map[string]bool{}}
	if MessageIsSeen(m2) {
		t.Error("expected not seen")
	}
	if MessageIsSeen(Message{}) {
		t.Error("expected not seen on empty")
	}
}

func TestMessageHeaderID(t *testing.T) {
	m := Message{MessageID: []string{"<x@y.com>"}}
	if MessageHeaderID(m) != "<x@y.com>" {
		t.Errorf("MessageHeaderID = %q", MessageHeaderID(m))
	}
	if MessageHeaderID(Message{}) != "" {
		t.Error("MessageHeaderID on empty")
	}
}

func TestMessageInReplyTo(t *testing.T) {
	m := Message{InReplyTo: []string{"<p@q.com>"}}
	if MessageInReplyTo(m) != "<p@q.com>" {
		t.Errorf("MessageInReplyTo = %q", MessageInReplyTo(m))
	}
	if MessageInReplyTo(Message{}) != "" {
		t.Error("MessageInReplyTo on empty")
	}
}

func TestMessageMailboxID(t *testing.T) {
	mbxID := jmap.ID("mbx-inbox")
	m := Message{MailboxIDs: map[jmap.ID]bool{mbxID: true}}
	if got := MessageMailboxID(m); got != "mbx-inbox" {
		t.Errorf("MessageMailboxID = %q", got)
	}
	if MessageMailboxID(Message{}) != "" {
		t.Error("MessageMailboxID on empty")
	}
}

func TestDefaultInbox(t *testing.T) {
	ib := DefaultInbox("user@example.com")
	if string(ib.ID) != MakeMailboxID("user@example.com") {
		t.Errorf("ID = %q", ib.ID)
	}
	if ib.Name != "user@example.com" {
		t.Errorf("Name = %q", ib.Name)
	}
	if !ib.IsSubscribed {
		t.Error("expected IsSubscribed")
	}
	if ib.Rights == nil {
		t.Error("expected Rights")
	}
}

func TestSafeFilename(t *testing.T) {
	tests := []struct{ in, want string }{
		{"hello", "hello"},
		{"a/b", "a-b"},
		{"a\\b", "a-b"},
		{"a:b*c?d\"e<f>g|h", "a-b-c-d-e-f-g-h"},
		{"  spaces  ", "spaces"},
	}
	for _, tt := range tests {
		if got := SafeFilename(tt.in); got != tt.want {
			t.Errorf("SafeFilename(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSafeFilenameLong(t *testing.T) {
	long := strings.Repeat("a", 100)
	got := SafeFilename(long)
	if len(got) != 60 {
		t.Errorf("SafeFilename long len = %d, want 60", len(got))
	}
}


func TestAssignThreadIDs(t *testing.T) {
	ts := time.Now()
	m1 := Message{
		ID:         "1",
		MessageID:  []string{"<root@x.com>"},
		ReceivedAt: TimePtr(ts),
	}
	m2 := Message{
		ID:         "2",
		MessageID:  []string{"<reply@x.com>"},
		InReplyTo:  []string{"<root@x.com>"},
		ReceivedAt: TimePtr(ts.Add(time.Minute)),
	}
	msgs := AssignThreadIDs([]Message{m1, m2})
	// both should share the same thread root
	if msgs[0].ThreadID == "" {
		t.Error("m1 ThreadID empty")
	}
	if msgs[1].ThreadID == "" {
		t.Error("m2 ThreadID empty")
	}
	if msgs[0].ThreadID != msgs[1].ThreadID {
		t.Errorf("thread IDs differ: %q vs %q", msgs[0].ThreadID, msgs[1].ThreadID)
	}
}

func TestAssignThreadIDsNoMessageID(t *testing.T) {
	ts := time.Now()
	m := Message{ID: "1", ReceivedAt: TimePtr(ts)}
	msgs := AssignThreadIDs([]Message{m})
	if msgs[0].ThreadID == "" {
		t.Error("ThreadID should not be empty")
	}
}

func TestAssignThreadIDsAlreadySet(t *testing.T) {
	ts := time.Now()
	m := Message{ID: "1", ThreadID: "thr-existing", ReceivedAt: TimePtr(ts)}
	msgs := AssignThreadIDs([]Message{m})
	if msgs[0].ThreadID != "thr-existing" {
		t.Errorf("ThreadID = %q, want thr-existing", msgs[0].ThreadID)
	}
}

func TestGroupByThread(t *testing.T) {
	ts := time.Now()
	m1 := Message{ID: "1", ThreadID: "thr-a", ReceivedAt: TimePtr(ts)}
	m2 := Message{ID: "2", ThreadID: "thr-a", ReceivedAt: TimePtr(ts.Add(time.Minute))}
	m3 := Message{ID: "3", ThreadID: "thr-b", ReceivedAt: TimePtr(ts)}
	threads := GroupByThread([]Message{m1, m2, m3})
	if len(threads) != 2 {
		t.Fatalf("len = %d, want 2", len(threads))
	}
	// thread-a should be first (has latest message)
	if string(threads[0].ID) != "thr-a" {
		t.Errorf("first thread = %q, want thr-a", threads[0].ID)
	}
	if len(threads[0].EmailIDs) != 2 {
		t.Errorf("thread-a email count = %d", len(threads[0].EmailIDs))
	}
}

func TestGroupByThreadEmpty(t *testing.T) {
	threads := GroupByThread(nil)
	if len(threads) != 0 {
		t.Errorf("expected empty, got %d", len(threads))
	}
}
