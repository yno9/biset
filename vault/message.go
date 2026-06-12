package vault

import (
	"fmt"
	"sort"
	"strings"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"git.sr.ht/~rockorager/go-jmap/mail/mailbox"
)

// ── time helpers ──────────────────────────────────────────────────────────────

func TimePtr(t time.Time) *time.Time { return &t }

func TimeVal(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// ── ID helpers ────────────────────────────────────────────────────────────────

func MakeMessageID(messageID, inboxKey string, ts time.Time) string {
	if messageID != "" {
		id := strings.Trim(messageID, "<>")
		id = strings.ReplaceAll(id, "/", "_")
		return "msg-" + id
	}
	return fmt.Sprintf("msg-%s-%d", strings.ReplaceAll(inboxKey, "/", "-"), ts.UnixMilli())
}

func MakeMailboxID(inboxKey string) string {
	return "mbx-" + strings.ReplaceAll(inboxKey, "/", "~")
}

func InboxKeyFromMailboxID(mailboxID string) string {
	return strings.ReplaceAll(strings.TrimPrefix(mailboxID, "mbx-"), "~", "/")
}

func MakeThreadID(rootMessageID string) string {
	id := strings.Trim(rootMessageID, "<>")
	if id == "" {
		return fmt.Sprintf("thr-ts-%d", time.Now().UnixMilli())
	}
	return "thr-" + strings.ReplaceAll(id, "/", "_")
}

func MessageIDFromMsgID(msgID string) string {
	id := strings.TrimPrefix(msgID, "msg-")
	if id == "" {
		return ""
	}
	return "<" + id + ">"
}

// ── Message construction ──────────────────────────────────────────────────────

func NewTextMessage(id, threadID, mailboxID string, from []*Address, to, cc []*Address, subject, body string, receivedAt time.Time, inReplyTo string) Message {
	partID := "1"
	m := Message{
		ID:         jmap.ID(id),
		BlobID:     jmap.ID("blob-" + id),
		ThreadID:   jmap.ID(threadID),
		MailboxIDs: map[jmap.ID]bool{jmap.ID(mailboxID): true},
		Keywords:   map[string]bool{},
		From:       from,
		To:         to,
		CC:         cc,
		Subject:    subject,
		ReceivedAt: TimePtr(receivedAt),
		BodyValues: map[string]*BodyValue{
			partID: {Value: body},
		},
		TextBody: []*BodyPart{{
			PartID:  partID,
			BlobID:  jmap.ID("blob-" + id + "-body"),
			Type:    "text/plain",
			Charset: "utf-8",
			Size:    uint64(len(body)),
		}},
		HTMLBody: []*BodyPart{},
		Preview:  previewText(body),
		Size:     uint64(len(body)),
	}
	if inReplyTo != "" {
		m.InReplyTo = []string{inReplyTo}
		m.References = []string{inReplyTo}
	}
	return m
}

func previewText(body string) string {
	r := []rune(body)
	if len(r) > 256 {
		return string(r[:256])
	}
	return body
}

// ── Message field helpers ─────────────────────────────────────────────────────

func MessageBody(m Message) string {
	if len(m.TextBody) > 0 && m.TextBody[0] != nil {
		partID := m.TextBody[0].PartID
		if bv, ok := m.BodyValues[partID]; ok && bv != nil {
			return bv.Value
		}
	}
	return ""
}

func MessageFromAddr(m Message) string {
	if len(m.From) > 0 && m.From[0] != nil {
		return m.From[0].Email
	}
	return ""
}

func MessageFromName(m Message) string {
	if len(m.From) > 0 && m.From[0] != nil {
		return m.From[0].Name
	}
	return ""
}

func MessageIsSeen(m Message) bool {
	return m.Keywords["$seen"]
}

func MessageHeaderID(m Message) string {
	if len(m.MessageID) > 0 {
		return m.MessageID[0]
	}
	return ""
}

func MessageInReplyTo(m Message) string {
	if len(m.InReplyTo) > 0 {
		return m.InReplyTo[0]
	}
	return ""
}

func MessageMailboxID(m Message) string {
	for id := range m.MailboxIDs {
		return string(id)
	}
	return ""
}

// ── Mailbox helpers ───────────────────────────────────────────────────────────

func DefaultInbox(inboxKey string) Inbox {
	return Inbox{
		ID:   jmap.ID(MakeMailboxID(inboxKey)),
		Name: inboxKey,
		Role: mailbox.RoleInbox,
		Rights: &mailbox.Rights{
			MayReadItems:   true,
			MayAddItems:    true,
			MayRemoveItems: true,
			MaySetSeen:     true,
			MaySetKeywords: true,
			MayCreateChild: false,
			MayRename:      false,
			MayDelete:      false,
			MaySubmit:      true,
		},
		IsSubscribed: true,
	}
}

// ── Thread grouping ───────────────────────────────────────────────────────────

func AssignThreadIDs(messages []Message) []Message {
	parentOf := map[string]string{}
	for _, m := range messages {
		msgID := MessageHeaderID(m)
		if msgID == "" {
			continue
		}
		irt := MessageInReplyTo(m)
		if irt != "" {
			parentOf[msgID] = irt
		} else if _, exists := parentOf[msgID]; !exists {
			parentOf[msgID] = ""
		}
	}

	rootOf := func(msgID string) string {
		visited := map[string]bool{}
		cur := msgID
		for cur != "" {
			if visited[cur] {
				break
			}
			visited[cur] = true
			parent, known := parentOf[cur]
			if !known || parent == "" {
				break
			}
			cur = parent
		}
		return cur
	}

	for i := range messages {
		if messages[i].ThreadID != "" {
			continue
		}
		msgID := MessageHeaderID(messages[i])
		parentID := MessageInReplyTo(messages[i])

		var root string
		if msgID != "" {
			root = rootOf(msgID)
		} else if parentID != "" {
			root = parentID
		}

		if root != "" {
			messages[i].ThreadID = jmap.ID(MakeThreadID(root))
		} else {
			messages[i].ThreadID = jmap.ID(fmt.Sprintf("thr-ts-%d", TimeVal(messages[i].ReceivedAt).UnixMilli()))
		}
	}
	return messages
}

func GroupByThread(messages []Message) []Thread {
	threadMsgs := map[string][]Message{}
	order := []string{}
	seen := map[string]bool{}

	for _, m := range messages {
		tid := string(m.ThreadID)
		if !seen[tid] {
			seen[tid] = true
			order = append(order, tid)
		}
		threadMsgs[tid] = append(threadMsgs[tid], m)
	}

	sort.Slice(order, func(i, j int) bool {
		return latestMsgTs(threadMsgs[order[i]]) > latestMsgTs(threadMsgs[order[j]])
	})

	threads := make([]Thread, 0, len(order))
	for _, tid := range order {
		grp := threadMsgs[tid]
		sort.Slice(grp, func(i, j int) bool {
			return TimeVal(grp[i].ReceivedAt).After(TimeVal(grp[j].ReceivedAt))
		})
		ids := make([]jmap.ID, len(grp))
		for i, m := range grp {
			ids[i] = m.ID
		}
		threads = append(threads, Thread{ID: jmap.ID(tid), EmailIDs: ids})
	}
	return threads
}

func latestMsgTs(messages []Message) int64 {
	var max int64
	for _, m := range messages {
		if ts := TimeVal(m.ReceivedAt).UnixMilli(); ts > max {
			max = ts
		}
	}
	return max
}

func DeduplicateMessages(messages []Message) []Message {
	seen := map[jmap.ID]bool{}
	out := messages[:0:len(messages)]
	for _, m := range messages {
		if !seen[m.ID] {
			seen[m.ID] = true
			out = append(out, m)
		}
	}
	return out
}

func MergeMessages(incoming, existing []Message) []Message {
	byID := map[jmap.ID]Message{}
	for _, m := range existing {
		byID[m.ID] = m
	}
	for _, m := range incoming {
		if ex, ok := byID[m.ID]; ok && ex.Keywords["$seen"] && !m.Keywords["$seen"] {
			if m.Keywords == nil {
				m.Keywords = map[string]bool{}
			}
			m.Keywords["$seen"] = true
		}
		byID[m.ID] = m
	}
	merged := make([]Message, 0, len(byID))
	for _, m := range byID {
		merged = append(merged, m)
	}
	sort.Slice(merged, func(i, j int) bool {
		return TimeVal(merged[i].ReceivedAt).After(TimeVal(merged[j].ReceivedAt))
	})
	return merged
}

// ── misc ──────────────────────────────────────────────────────────────────────

func SafeFilename(s string) string {
	rep := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "*", "-", "?", "-", "\"", "-", "<", "-", ">", "-", "|", "-")
	s = rep.Replace(s)
	if len(s) > 60 {
		s = s[:60]
	}
	return strings.TrimSpace(s)
}
