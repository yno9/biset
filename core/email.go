package core

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ── ID helpers ────────────────────────────────────────────────────────────────

func MakeEmailID(messageID, inboxKey string, ts time.Time) string {
	if messageID != "" {
		id := strings.Trim(messageID, "<>")
		id = strings.ReplaceAll(id, "/", "_")
		return "eml-" + id
	}
	return fmt.Sprintf("eml-%s-%d", strings.ReplaceAll(inboxKey, "/", "-"), ts.UnixMilli())
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

// MessageIDFromEmailID extracts the original Message-ID from an email ID.
// Inverse of MakeEmailID (lossy: assumes no '/' in original message IDs).
func MessageIDFromEmailID(emailID string) string {
	id := strings.TrimPrefix(emailID, "eml-")
	if id == "" {
		return ""
	}
	return "<" + id + ">"
}

// ── Email helpers ─────────────────────────────────────────────────────────────

func NewTextEmail(id, threadID, mailboxID string, from []Address, to, cc []Address, subject, body string, receivedAt time.Time, inReplyTo string) Email {
	partID := "1"
	e := Email{
		ID:         id,
		BlobID:     "blob-" + id,
		ThreadID:   threadID,
		MailboxIDs: map[string]bool{mailboxID: true},
		Keywords:   map[string]bool{},
		From:       from,
		To:         to,
		Cc:         cc,
		Subject:    subject,
		ReceivedAt: receivedAt,
		BodyValues: map[string]BodyValue{
			partID: {Value: body},
		},
		TextBody: []BodyPart{{
			PartID:  partID,
			BlobID:  "blob-" + id + "-body",
			Type:    "text/plain",
			Charset: "utf-8",
			Size:    len(body),
		}},
		HtmlBody: []BodyPart{},
		Preview:  previewText(body),
		Size:     len(body),
	}
	if inReplyTo != "" {
		e.InReplyTo = []string{inReplyTo}
		e.References = []string{inReplyTo}
	}
	return e
}

func previewText(body string) string {
	r := []rune(body)
	if len(r) > 256 {
		return string(r[:256])
	}
	return body
}

// EmailBody returns the plain text body of an email.
func EmailBody(e Email) string {
	if len(e.TextBody) > 0 {
		partID := e.TextBody[0].PartID
		if bv, ok := e.BodyValues[partID]; ok {
			return bv.Value
		}
	}
	return ""
}

// EmailFromAddr returns the first From address email string.
func EmailFromAddr(e Email) string {
	if len(e.From) > 0 {
		return e.From[0].Email
	}
	return ""
}

// EmailFromName returns the first From address display name.
func EmailFromName(e Email) string {
	if len(e.From) > 0 {
		return e.From[0].Name
	}
	return ""
}

// EmailIsSeen reports whether the email has the $seen keyword.
func EmailIsSeen(e Email) bool {
	return e.Keywords["$seen"]
}

// EmailMessageID returns the first Message-ID value, or "".
func EmailMessageID(e Email) string {
	if len(e.MessageID) > 0 {
		return e.MessageID[0]
	}
	return ""
}

// EmailInReplyTo returns the first In-Reply-To value, or "".
func EmailInReplyTo(e Email) string {
	if len(e.InReplyTo) > 0 {
		return e.InReplyTo[0]
	}
	return ""
}

// EmailMailboxID returns the first mailbox ID the email belongs to.
func EmailMailboxID(e Email) string {
	for id := range e.MailboxIDs {
		return id
	}
	return ""
}

// DefaultMailbox returns a standard inbox Mailbox for the given inboxKey.
func DefaultMailbox(inboxKey string) Mailbox {
	return Mailbox{
		ID:       MakeMailboxID(inboxKey),
		Name:     inboxKey,
		ParentID: nil,
		Role:     "inbox",
		MyRights: MailboxRights{
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

// ── thread grouping ───────────────────────────────────────────────────────────

// AssignThreadIDs walks the InReplyTo chain within the batch and sets ThreadID
// on emails that don't already have one.
func AssignThreadIDs(emails []Email) []Email {
	// parentOf maps messageID → inReplyTo, preferring entries that have one.
	// The same message can appear multiple times (inbox + sent copies with different
	// Email IDs but identical Message-IDs). The sent copy often lacks InReplyTo,
	// so we must not let it overwrite the inbox copy's chain.
	parentOf := map[string]string{}
	for _, e := range emails {
		msgID := EmailMessageID(e)
		if msgID == "" {
			continue
		}
		irt := EmailInReplyTo(e)
		if irt != "" {
			parentOf[msgID] = irt // any copy with InReplyTo wins
		} else if _, exists := parentOf[msgID]; !exists {
			parentOf[msgID] = ""
		}
	}

	rootOf := func(msgID string) string {
		visited := map[string]bool{}
		cur := msgID
		for cur != "" {
			if visited[cur] {
				break // cycle
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

	for i := range emails {
		if emails[i].ThreadID != "" {
			continue
		}
		msgID := EmailMessageID(emails[i])
		parentID := EmailInReplyTo(emails[i])

		var root string
		if msgID != "" {
			root = rootOf(msgID)
		} else if parentID != "" {
			root = parentID
		}

		if root != "" {
			emails[i].ThreadID = MakeThreadID(root)
		} else {
			emails[i].ThreadID = fmt.Sprintf("thr-ts-%d", emails[i].ReceivedAt.UnixMilli())
		}
	}
	return emails
}

// GroupByThread groups emails by ThreadID and returns one Thread per group,
// sorted by most recent email descending.
func GroupByThread(emails []Email) []Thread {
	threadEmails := map[string][]Email{}
	order := []string{}
	seen := map[string]bool{}

	for _, e := range emails {
		tid := e.ThreadID
		if !seen[tid] {
			seen[tid] = true
			order = append(order, tid)
		}
		threadEmails[tid] = append(threadEmails[tid], e)
	}

	sort.Slice(order, func(i, j int) bool {
		return latestEmailTs(threadEmails[order[i]]) > latestEmailTs(threadEmails[order[j]])
	})

	threads := make([]Thread, 0, len(order))
	for _, tid := range order {
		grp := threadEmails[tid]
		sort.Slice(grp, func(i, j int) bool {
			return grp[i].ReceivedAt.After(grp[j].ReceivedAt)
		})
		eIDs := make([]string, len(grp))
		for i, e := range grp {
			eIDs[i] = e.ID
		}
		threads = append(threads, Thread{ID: tid, EmailIDs: eIDs})
	}
	return threads
}

func latestEmailTs(emails []Email) int64 {
	var max int64
	for _, e := range emails {
		if ts := e.ReceivedAt.UnixMilli(); ts > max {
			max = ts
		}
	}
	return max
}

// DeduplicateEmails removes duplicate emails by ID (last write wins).
func DeduplicateEmails(emails []Email) []Email {
	seen := map[string]bool{}
	out := emails[:0:len(emails)]
	for _, e := range emails {
		if !seen[e.ID] {
			seen[e.ID] = true
			out = append(out, e)
		}
	}
	return out
}

// MergeEmails merges incoming emails with existing ones, deduplicating by ID.
// Incoming emails take precedence (update existing).
func MergeEmails(incoming, existing []Email) []Email {
	byID := map[string]Email{}
	for _, e := range existing {
		byID[e.ID] = e
	}
	for _, e := range incoming {
		if ex, ok := byID[e.ID]; ok && ex.Keywords["$seen"] && !e.Keywords["$seen"] {
			// local already marked seen; server hasn't propagated yet — preserve local state
			if e.Keywords == nil {
				e.Keywords = map[string]bool{}
			}
			e.Keywords["$seen"] = true
		}
		byID[e.ID] = e
	}
	merged := make([]Email, 0, len(byID))
	for _, e := range byID {
		merged = append(merged, e)
	}
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].ReceivedAt.After(merged[j].ReceivedAt)
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
