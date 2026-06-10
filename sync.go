package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yd7a/biset/core"
)

// SyncNotification holds info for a desktop notification.
type SyncNotification struct {
	Contact   string
	Body      string
	Ts        int64
	MessageID string
}

func runSync(cfg *Config, mgr *core.Manager) (int, []SyncNotification) {
	lockPath, ok := acquireLock(cfg.Vault)
	if !ok {
		log.Printf("sync already running — skipping")
		return 0, nil
	}
	defer os.Remove(lockPath)

	if err := os.MkdirAll(cfg.Vault, 0755); err != nil {
		log.Printf("mkdir vault: %v", err)
		return 0, nil
	}

	// migrate old vault format on first run
	core.MigrateVault(cfg.Vault)

	// 1. flush outgoing
	core.FlushOutgoing(cfg.Vault, mgr)

	// 2. flush actions
	core.FlushActions(cfg.Vault, mgr)

	// 3. fetch from all connectors
	var allEmails []core.Email
	var allMailboxes []core.Mailbox
	mailboxSeen := map[string]bool{}
	for _, c := range mgr.Connectors() {
		if !c.Has("fetch") {
			continue
		}
		result, err := c.Fetch()
		if err != nil {
			log.Printf("[%s] fetch: %v", c.Name(), err)
			continue
		}
		allEmails = append(allEmails, result.Emails...)
		for _, m := range result.Mailboxes {
			if !mailboxSeen[m.ID] {
				mailboxSeen[m.ID] = true
				allMailboxes = append(allMailboxes, m)
			}
		}
	}

	// 4. assign thread IDs + deduplicate
	// Pre-resolve threadIDs for replies to already-stored emails.
	// AssignThreadIDs only sees the current batch; without this, a reply
	// fetched in a later sync cycle gets a brand-new threadId instead of
	// joining the original thread.
	if existing, err := core.ScanEmails(cfg.Vault); err == nil {
		existingByMsgID := make(map[string]string, len(existing))
		for _, e := range existing {
			if msgID := core.EmailMessageID(e); msgID != "" {
				existingByMsgID[msgID] = e.ThreadID
			}
		}
		for i := range allEmails {
			if allEmails[i].ThreadID != "" {
				continue
			}
			if inReplyTo := core.EmailInReplyTo(allEmails[i]); inReplyTo != "" {
				if tid := existingByMsgID[inReplyTo]; tid != "" {
					allEmails[i].ThreadID = tid
				}
			}
		}
	}
	allEmails = core.DeduplicateEmails(allEmails)
	allEmails = core.AssignThreadIDs(allEmails)
	fmt.Printf("fetched %d emails\n", len(allEmails))

	// collect notifications (received emails newer than 5 minutes ago)
	cutoff := time.Now().Add(-5 * time.Minute).UnixMilli()
	var notifications []SyncNotification
	for _, e := range allEmails {
		inboxKey := core.InboxKeyFromMailboxID(core.EmailMailboxID(e))
		fromAddr := core.EmailFromAddr(e)
		if strings.EqualFold(fromAddr, inboxKey) {
			continue // sent by self
		}
		if e.ReceivedAt.UnixMilli() < cutoff {
			continue
		}
		body := EmailBodyPreview(e, 80)
		notifications = append(notifications, SyncNotification{
			Contact:   fromAddr,
			Body:      body,
			Ts:        e.ReceivedAt.UnixMilli(),
			MessageID: core.EmailMessageID(e),
		})
	}

	// 5. write mailboxes.json
	if len(allMailboxes) > 0 {
		core.WriteMailboxes(cfg.Vault, allMailboxes) //nolint:errcheck
	}

	// 6. group, merge with existing, write
	totalUpdated := 0
	if len(allEmails) > 0 {
		byInbox := groupEmailsByInbox(allEmails)
		for inboxKey, emails := range byInbox {
			inboxDir := filepath.Join(cfg.Vault, inboxKey)
			threads := core.GroupByThread(emails)
			for _, t := range threads {
				threadEmails := emailsForThread(emails, t.ID)
				merged := mergeWithExistingThread(cfg.Vault, t.ID, threadEmails)
				if core.WriteThreadMD(cfg.Vault, inboxKey, merged) {
					totalUpdated++
				}
			}
			core.RenderMissingMDs(cfg.Vault, inboxKey)
			core.EnsureNewFile(cfg.Vault, inboxKey)
			writeSyncLog(cfg.Vault, inboxKey, emailsForInbox(emails, inboxKey))
			_ = inboxDir
		}
	}

	fmt.Printf("done — updated: %d\n", totalUpdated)
	return totalUpdated, notifications
}

// mergeWithExistingThread reads existing emails for the thread from vault and
// merges with newly fetched ones.
func mergeWithExistingThread(vaultDir, threadID string, incoming []core.Email) []core.Email {
	existing := core.ReadEmailsForThread(vaultDir, threadID)
	if len(existing) == 0 {
		return incoming
	}
	return core.MergeEmails(incoming, existing)
}

// groupEmailsByInbox separates emails by inbox key derived from MailboxIDs.
func groupEmailsByInbox(emails []core.Email) map[string][]core.Email {
	result := map[string][]core.Email{}
	for _, e := range emails {
		mbxID := core.EmailMailboxID(e)
		inboxKey := core.InboxKeyFromMailboxID(mbxID)
		if inboxKey == "" {
			inboxKey = core.EmailFromAddr(e)
		}
		result[inboxKey] = append(result[inboxKey], e)
	}
	return result
}

func emailsForThread(emails []core.Email, threadID string) []core.Email {
	var out []core.Email
	for _, e := range emails {
		if e.ThreadID == threadID {
			out = append(out, e)
		}
	}
	return out
}

func emailsForInbox(emails []core.Email, inboxKey string) []core.Email {
	mbxID := core.MakeMailboxID(inboxKey)
	var out []core.Email
	for _, e := range emails {
		if e.MailboxIDs[mbxID] {
			out = append(out, e)
		}
	}
	return out
}

// EmailBodyPreview returns a truncated body string for notifications.
func EmailBodyPreview(e core.Email, maxRunes int) string {
	body := core.EmailBody(e)
	r := []rune(body)
	if len(r) > maxRunes {
		return string(r[:maxRunes])
	}
	return body
}

// ── helpers ───────────────────────────────────────────────────────────────────

// ── sync log ──────────────────────────────────────────────────────────────────

func writeSyncLog(vaultDir, inboxKey string, emails []core.Email) {
	if len(emails) == 0 {
		return
	}
	var lines []string
	for _, e := range emails {
		ts := e.ReceivedAt.Local().Format("2006-01-02 15:04")
		from := core.EmailFromAddr(e)
		if name := core.EmailFromName(e); name != "" {
			from = name
		}
		var to string
		mbxID := core.MakeMailboxID(inboxKey)
		if e.MailboxIDs[mbxID] && !strings.EqualFold(core.EmailFromAddr(e), inboxKey) {
			to = inboxKey
		} else if len(e.To) > 0 {
			to = e.To[0].Email
		} else {
			to = "?"
		}
		lines = append(lines, fmt.Sprintf("%s %s → %s", ts, from, to))
	}
	writeBisetLog(vaultDir, inboxKey, lines)
}

// firstAddr returns the first address from a JSON array string.
func firstAddr(jsonArr string) string {
	if jsonArr == "" {
		return ""
	}
	var addrs []string
	if err := json.Unmarshal([]byte(jsonArr), &addrs); err == nil && len(addrs) > 0 {
		return addrs[0]
	}
	return jsonArr
}
