package core

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ── path helpers ──────────────────────────────────────────────────────────────

func EmailFilePath(vaultDir, emailID string) string {
	return filepath.Join(vaultDir, ".data", "emails", emailID+".json")
}

func ThreadFilePath(vaultDir, threadID string) string {
	return filepath.Join(vaultDir, ".data", "threads", threadID+".json")
}

func MailboxesFilePath(vaultDir string) string {
	return filepath.Join(vaultDir, ".data", "mailboxes.json")
}

// ── email ─────────────────────────────────────────────────────────────────────

func WriteEmail(vaultDir string, email Email) (bool, error) {
	path := EmailFilePath(vaultDir, email.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	b, err := json.MarshalIndent(email, "", "  ")
	if err != nil {
		return false, err
	}
	return WriteIfChanged(path, string(b)), nil
}

func ReadEmail(vaultDir, emailID string) (Email, error) {
	b, err := os.ReadFile(EmailFilePath(vaultDir, emailID))
	if err != nil {
		return Email{}, err
	}
	var e Email
	return e, json.Unmarshal(b, &e)
}

func DeleteEmail(vaultDir, emailID string) error {
	return os.Remove(EmailFilePath(vaultDir, emailID))
}

func ScanEmails(vaultDir string) ([]Email, error) {
	dir := filepath.Join(vaultDir, ".data", "emails")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Email
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var email Email
		if err := json.Unmarshal(b, &email); err != nil {
			continue
		}
		out = append(out, email)
	}
	return out, nil
}

// ── thread ────────────────────────────────────────────────────────────────────

func WriteThread(vaultDir string, thread Thread) (bool, error) {
	path := ThreadFilePath(vaultDir, thread.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	b, err := json.MarshalIndent(thread, "", "  ")
	if err != nil {
		return false, err
	}
	return WriteIfChanged(path, string(b)), nil
}

func ReadThread(vaultDir, threadID string) (Thread, error) {
	b, err := os.ReadFile(ThreadFilePath(vaultDir, threadID))
	if err != nil {
		return Thread{}, err
	}
	var t Thread
	return t, json.Unmarshal(b, &t)
}

func DeleteThread(vaultDir, threadID string) error {
	return os.Remove(ThreadFilePath(vaultDir, threadID))
}

func ScanThreads(vaultDir string) ([]Thread, error) {
	dir := filepath.Join(vaultDir, ".data", "threads")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Thread
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var t Thread
		if err := json.Unmarshal(b, &t); err != nil {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func ReadEmailsForThread(vaultDir, threadID string) []Email {
	thread, err := ReadThread(vaultDir, threadID)
	if err != nil {
		return nil
	}
	var out []Email
	for _, id := range thread.EmailIDs {
		e, err := ReadEmail(vaultDir, id)
		if err != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

// ── mailboxes ─────────────────────────────────────────────────────────────────

func WriteMailboxes(vaultDir string, mailboxes []Mailbox) error {
	path := MailboxesFilePath(vaultDir)
	os.MkdirAll(filepath.Dir(path), 0755) //nolint:errcheck
	b, err := json.MarshalIndent(mailboxes, "", "  ")
	if err != nil {
		return err
	}
	WriteIfChanged(path, string(b))
	return nil
}

func ReadMailboxes(vaultDir string) []Mailbox {
	b, err := os.ReadFile(MailboxesFilePath(vaultDir))
	if err != nil {
		return nil
	}
	var mailboxes []Mailbox
	json.Unmarshal(b, &mailboxes) //nolint:errcheck
	return mailboxes
}

// ── utility ───────────────────────────────────────────────────────────────────

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

func emailsInThread(emails []Email, threadID string) []Email {
	var out []Email
	for _, e := range emails {
		if e.ThreadID == threadID {
			out = append(out, e)
		}
	}
	return out
}

// ── migration ─────────────────────────────────────────────────────────────────

func MigrateVault(vaultDir string) {
	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		inboxKey := e.Name()
		dataDir := filepath.Join(vaultDir, inboxKey, ".data")
		files, err := os.ReadDir(dataDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			path := filepath.Join(dataDir, f.Name())
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			var vt struct {
				ID       string  `json:"id"`
				InboxKey string  `json:"inboxKey"`
				Emails   []Email `json:"emails"`
			}
			if json.Unmarshal(b, &vt) == nil && vt.ID != "" && len(vt.Emails) > 0 {
				key := vt.InboxKey
				if key == "" {
					key = inboxKey
				}
				mbxID := MakeMailboxID(key)
				for i := range vt.Emails {
					if vt.Emails[i].MailboxIDs == nil {
						vt.Emails[i].MailboxIDs = map[string]bool{mbxID: true}
					}
					WriteEmail(vaultDir, vt.Emails[i]) //nolint:errcheck
				}
				thread := Thread{ID: vt.ID}
				for _, em := range vt.Emails {
					thread.EmailIDs = append(thread.EmailIDs, em.ID)
				}
				WriteThread(vaultDir, thread) //nolint:errcheck
				os.Remove(path)               //nolint:errcheck
				log.Printf("[migrate] %s → %d emails", f.Name(), len(vt.Emails))
				continue
			}

			if emails, threadID, key := migrateOldFormat(b, inboxKey); len(emails) > 0 {
				mbxID := MakeMailboxID(key)
				for i := range emails {
					if emails[i].MailboxIDs == nil {
						emails[i].MailboxIDs = map[string]bool{mbxID: true}
					}
					WriteEmail(vaultDir, emails[i]) //nolint:errcheck
				}
				thread := Thread{ID: threadID}
				for _, em := range emails {
					thread.EmailIDs = append(thread.EmailIDs, em.ID)
				}
				WriteThread(vaultDir, thread) //nolint:errcheck
				os.Remove(path)               //nolint:errcheck
				log.Printf("[migrate] old %s → %d emails", f.Name(), len(emails))
			}
		}
	}
}

func migrateOldFormat(b []byte, inboxKey string) (emails []Email, threadID, key string) {
	var old struct {
		Inbox  string `json:"inbox"`
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
	if err := json.Unmarshal(b, &old); err != nil || old.Thread.ID == "" {
		return nil, "", ""
	}

	key = old.Inbox
	if key == "" {
		key = inboxKey
	}
	mbxID := MakeMailboxID(key)
	threadID = MakeThreadID(old.Thread.ID)

	for _, m := range old.Thread.Messages {
		ts, _ := time.Parse(time.RFC3339, m.Time)
		eID := MakeEmailID(m.MessageID, key, ts)

		keywords := map[string]bool{}
		if m.Seen {
			keywords["$seen"] = true
		}

		var to, cc []Address
		if m.Meta != nil {
			if raw := m.Meta["to_addrs"]; raw != "" {
				var addrs []string
				if json.Unmarshal([]byte(raw), &addrs) == nil {
					for _, a := range addrs {
						to = append(to, Address{Email: a})
					}
				}
			}
			if raw := m.Meta["cc_addrs"]; raw != "" {
				var addrs []string
				if json.Unmarshal([]byte(raw), &addrs) == nil {
					for _, a := range addrs {
						cc = append(cc, Address{Email: a})
					}
				}
			}
		}

		subj := ""
		if m.Meta != nil {
			subj = m.Meta["subject"]
		}

		body := m.Body
		e := Email{
			ID:         eID,
			BlobID:     "blob-" + eID,
			ThreadID:   threadID,
			MailboxIDs: map[string]bool{mbxID: true},
			Keywords:   keywords,
			From:       []Address{{Email: m.From, Name: m.FromName}},
			To:         to,
			Cc:         cc,
			Subject:    subj,
			ReceivedAt: ts,
			BodyValues: map[string]BodyValue{"1": {Value: body}},
			TextBody:   []BodyPart{{PartID: "1", BlobID: "blob-" + eID + "-body", Type: "text/plain", Charset: "utf-8", Size: len(body)}},
			HtmlBody:   []BodyPart{},
			Preview:    previewText(body),
			Size:       len(body),
		}
		if m.MessageID != "" {
			e.MessageID = []string{m.MessageID}
		}
		if m.ParentID != "" {
			e.InReplyTo = []string{m.ParentID}
			e.References = []string{m.ParentID}
		}
		emails = append(emails, e)
	}
	return emails, threadID, key
}

// ReThreadVault re-assigns threadIds across all stored emails by walking the
// full InReplyTo chain globally, then re-renders all affected MD files.
// Skips if already done (marker file exists).
func ReThreadVault(vaultDir string) {
	marker := filepath.Join(vaultDir, ".data", ".rethreaded")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	defer os.WriteFile(marker, []byte("1"), 0644) //nolint:errcheck
	emails, err := ScanEmails(vaultDir)
	log.Printf("[rethread] vault=%s emails=%d err=%v", vaultDir, len(emails), err)
	if err != nil || len(emails) == 0 {
		return
	}

	parentOf := make(map[string]string, len(emails))
	for _, e := range emails {
		msgID := EmailMessageID(e)
		if msgID == "" {
			continue
		}
		irt := EmailInReplyTo(e)
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

	changed := false
	for i := range emails {
		msgID := EmailMessageID(emails[i])
		parentID := EmailInReplyTo(emails[i])

		var root string
		if msgID != "" {
			root = rootOf(msgID)
		} else if parentID != "" {
			root = rootOf(parentID)
		}

		var newThreadID string
		if root != "" {
			newThreadID = MakeThreadID(root)
		} else {
			newThreadID = emails[i].ThreadID
		}

		if newThreadID != "" && newThreadID != emails[i].ThreadID {
			emails[i].ThreadID = newThreadID
			changed = true
		}
	}

	if changed {
		for _, e := range emails {
			WriteEmail(vaultDir, e) //nolint:errcheck
		}
	}

	threads := GroupByThread(emails)
	log.Printf("[ReThreadVault] rebuilding %d thread indexes", len(threads))
	for _, t := range threads {
		emailIDs := make([]string, len(t.EmailIDs))
		copy(emailIDs, t.EmailIDs)
		WriteThread(vaultDir, Thread{ID: t.ID, EmailIDs: emailIDs}) //nolint:errcheck
	}

	{
		validThreadIDs := make(map[string]bool, len(threads))
		for _, t := range threads {
			validThreadIDs[t.ID] = true
		}
		threadsDir := filepath.Join(vaultDir, ".data", "threads")
		if entries, err := os.ReadDir(threadsDir); err == nil {
			for _, f := range entries {
				if !strings.HasSuffix(f.Name(), ".json") {
					continue
				}
				tid := strings.TrimSuffix(f.Name(), ".json")
				if !validThreadIDs[tid] {
					log.Printf("[ReThreadVault] deleting stale thread index %s", f.Name())
					os.Remove(filepath.Join(threadsDir, f.Name())) //nolint:errcheck
				}
			}
		}
	}

	inboxes := map[string]bool{}
	for _, e := range emails {
		inboxes[InboxKeyFromMailboxID(EmailMailboxID(e))] = true
	}
	for inboxKey := range inboxes {
		if inboxKey == "" {
			continue
		}
		inboxDir := filepath.Join(vaultDir, inboxKey)
		if entries, err := os.ReadDir(inboxDir); err == nil {
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".md") {
					os.Remove(filepath.Join(inboxDir, entry.Name())) //nolint:errcheck
				}
			}
		}
		mbxID := MakeMailboxID(inboxKey)
		for _, t := range threads {
			threadEmails := emailsInThread(emails, t.ID)
			var inboxEmails []Email
			for _, e := range threadEmails {
				if e.MailboxIDs[mbxID] {
					inboxEmails = append(inboxEmails, e)
				}
			}
			if len(inboxEmails) == 0 {
				continue
			}
			mdPath, content := RenderMD(vaultDir, inboxKey, inboxEmails)
			if mdPath == "" {
				continue
			}
			os.MkdirAll(filepath.Dir(mdPath), 0755) //nolint:errcheck
			WriteIfChanged(mdPath, string(content))
			SetMDMtime(mdPath, inboxEmails)
		}
	}
}
