package vault

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
)

// ── path helpers ──────────────────────────────────────────────────────────────

func SubmissionFilePath(vaultDir, id string) string {
	return filepath.Join(vaultDir, ".data", "submissions", id+".json")
}

// ── submissions ───────────────────────────────────────────────────────────────

func WriteSubmission(vaultDir string, s PendingSubmission) error {
	path := SubmissionFilePath(vaultDir, s.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func ScanSubmissions(vaultDir string) ([]PendingSubmission, error) {
	dir := filepath.Join(vaultDir, ".data", "submissions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []PendingSubmission
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var s PendingSubmission
		if err := json.Unmarshal(b, &s); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func DeleteSubmission(vaultDir, id string) error {
	return os.Remove(SubmissionFilePath(vaultDir, id))
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

func messagesInThread(messages []Message, threadID string) []Message {
	var out []Message
	for _, m := range messages {
		if string(m.ThreadID) == threadID {
			out = append(out, m)
		}
	}
	return out
}

// ── identities ────────────────────────────────────────────────────────────────

func identitiesPath(vaultDir string) string {
	return filepath.Join(vaultDir, ".data", "identities.json")
}

func WriteIdentities(vaultDir string, ids []Identity) error {
	b, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Join(vaultDir, ".data"), 0755) //nolint:errcheck
	return os.WriteFile(identitiesPath(vaultDir), b, 0644)
}

func GetIdentities(vaultDir string) []Identity {
	if b, err := os.ReadFile(identitiesPath(vaultDir)); err == nil {
		var ids []Identity
		if json.Unmarshal(b, &ids) == nil && len(ids) > 0 {
			return ids
		}
	}
	// fallback: derive from inbox directories
	entries, _ := os.ReadDir(vaultDir)
	var list []Identity
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			list = append(list, Identity{
				ID:        jmap.ID("id-" + e.Name()),
				Name:      e.Name(),
				Email:     e.Name(),
				MayDelete: false,
			})
		}
	}
	return list
}

// ── migration ─────────────────────────────────────────────────────────────────
//
// Legacy-format helpers used only by MigrateVault / ReThreadVault. These
// keep their own minimal file I/O so the public vault API stays free of
// message/thread CRUD (which the JMAP Store now owns). Migration runs once
// at boot, before the Store is opened, so direct disk writes are safe —
// the Store loads the post-migration state on startup.

func migrateWriteMessage(vaultDir string, m Message) {
	path := filepath.Join(vaultDir, ".data", "messages", string(m.ID)+".json")
	os.MkdirAll(filepath.Dir(path), 0755) //nolint:errcheck
	if b, err := json.MarshalIndent(m, "", "  "); err == nil {
		os.WriteFile(path, b, 0644) //nolint:errcheck
	}
}

func migrateScanMessages(vaultDir string) []Message {
	dir := filepath.Join(vaultDir, ".data", "messages")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Message
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m Message
		if json.Unmarshal(b, &m) == nil {
			out = append(out, m)
		}
	}
	return out
}


func MigrateVault(vaultDir string) {
	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		mailboxName := e.Name()
		dataDir := filepath.Join(vaultDir, mailboxName, ".data")
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
				ID          string    `json:"id"`
				MailboxName string    `json:"mailbox_name"`
				Messages    []Message `json:"messages"`
			}
			if json.Unmarshal(b, &vt) == nil && vt.ID != "" && len(vt.Messages) > 0 {
				key := vt.MailboxName
				if key == "" {
					key = mailboxName
				}
				// Threads are derived by the Store from message ThreadIDs;
				// migration only persists messages.
				mbxID := jmap.ID(MakeMailboxID(key))
				for i := range vt.Messages {
					if vt.Messages[i].MailboxIDs == nil {
						vt.Messages[i].MailboxIDs = map[jmap.ID]bool{mbxID: true}
					}
					if vt.Messages[i].ThreadID == "" {
						vt.Messages[i].ThreadID = jmap.ID(vt.ID)
					}
					migrateWriteMessage(vaultDir, vt.Messages[i])
				}
				os.Remove(path) //nolint:errcheck
				log.Printf("[migrate] %s → %d messages", f.Name(), len(vt.Messages))
				continue
			}

			if msgs, threadID, key := migrateOldFormat(b, mailboxName); len(msgs) > 0 {
				mbxID := jmap.ID(MakeMailboxID(key))
				for i := range msgs {
					if msgs[i].MailboxIDs == nil {
						msgs[i].MailboxIDs = map[jmap.ID]bool{mbxID: true}
					}
					if msgs[i].ThreadID == "" {
						msgs[i].ThreadID = jmap.ID(threadID)
					}
					migrateWriteMessage(vaultDir, msgs[i])
				}
				os.Remove(path) //nolint:errcheck
				log.Printf("[migrate] old %s → %d messages", f.Name(), len(msgs))
			}
		}
	}
}

func migrateOldFormat(b []byte, mailboxName string) (msgs []Message, threadID, key string) {
	var old struct {
		Mailbox  string `json:"inbox"`
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

	key = old.Mailbox
	if key == "" {
		key = mailboxName
	}
	mbxID := jmap.ID(MakeMailboxID(key))
	threadID = MakeThreadID(old.Thread.ID)

	for _, raw := range old.Thread.Messages {
		ts, _ := time.Parse(time.RFC3339, raw.Time)
		id := jmap.ID(MakeMessageID(raw.MessageID, key, ts))

		keywords := map[string]bool{}
		if raw.Seen {
			keywords["$seen"] = true
		}

		var to, cc []*Address
		if raw.Meta != nil {
			if s := raw.Meta["to_addrs"]; s != "" {
				var addrs []string
				if json.Unmarshal([]byte(s), &addrs) == nil {
					for _, a := range addrs {
						to = append(to, &Address{Email: a})
					}
				}
			}
			if s := raw.Meta["cc_addrs"]; s != "" {
				var addrs []string
				if json.Unmarshal([]byte(s), &addrs) == nil {
					for _, a := range addrs {
						cc = append(cc, &Address{Email: a})
					}
				}
			}
		}

		subj := ""
		if raw.Meta != nil {
			subj = raw.Meta["subject"]
		}

		body := raw.Body
		m := Message{
			ID:         id,
			BlobID:     jmap.ID("blob-" + string(id)),
			ThreadID:   jmap.ID(threadID),
			MailboxIDs: map[jmap.ID]bool{mbxID: true},
			Keywords:   keywords,
			From:       []*Address{{Email: raw.From, Name: raw.FromName}},
			To:         to,
			CC:         cc,
			Subject:    subj,
			ReceivedAt: TimePtr(ts),
			BodyValues: map[string]*BodyValue{"1": {Value: body}},
			TextBody:   []*BodyPart{{PartID: "1", BlobID: jmap.ID("blob-" + string(id) + "-body"), Type: "text/plain", Charset: "utf-8", Size: uint64(len(body))}},
			HTMLBody:   []*BodyPart{},
			Preview:    previewText(body),
			Size:       uint64(len(body)),
		}
		if raw.MessageID != "" {
			m.MessageID = []string{raw.MessageID}
		}
		if raw.ParentID != "" {
			m.InReplyTo = []string{raw.ParentID}
			m.References = []string{raw.ParentID}
		}
		msgs = append(msgs, m)
	}
	return msgs, threadID, key
}

// ReThreadVault re-assigns threadIds across all stored messages.
func ReThreadVault(vaultDir string, inboxCfg func(string) MailboxConfig) {
	marker := filepath.Join(vaultDir, ".data", ".rethreaded")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	defer os.WriteFile(marker, []byte("1"), 0644) //nolint:errcheck

	messages := migrateScanMessages(vaultDir)
	if len(messages) == 0 {
		return
	}

	parentOf := make(map[string]string, len(messages))
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

	changed := false
	for i := range messages {
		msgID := MessageHeaderID(messages[i])
		parentID := MessageInReplyTo(messages[i])

		var root string
		if msgID != "" {
			root = rootOf(msgID)
		} else if parentID != "" {
			root = rootOf(parentID)
		}

		var newThreadID jmap.ID
		if root != "" {
			newThreadID = jmap.ID(MakeThreadID(root))
		} else {
			newThreadID = messages[i].ThreadID
		}

		if newThreadID != "" && newThreadID != messages[i].ThreadID {
			messages[i].ThreadID = newThreadID
			changed = true
		}
	}

	if changed {
		for _, m := range messages {
			migrateWriteMessage(vaultDir, m) //nolint:errcheck
		}
	}

	threads := GroupByThread(messages)
	log.Printf("[ReThreadVault] grouped into %d threads", len(threads))

	// Legacy thread index files are obsolete (Store derives threads from
	// message ThreadIDs). Remove the entire dir if present so it doesn't
	// confuse future readers.
	threadsDir := filepath.Join(vaultDir, ".data", "threads")
	if _, err := os.Stat(threadsDir); err == nil {
		os.RemoveAll(threadsDir) //nolint:errcheck
	}

	mailboxes := map[string]bool{}
	for _, m := range messages {
		mailboxes[MailboxNameFromID(MessageMailboxID(m))] = true
	}
	for mailboxName := range mailboxes {
		if mailboxName == "" {
			continue
		}
		inboxDir := filepath.Join(vaultDir, mailboxName)
		if entries, err := os.ReadDir(inboxDir); err == nil {
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".md") {
					os.Remove(filepath.Join(inboxDir, entry.Name())) //nolint:errcheck
				}
			}
		}
		mbxID := jmap.ID(MakeMailboxID(mailboxName))
		for _, t := range threads {
			threadMsgs := messagesInThread(messages, string(t.ID))
			var inboxMsgs []Message
			for _, m := range threadMsgs {
				if m.MailboxIDs[mbxID] {
					inboxMsgs = append(inboxMsgs, m)
				}
			}
			if len(inboxMsgs) == 0 {
				continue
			}
			mdPath, content := RenderMD(vaultDir, mailboxName, inboxMsgs, inboxCfg(mailboxName))
			if mdPath == "" {
				continue
			}
			os.MkdirAll(filepath.Dir(mdPath), 0755) //nolint:errcheck
			WriteIfChanged(mdPath, string(content))
			SetMDMtime(mdPath, inboxMsgs)
		}
	}
}
