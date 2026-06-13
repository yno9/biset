package vault

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
)

// ── path helpers ──────────────────────────────────────────────────────────────

func MessageFilePath(vaultDir string, id ID) string {
	return filepath.Join(vaultDir, ".data", "messages", string(id)+".json")
}

func ThreadFilePath(vaultDir string, threadID ID) string {
	return filepath.Join(vaultDir, ".data", "threads", string(threadID)+".json")
}

func MailboxesFilePath(vaultDir string) string {
	return filepath.Join(vaultDir, ".data", "mailboxes.json")
}

func SubmissionFilePath(vaultDir, id string) string {
	return filepath.Join(vaultDir, ".data", "submissions", id+".json")
}

// ── messages ──────────────────────────────────────────────────────────────────

func WriteMessage(vaultDir string, m Message) (bool, error) {
	path := MessageFilePath(vaultDir, m.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return false, err
	}
	return WriteIfChanged(path, string(b)), nil
}

func ReadMessage(vaultDir string, id ID) (Message, error) {
	b, err := os.ReadFile(MessageFilePath(vaultDir, id))
	if err != nil {
		return Message{}, err
	}
	var m Message
	return m, json.Unmarshal(b, &m)
}

func DeleteMessage(vaultDir string, id ID) error {
	return os.Remove(MessageFilePath(vaultDir, id))
}

func PurgeMessageCache(vaultDir string) {
	dir := filepath.Join(vaultDir, ".data", "messages")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			os.Remove(filepath.Join(dir, e.Name())) //nolint:errcheck
		}
	}
}

func ScanMessages(vaultDir string) ([]Message, error) {
	dir := filepath.Join(vaultDir, ".data", "messages")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
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
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		out = append(out, m)
	}
	return out, nil
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

// ── threads ───────────────────────────────────────────────────────────────────

func WriteThread(vaultDir string, t Thread) (bool, error) {
	path := ThreadFilePath(vaultDir, t.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return false, err
	}
	return WriteIfChanged(path, string(b)), nil
}

func ReadThread(vaultDir string, threadID ID) (Thread, error) {
	b, err := os.ReadFile(ThreadFilePath(vaultDir, threadID))
	if err != nil {
		return Thread{}, err
	}
	var t Thread
	return t, json.Unmarshal(b, &t)
}

func DeleteThread(vaultDir string, threadID ID) error {
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

func ReadMessagesForThread(vaultDir string, threadID ID) []Message {
	t, err := ReadThread(vaultDir, threadID)
	if err != nil {
		return nil
	}
	var out []Message
	for _, id := range t.EmailIDs {
		m, err := ReadMessage(vaultDir, id)
		if err != nil {
			continue
		}
		out = append(out, m)
	}
	return out
}

// ── mailboxes ─────────────────────────────────────────────────────────────────

func WriteInboxes(vaultDir string, inboxes []Inbox) error {
	path := MailboxesFilePath(vaultDir)
	os.MkdirAll(filepath.Dir(path), 0755) //nolint:errcheck
	b, err := json.MarshalIndent(inboxes, "", "  ")
	if err != nil {
		return err
	}
	WriteIfChanged(path, string(b))
	return nil
}

func ReadInboxes(vaultDir string) []Inbox {
	b, err := os.ReadFile(MailboxesFilePath(vaultDir))
	if err != nil {
		return nil
	}
	var inboxes []Inbox
	json.Unmarshal(b, &inboxes) //nolint:errcheck
	return inboxes
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

// ── query helpers ─────────────────────────────────────────────────────────────

func GetInboxes(vaultDir string) []Inbox {
	inboxes := ReadInboxes(vaultDir)
	if len(inboxes) == 0 {
		entries, _ := os.ReadDir(vaultDir)
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				inboxes = append(inboxes, DefaultInbox(e.Name()))
			}
		}
	}
	return inboxes
}

func QueryMessageIDs(vaultDir, mailboxID string, position, limit int) (ids []string, total int) {
	messages, _ := ScanMessages(vaultDir)
	type entry struct {
		id         string
		receivedAt time.Time
	}
	var list []entry
	for _, m := range messages {
		if mailboxID != "" && !m.MailboxIDs[jmap.ID(mailboxID)] {
			continue
		}
		list = append(list, entry{string(m.ID), TimeVal(m.ReceivedAt)})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].receivedAt.After(list[j].receivedAt)
	})
	total = len(list)
	if position >= total {
		return []string{}, total
	}
	end := position + limit
	if limit <= 0 || end > total {
		end = total
	}
	ids = make([]string, 0, end-position)
	for _, e := range list[position:end] {
		ids = append(ids, e.id)
	}
	return ids, total
}

func GetIdentities(vaultDir string) []Identity {
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

func FindThreadByMessageID(vaultDir, messageID string) string {
	messages, _ := ScanMessages(vaultDir)
	for _, m := range messages {
		for _, msgID := range m.MessageID {
			if msgID == messageID {
				return string(m.ThreadID)
			}
		}
	}
	return ""
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
				ID       string    `json:"id"`
				InboxKey string    `json:"inboxKey"`
				Messages []Message `json:"messages"`
			}
			if json.Unmarshal(b, &vt) == nil && vt.ID != "" && len(vt.Messages) > 0 {
				key := vt.InboxKey
				if key == "" {
					key = inboxKey
				}
				mbxID := jmap.ID(MakeMailboxID(key))
				for i := range vt.Messages {
					if vt.Messages[i].MailboxIDs == nil {
						vt.Messages[i].MailboxIDs = map[jmap.ID]bool{mbxID: true}
					}
					WriteMessage(vaultDir, vt.Messages[i]) //nolint:errcheck
				}
				t := Thread{ID: jmap.ID(vt.ID)}
				for _, m := range vt.Messages {
					t.EmailIDs = append(t.EmailIDs, m.ID)
				}
				WriteThread(vaultDir, t) //nolint:errcheck
				os.Remove(path)          //nolint:errcheck
				log.Printf("[migrate] %s → %d messages", f.Name(), len(vt.Messages))
				continue
			}

			if msgs, threadID, key := migrateOldFormat(b, inboxKey); len(msgs) > 0 {
				mbxID := jmap.ID(MakeMailboxID(key))
				for i := range msgs {
					if msgs[i].MailboxIDs == nil {
						msgs[i].MailboxIDs = map[jmap.ID]bool{mbxID: true}
					}
					WriteMessage(vaultDir, msgs[i]) //nolint:errcheck
				}
				t := Thread{ID: jmap.ID(threadID)}
				for _, m := range msgs {
					t.EmailIDs = append(t.EmailIDs, m.ID)
				}
				WriteThread(vaultDir, t) //nolint:errcheck
				os.Remove(path)          //nolint:errcheck
				log.Printf("[migrate] old %s → %d messages", f.Name(), len(msgs))
			}
		}
	}
}

func migrateOldFormat(b []byte, inboxKey string) (msgs []Message, threadID, key string) {
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
func ReThreadVault(vaultDir string) {
	marker := filepath.Join(vaultDir, ".data", ".rethreaded")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	defer os.WriteFile(marker, []byte("1"), 0644) //nolint:errcheck

	messages, err := ScanMessages(vaultDir)
	if err != nil || len(messages) == 0 {
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
			WriteMessage(vaultDir, m) //nolint:errcheck
		}
	}

	threads := GroupByThread(messages)
	log.Printf("[ReThreadVault] rebuilding %d thread indexes", len(threads))
	for _, t := range threads {
		ids := make([]jmap.ID, len(t.EmailIDs))
		copy(ids, t.EmailIDs)
		WriteThread(vaultDir, Thread{ID: t.ID, EmailIDs: ids}) //nolint:errcheck
	}

	{
		validThreadIDs := make(map[jmap.ID]bool, len(threads))
		for _, t := range threads {
			validThreadIDs[t.ID] = true
		}
		threadsDir := filepath.Join(vaultDir, ".data", "threads")
		if entries, err := os.ReadDir(threadsDir); err == nil {
			for _, f := range entries {
				if !strings.HasSuffix(f.Name(), ".json") {
					continue
				}
				tid := jmap.ID(strings.TrimSuffix(f.Name(), ".json"))
				if !validThreadIDs[tid] {
					log.Printf("[ReThreadVault] deleting stale thread index %s", f.Name())
					os.Remove(filepath.Join(threadsDir, f.Name())) //nolint:errcheck
				}
			}
		}
	}

	inboxes := map[string]bool{}
	for _, m := range messages {
		inboxes[InboxKeyFromMailboxID(MessageMailboxID(m))] = true
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
		mbxID := jmap.ID(MakeMailboxID(inboxKey))
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
			mdPath, content := RenderMD(vaultDir, inboxKey, inboxMsgs)
			if mdPath == "" {
				continue
			}
			os.MkdirAll(filepath.Dir(mdPath), 0755) //nolint:errcheck
			WriteIfChanged(mdPath, string(content))
			SetMDMtime(mdPath, inboxMsgs)
		}
	}
}
