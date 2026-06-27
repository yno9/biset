package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"biset/vault"
	jmapserver "github.com/yno9/go-jmapserver"
)

// FlushOutgoing processes all MD files with status:send or !b body and sends them.
func FlushOutgoing(vaultDir string, mgr *Manager, store *jmapserver.Store) int {
	count := 0
	entries, _ := os.ReadDir(vaultDir)
	for _, d := range entries {
		if !d.IsDir() {
			continue
		}
		inboxKey := d.Name()
		inboxDir := filepath.Join(vaultDir, inboxKey)
		files, _ := os.ReadDir(inboxDir)
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".md") {
				continue
			}
			if flushMDSend(filepath.Join(inboxDir, f.Name()), inboxKey, vaultDir, mgr, store) {
				count++
			}
		}
	}
	// also scan vault root
	rootFiles, _ := os.ReadDir(vaultDir)
	for _, f := range rootFiles {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".md") {
			continue
		}
		if flushMDSend(filepath.Join(vaultDir, f.Name()), "", vaultDir, mgr, store) {
			count++
		}
	}
	return count
}

func flushMDSend(filePath, inboxKey, vaultDir string, mgr *Manager, store *jmapserver.Store) bool {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	fm := vault.ParseFrontmatter(string(content))
	isStatusSend := strings.TrimSpace(fm["status"]) == "send"
	body := vault.ExtractBody(string(content))
	hasBangB := strings.Contains(body, "!b")
	if !isStatusSend && !hasBangB {
		return false
	}

	if hasBangB {
		body = strings.ReplaceAll(body, "!b", "")
		body = strings.TrimSpace(body)
	}

	inbox := ""
	if mbxID := strings.TrimSpace(fm["mailboxId"]); mbxID != "" {
		inbox = vault.InboxKeyFromMailboxID(mbxID)
	}
	if inbox == "" {
		inbox = strings.TrimSpace(fm["inbox"])
	}
	if inbox == "" {
		inbox = inboxKey
	}

	if body == "" {
		log.Printf("skip %s: no body", filepath.Base(filePath))
		return false
	}

	c := mgr.RelayForAccount(inbox)
	if c == nil {
		log.Printf("skip %s: no relay for inbox %q", filepath.Base(filePath), inbox)
		return false
	}

	contact := strings.TrimSpace(fm["contact"])
	subject := strings.Trim(fm["subject"], "\"")
	cc := strings.TrimSpace(fm["cc"])
	bcc := strings.TrimSpace(fm["bcc"])
	inReplyTo := ""

	if threadID := expandThreadID(fm["id"]); threadID != "" {
		threadMsgs := store.AllForThread(jmap.ID(threadID))
		if len(threadMsgs) > 0 {
			orig := threadMsgs[len(threadMsgs)-1] // newest message (sorted ascending)
			{
				if contact == "" {
					fromAddr := vault.MessageFromAddr(orig)
					if strings.EqualFold(fromAddr, inbox) && len(orig.To) > 0 && orig.To[0] != nil {
						contact = orig.To[0].Email
					} else {
						contact = fromAddr
					}
				}
				if subject == "" {
					subject = orig.Subject
					if !strings.HasPrefix(strings.ToLower(subject), "re:") {
						subject = "Re: " + subject
					}
				}
				if cc == "" && len(orig.CC) > 0 {
					ccAddrs := make([]string, 0, len(orig.CC))
					for _, a := range orig.CC {
						if a != nil && !strings.EqualFold(a.Email, inbox) {
							ccAddrs = append(ccAddrs, a.Email)
						}
					}
					cc = strings.Join(ccAddrs, ", ")
				}
				inReplyTo = resolveInReplyTo(store, orig.ID)
				if inReplyTo == "" {
					inReplyTo = vault.MessageIDFromMsgID(string(orig.ID))
				}
			}
		}
	}

	if contact == "" {
		log.Printf("skip %s: no contact", filepath.Base(filePath))
		return false
	}

	fromAddr := &vault.Address{Email: inbox}
	toAddrs := parseAddressList(contact)
	ccAddrs := parseAddressList(cc)
	bccAddrs := parseAddressList(bcc)

	mailboxID := vault.MakeMailboxID(inbox)
	now := time.Now()
	msgID := jmap.ID(vault.MakeMessageID("", inbox, now))
	threadID := expandThreadID(fm["id"])
	if threadID == "" {
		if inReplyTo != "" {
			threadID = vault.MakeThreadID(inReplyTo)
		} else {
			threadID = vault.MakeThreadID(string(msgID))
		}
	}

	partID := "1"
	msg := vault.Message{
		ID:         msgID,
		BlobID:     jmap.ID("blob-" + string(msgID)),
		ThreadID:   jmap.ID(threadID),
		MailboxIDs: map[jmap.ID]bool{jmap.ID(mailboxID): true},
		Keywords:   map[string]bool{"$seen": true},
		From:       []*vault.Address{fromAddr},
		To:         toAddrs,
		CC:         ccAddrs,
		BCC:        bccAddrs,
		Subject:    subject,
		ReceivedAt: vault.TimePtr(now),
		BodyValues: map[string]*vault.BodyValue{partID: {Value: body}},
		TextBody: []*vault.BodyPart{{
			PartID:  partID,
			BlobID:  jmap.ID("blob-" + string(msgID) + "-body"),
			Type:    "text/plain",
			Charset: "utf-8",
			Size:    uint64(len(body)),
		}},
		HTMLBody: []*vault.BodyPart{},
		Preview:  body,
		Size:     uint64(len(body)),
	}
	if inReplyTo != "" {
		msg.InReplyTo = []string{inReplyTo}
		msg.References = []string{inReplyTo}
	}
	if len(msg.MessageID) == 0 {
		// RFC 5322-compliant Message-Id, independent of the internal JMAP id
		// (which contains "@" in localpart and isn't a valid id-left).
		msg.MessageID = []string{vault.NewRFCMessageID(inbox)}
	}

	rcptTo := make([]*vault.EnvelopeAddress, 0, len(toAddrs)+len(ccAddrs)+len(bccAddrs))
	for _, a := range append(append(toAddrs, ccAddrs...), bccAddrs...) {
		if a != nil {
			rcptTo = append(rcptTo, &vault.EnvelopeAddress{Email: a.Email})
		}
	}
	envelope := vault.Envelope{
		MailFrom: &vault.EnvelopeAddress{Email: inbox},
		RcptTo:   rcptTo,
	}

	sub := vault.PendingSubmission{
		ID:       string(msgID),
		Message:  msg,
		Envelope: envelope,
		InboxKey: inbox,
		Created:  now,
	}
	if err := vault.WriteSubmission(vaultDir, sub); err != nil {
		log.Printf("write submission %s: %v", filepath.Base(filePath), err)
		return false
	}

	if filepath.Base(filePath) == "_new.md" {
		os.WriteFile(filePath, []byte(vault.NewFileContent()), 0644) //nolint:errcheck
	} else {
		for _, m := range store.AllForThread(msg.ThreadID) {
			if !vault.MessageIsSeen(m) {
				if m.Keywords == nil {
					m.Keywords = map[string]bool{}
				}
				m.Keywords["$seen"] = true
				store.Put(m) //nolint:errcheck
			}
		}
		cleared := strings.Replace(vault.ClearBody(string(content)), "status: send", "status: ", 1)
		os.WriteFile(filePath, []byte(cleared), 0644) //nolint:errcheck
	}

	fmt.Printf("queued: %s → %s\n", filepath.Base(filePath), contact)
	return true
}

func expandThreadID(s string) string {
	return strings.TrimSpace(s)
}

func resolveInReplyTo(store *jmapserver.Store, msgID jmap.ID) string {
	m, ok := store.Get(msgID)
	if !ok {
		return ""
	}
	return vault.MessageHeaderID(m)
}

func parseAddressList(s string) []*vault.Address {
	if s == "" {
		return nil
	}
	var out []*vault.Address
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, &vault.Address{Email: part})
		}
	}
	return out
}

// FlushActions processes non-send status fields in MD files (seen, archived, deleted, etc).
func FlushActions(cfg *vault.Config, mgr *Manager, store *jmapserver.Store) int {
	vaultDir := cfg.Vault
	count := 0
	inboxDirs, _ := os.ReadDir(vaultDir)
	for _, d := range inboxDirs {
		if !d.IsDir() {
			continue
		}
		inboxKey := d.Name()
		dirPath := filepath.Join(vaultDir, inboxKey)
		entries, _ := os.ReadDir(dirPath)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			filePath := filepath.Join(dirPath, e.Name())
			b, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			fm := vault.ParseFrontmatter(string(b))
			status := strings.TrimSpace(fm["status"])
			if status == "" || status == "send" {
				continue
			}

			if status == "follow" {
				contact := strings.TrimSpace(fm["contact"])
				if contact == "" {
					log.Printf("[FlushActions] follow: no contact in %s", e.Name())
					continue
				}
				c := mgr.RelayForAccount(inboxKey)
				if c != nil {
					if err := c.Follow(contact); err != nil {
						log.Printf("[FlushActions] follow %s: %v", contact, err)
					}
				}
				cleared := strings.Replace(string(b), "status: follow", "status: ", 1)
				os.WriteFile(filePath, []byte(cleared), 0644) //nolint:errcheck
				count++
				continue
			}

			c := mgr.RelayForAccount(inboxKey)

			threadID := expandThreadID(fm["id"])
			var msgIDs []jmap.ID
			if threadID != "" {
				for _, m := range store.AllForThread(jmap.ID(threadID)) {
					msgIDs = append(msgIDs, m.ID)
				}
			}
			log.Printf("[FlushActions] file=%s status=%s connector=%v msgs=%d threadID=%q", e.Name(), status, c != nil, len(msgIDs), threadID)
			if c != nil && len(msgIDs) > 0 {
				for _, mid := range msgIDs {
					if err := c.Handle(string(mid), status); err != nil {
						log.Printf("[FlushActions] handle error %s: %v", mid, err)
					}
				}
				log.Printf("[FlushActions] handle ok")
			}
			if status == "seen" {
				for _, mid := range msgIDs {
					if m, ok := store.Get(mid); ok {
						if m.Keywords == nil {
							m.Keywords = map[string]bool{}
						}
						m.Keywords["$seen"] = true
						store.Put(m) //nolint:errcheck
					} else {
						log.Printf("[FlushActions] Get %s: not found", mid)
					}
				}
				msgs := store.AllForThread(jmap.ID(threadID))
				log.Printf("[FlushActions] seen: msgs=%d", len(msgs))
				written := vault.WriteThreadMD(vaultDir, inboxKey, msgs, mgr.InboxConfigFor(inboxKey, cfg))
				log.Printf("[FlushActions] seen: WriteThreadMD written=%v", written)
				count++
				continue
			}
			os.Remove(filePath) //nolint:errcheck
			if threadID != "" {
				for _, mid := range msgIDs {
					store.Delete(jmap.ID(mid))
					vault.DeleteMessage(vaultDir, jmap.ID(mid)) //nolint:errcheck
				}
			}
			fmt.Printf("%s: %s\n", status, e.Name())
			count++
		}
	}
	return count
}
