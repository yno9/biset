package core

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FlushOutgoing processes all MD files with status:send or !b body and sends them.
func FlushOutgoing(vaultDir string, mgr *Manager) int {
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
			if flushMDSend(filepath.Join(inboxDir, f.Name()), inboxKey, vaultDir, mgr) {
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
		if flushMDSend(filepath.Join(vaultDir, f.Name()), "", vaultDir, mgr) {
			count++
		}
	}
	return count
}

func flushMDSend(filePath, inboxKey, vaultDir string, mgr *Manager) bool {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	fm := ParseFrontmatter(string(content))
	isStatusSend := strings.TrimSpace(fm["status"]) == "send"
	body := ExtractBody(string(content))
	hasBangB := strings.Contains(body, "!b")
	if !isStatusSend && !hasBangB {
		return false
	}

	if hasBangB {
		body = strings.ReplaceAll(body, "!b", "")
		body = strings.TrimSpace(body)
	}

	// Derive inbox from mailboxId (new) or inbox (legacy).
	inbox := ""
	if mbxID := strings.TrimSpace(fm["mailboxId"]); mbxID != "" {
		inbox = InboxKeyFromMailboxID(mbxID)
	}
	if inbox == "" {
		inbox = strings.TrimSpace(fm["inbox"]) // legacy fallback
	}
	if inbox == "" {
		inbox = inboxKey
	}

	if body == "" {
		log.Printf("skip %s: no body", filepath.Base(filePath))
		return false
	}

	protocol := strings.TrimSpace(fm["protocol"])
	if protocol == "" {
		protocol = "smtp"
	}

	c := mgr.ConnectorFor(protocol)
	if c == nil {
		log.Printf("skip %s: no connector for protocol %q", filepath.Base(filePath), protocol)
		return false
	}

	contact := strings.TrimSpace(fm["contact"])
	subject := strings.Trim(fm["subject"], "\"")
	cc := strings.TrimSpace(fm["cc"])
	bcc := strings.TrimSpace(fm["bcc"])
	inReplyTo := ""

	if threadID := expandThreadID(fm["id"]); threadID != "" {
		if thread, err := ReadThread(vaultDir, threadID); err == nil && len(thread.EmailIDs) > 0 {
			latestEmailID := thread.EmailIDs[0]
			if orig, err := ReadEmail(vaultDir, latestEmailID); err == nil {
				if contact == "" {
					fromAddr := EmailFromAddr(orig)
					if strings.EqualFold(fromAddr, inbox) && len(orig.To) > 0 {
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
				if cc == "" && len(orig.Cc) > 0 {
					ccAddrs := make([]string, 0, len(orig.Cc))
					for _, a := range orig.Cc {
						if !strings.EqualFold(a.Email, inbox) {
							ccAddrs = append(ccAddrs, a.Email)
						}
					}
					cc = strings.Join(ccAddrs, ", ")
				}
				inReplyTo = resolveInReplyTo(vaultDir, latestEmailID)
				if inReplyTo == "" {
					inReplyTo = MessageIDFromEmailID(latestEmailID)
				}
			}
		}
	}

	if contact == "" {
		log.Printf("skip %s: no contact", filepath.Base(filePath))
		return false
	}

	fromAddr := Address{Email: inbox}
	toAddrs := parseAddressList(contact)
	ccAddrs := parseAddressList(cc)
	bccAddrs := parseAddressList(bcc)

	mailboxID := MakeMailboxID(inbox)
	emailID := MakeEmailID("", inbox, time.Now())
	// Prefer the thread ID from the MD frontmatter (existing thread).
	// MakeThreadID(inReplyTo) would produce a different ID than the original thread.
	threadID := expandThreadID(fm["id"])
	if threadID == "" {
		if inReplyTo != "" {
			threadID = MakeThreadID(inReplyTo)
		} else {
			threadID = MakeThreadID(emailID)
		}
	}

	partID := "1"
	email := Email{
		ID:         emailID,
		BlobID:     "blob-" + emailID,
		ThreadID:   threadID,
		MailboxIDs: map[string]bool{mailboxID: true},
		Keywords:   map[string]bool{"$seen": true},
		From:       []Address{fromAddr},
		To:         toAddrs,
		Cc:         ccAddrs,
		Bcc:        bccAddrs,
		Subject:    subject,
		ReceivedAt: time.Now(),
		BodyValues: map[string]BodyValue{partID: {Value: body}},
		TextBody:   []BodyPart{{PartID: partID, BlobID: "blob-" + emailID + "-body", Type: "text/plain", Charset: "utf-8", Size: len(body)}},
		HtmlBody:   []BodyPart{},
		Preview:    body,
		Size:       len(body),
	}
	if inReplyTo != "" {
		email.InReplyTo = []string{inReplyTo}
		email.References = []string{inReplyTo}
	}
	if len(email.MessageID) == 0 {
		email.MessageID = []string{emailID + "@biset"}
	}

	rcptTo := make([]EnvelopeAddress, 0, len(toAddrs)+len(ccAddrs)+len(bccAddrs))
	for _, a := range append(append(toAddrs, ccAddrs...), bccAddrs...) {
		rcptTo = append(rcptTo, EnvelopeAddress{Email: a.Email})
	}
	envelope := Envelope{
		MailFrom: EnvelopeAddress{Email: inbox},
		RcptTo:   rcptTo,
	}

	if err := c.Send(email, envelope); err != nil {
		log.Printf("send error %s: %v", filepath.Base(filePath), err)
		return false
	}

	WriteEmail(vaultDir, email) //nolint:errcheck

	if filepath.Base(filePath) == "_new.md" {
		os.WriteFile(filePath, []byte(NewFileTemplate), 0644) //nolint:errcheck
	} else {
		// Mark all thread emails as seen (sending implies you've read the thread).
		existing := ReadEmailsForThread(vaultDir, email.ThreadID)
		for _, e := range existing {
			if !EmailIsSeen(e) {
				if e.Keywords == nil {
					e.Keywords = map[string]bool{}
				}
				e.Keywords["$seen"] = true
				WriteEmail(vaultDir, e) //nolint:errcheck
			}
		}
		// Clear the file before WriteThreadMD so it doesn't re-inject the sent body.
		cleared := strings.Replace(ClearBody(string(content)), "status: send", "status: ", 1)
		os.WriteFile(filePath, []byte(cleared), 0644) //nolint:errcheck
		existing = ReadEmailsForThread(vaultDir, email.ThreadID)
		WriteThreadMD(vaultDir, inbox, existing)
	}

	fmt.Printf("sent: %s → %s\n", filepath.Base(filePath), contact)
	return true
}

func expandThreadID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "thr-") {
		return "thr-" + s
	}
	return s
}

func resolveInReplyTo(vaultDir, emailID string) string {
	e, err := ReadEmail(vaultDir, emailID)
	if err != nil {
		return ""
	}
	return EmailMessageID(e)
}

func parseAddressList(s string) []Address {
	if s == "" {
		return nil
	}
	var out []Address
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, Address{Email: part})
		}
	}
	return out
}

// FlushActions processes non-send status fields in MD files (seen, archived, deleted, etc).
func FlushActions(vaultDir string, mgr *Manager) int {
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
			fm := ParseFrontmatter(string(b))
			status := strings.TrimSpace(fm["status"])
			if status == "" || status == "send" {
				continue
			}

			protocol := strings.TrimSpace(fm["protocol"])
			if protocol == "" {
				protocol = "smtp"
			}
			c := mgr.ConnectorFor(protocol)

			threadID := expandThreadID(fm["id"])
			var emailIDs []string
			if threadID != "" {
				if thread, err := ReadThread(vaultDir, threadID); err == nil {
					emailIDs = thread.EmailIDs
				}
			}
			log.Printf("[FlushActions] file=%s status=%s connector=%v emails=%d threadID=%q", e.Name(), status, c != nil, len(emailIDs), threadID)
			if c != nil && len(emailIDs) > 0 {
				for _, eid := range emailIDs {
					if err := c.Handle(eid, status); err != nil {
						log.Printf("[FlushActions] handle error %s: %v", eid, err)
					}
				}
				log.Printf("[FlushActions] handle ok")
			}
			if status == "seen" {
				for _, eid := range emailIDs {
					if e, err := ReadEmail(vaultDir, eid); err == nil {
						if e.Keywords == nil {
							e.Keywords = map[string]bool{}
						}
						e.Keywords["$seen"] = true
						if _, werr := WriteEmail(vaultDir, e); werr != nil {
							log.Printf("[FlushActions] WriteEmail %s: %v", eid, werr)
						}
					} else {
						log.Printf("[FlushActions] ReadEmail %s: %v", eid, err)
					}
				}
				emails := ReadEmailsForThread(vaultDir, threadID)
				log.Printf("[FlushActions] seen: ReadEmailsForThread=%d", len(emails))
				written := WriteThreadMD(vaultDir, inboxKey, emails)
				log.Printf("[FlushActions] seen: WriteThreadMD written=%v", written)
				count++
				continue
			}
			os.Remove(filePath) //nolint:errcheck
			if threadID != "" {
				thread, err := ReadThread(vaultDir, threadID)
				if err == nil {
					for _, id := range thread.EmailIDs {
						DeleteEmail(vaultDir, id) //nolint:errcheck
					}
					DeleteThread(vaultDir, threadID) //nolint:errcheck
				}
			}
			fmt.Printf("%s: %s\n", status, e.Name())
			count++
		}
	}
	return count
}
