package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	gomessage "github.com/emersion/go-message/mail"
	"github.com/yd7a/biset/core"
)

// IMAPConfig holds IMAP connection settings.
type IMAPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	TLSMode  string `json:"tls_mode"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// imapFetch retrieves new emails from INBOX and Sent.
func imapFetch(cfg IMAPConfig, inboxKey string, since AccountState) ([]core.Email, AccountState, error) {
	c, err := imapDial(cfg)
	if err != nil {
		return nil, since, fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		return nil, since, fmt.Errorf("login: %w", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		return nil, since, fmt.Errorf("select: %w", err)
	}

	lastUID := uint32(0)
	fmt.Sscanf(since.LastUID, "%d", &lastUID)

	var criteria *imap.SearchCriteria
	if lastUID > 0 {
		uidRange := imap.UIDRange{Start: imap.UID(lastUID + 1), Stop: 0}
		criteria = &imap.SearchCriteria{UID: []imap.UIDSet{{uidRange}}}
	} else {
		criteria = &imap.SearchCriteria{}
	}

	searchData, err := c.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return nil, since, fmt.Errorf("search: %w", err)
	}

	var emails []core.Email
	var maxUID imap.UID
	newUIDs := searchData.AllUIDs()
	emailUIDs := since.EmailUIDs
	if emailUIDs == nil {
		emailUIDs = map[string]uint32{}
	}
	if len(newUIDs) > 0 {
		emails, maxUID = fetchUIDs(c, newUIDs, cfg.Username, inboxKey, emailUIDs)
	}
	if maxUID == 0 {
		maxUID = imap.UID(lastUID)
	}

	newState := AccountState{
		LastUID:     fmt.Sprintf("%d", maxUID),
		SentLastUID: since.SentLastUID,
		SentMailbox: since.SentMailbox,
		EmailUIDs:   emailUIDs,
	}

	// fetch Sent
	sentEmails, sentState := fetchSent(cfg, inboxKey, since, emailUIDs)
	emails = append(emails, sentEmails...)
	newState.SentLastUID = sentState.SentLastUID
	newState.SentMailbox = sentState.SentMailbox

	return emails, newState, nil
}

func fetchUIDs(c *imapclient.Client, uids []imap.UID, selfAddr, inboxKey string, emailUIDs map[string]uint32) ([]core.Email, imap.UID) {
	bodySection := &imap.FetchItemBodySection{Peek: true}
	fetchCmd := c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{
		UID:         true,
		Flags:       true,
		BodySection: []*imap.FetchItemBodySection{bodySection},
	})
	defer fetchCmd.Close()

	var emails []core.Email
	var maxUID imap.UID

	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		var uid imap.UID
		var bodyData []byte
		hasSeen := false
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			switch v := item.(type) {
			case imapclient.FetchItemDataUID:
				uid = v.UID
			case imapclient.FetchItemDataBodySection:
				bodyData, _ = io.ReadAll(v.Literal)
			case imapclient.FetchItemDataFlags:
				for _, f := range v.Flags {
					if f == imap.FlagSeen {
						hasSeen = true
					}
				}
			}
		}
		if uid > maxUID {
			maxUID = uid
		}
		if len(bodyData) > 0 {
			e, err := parseRawMessage(bodyData, selfAddr, inboxKey, hasSeen)
			if err != nil || e == nil {
				continue
			}
			// track emailId → IMAP UID for handle operations
			if uid > 0 {
				emailUIDs[e.ID] = uint32(uid)
			}
			emails = append(emails, *e)
		}
	}
	return emails, maxUID
}

func fetchSent(cfg IMAPConfig, inboxKey string, since AccountState, emailUIDs map[string]uint32) ([]core.Email, AccountState) {
	c, err := imapDial(cfg)
	if err != nil {
		return nil, since
	}
	defer c.Close()
	if err := c.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		return nil, since
	}

	sentMailbox := since.SentMailbox
	if sentMailbox == "" {
		sentMailbox = detectSentMailbox(c)
		if sentMailbox == "" {
			return nil, since
		}
	}
	if _, err := c.Select(sentMailbox, nil).Wait(); err != nil {
		return nil, since
	}

	sentLastUID := uint32(0)
	fmt.Sscanf(since.SentLastUID, "%d", &sentLastUID)

	var criteria *imap.SearchCriteria
	if sentLastUID > 0 {
		uidRange := imap.UIDRange{Start: imap.UID(sentLastUID + 1), Stop: 0}
		criteria = &imap.SearchCriteria{UID: []imap.UIDSet{{uidRange}}}
	} else {
		criteria = &imap.SearchCriteria{}
	}

	searchData, err := c.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return nil, AccountState{SentMailbox: sentMailbox, SentLastUID: since.SentLastUID}
	}
	uids := searchData.AllUIDs()
	if len(uids) == 0 {
		return nil, AccountState{SentMailbox: sentMailbox, SentLastUID: since.SentLastUID}
	}

	bodySection := &imap.FetchItemBodySection{}
	fetchCmd := c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{bodySection},
	})
	defer fetchCmd.Close()

	var emails []core.Email
	var maxUID imap.UID

	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		var uid imap.UID
		var bodyData []byte
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			switch v := item.(type) {
			case imapclient.FetchItemDataUID:
				uid = v.UID
			case imapclient.FetchItemDataBodySection:
				bodyData, _ = io.ReadAll(v.Literal)
			}
		}
		if uid > maxUID {
			maxUID = uid
		}
		if len(bodyData) > 0 {
			e, err := parseRawMessage(bodyData, cfg.Username, inboxKey, true) // sent = always seen
			if err != nil || e == nil {
				continue
			}
			// sent: mark as seen, clear inbox role
			e.Keywords["$seen"] = true
			if uid > 0 {
				emailUIDs[e.ID] = uint32(uid)
			}
			emails = append(emails, *e)
		}
	}

	return emails, AccountState{
		SentMailbox: sentMailbox,
		SentLastUID: fmt.Sprintf("%d", maxUID),
	}
}

func detectSentMailbox(c *imapclient.Client) string {
	listCmd := c.List("", "*", &imap.ListOptions{ReturnSpecialUse: true})
	defer listCmd.Close()
	for {
		mb := listCmd.Next()
		if mb == nil {
			break
		}
		for _, attr := range mb.Attrs {
			if strings.EqualFold(string(attr), `\Sent`) {
				return mb.Mailbox
			}
		}
		lower := strings.ToLower(mb.Mailbox)
		if lower == "sent" || lower == "sent messages" || lower == "sent items" {
			return mb.Mailbox
		}
	}
	return ""
}

func imapHandle(cfg IMAPConfig, state AccountState, emailID, action string) error {
	uid, hasUID := state.EmailUIDs[emailID]
	msgID := core.MessageIDFromEmailID(emailID)

	switch action {
	case "seen":
		if hasUID && uid > 0 {
			return imapMarkSeenUID(cfg, imap.UID(uid))
		}
		if msgID != "" {
			return imapMarkSeen(cfg, msgID)
		}
		return fmt.Errorf("cannot determine message ID for %q", emailID)
	case "deleted", "archived", "spam":
		if hasUID && uid > 0 {
			return imapExpungeUID(cfg, imap.UID(uid))
		}
		if msgID != "" {
			return imapExpunge(cfg, msgID)
		}
		return fmt.Errorf("cannot determine message ID for %q", emailID)
	default:
		return nil
	}
}

func imapMarkSeenUID(cfg IMAPConfig, uid imap.UID) error {
	c, err := imapDial(cfg)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		return fmt.Errorf("select: %w", err)
	}
	return c.Store(imap.UIDSetNum(uid), &imap.StoreFlags{
		Op:     imap.StoreFlagsAdd,
		Flags:  []imap.Flag{imap.FlagSeen},
		Silent: true,
	}, nil).Close()
}

func imapMarkSeen(cfg IMAPConfig, msgID string) error {
	c, err := imapDial(cfg)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		return fmt.Errorf("select: %w", err)
	}
	searchData, err := c.Search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Message-Id", Value: msgID}},
	}, nil).Wait()
	if err != nil || len(searchData.AllUIDs()) == 0 {
		return fmt.Errorf("message not found: %s", msgID)
	}
	uids := searchData.AllUIDs()
	return c.Store(imap.UIDSetNum(uids...), &imap.StoreFlags{
		Op:     imap.StoreFlagsAdd,
		Flags:  []imap.Flag{imap.FlagSeen},
		Silent: true,
	}, nil).Close()
}

func imapExpungeUID(cfg IMAPConfig, uid imap.UID) error {
	c, err := imapDial(cfg)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		return fmt.Errorf("select: %w", err)
	}
	storeCmd := c.Store(imap.UIDSetNum(uid), &imap.StoreFlags{
		Op:     imap.StoreFlagsAdd,
		Flags:  []imap.Flag{imap.FlagDeleted},
		Silent: true,
	}, nil)
	if err := storeCmd.Close(); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return c.Expunge().Close()
}

func imapExpunge(cfg IMAPConfig, messageID string) error {
	c, err := imapDial(cfg)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		return fmt.Errorf("select: %w", err)
	}

	criteria := &imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: messageID}},
	}
	searchData, err := c.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}
	uids := searchData.AllUIDs()
	if len(uids) == 0 {
		return nil
	}

	storeCmd := c.Store(imap.UIDSetNum(uids...), &imap.StoreFlags{
		Op:     imap.StoreFlagsAdd,
		Flags:  []imap.Flag{imap.FlagDeleted},
		Silent: true,
	}, nil)
	if err := storeCmd.Close(); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return c.Expunge().Close()
}

func appendToSent(cfg IMAPConfig, raw []byte) {
	c, err := imapDial(cfg)
	if err != nil {
		return
	}
	defer c.Close()
	if err := c.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		return
	}
	appendCmd := c.Append("Sent", int64(len(raw)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
	})
	appendCmd.Write(raw) //nolint:errcheck
	appendCmd.Close()    //nolint:errcheck
	appendCmd.Wait()     //nolint:errcheck
}

func imapWatch(ctx context.Context, cfg IMAPConfig, onChange func()) {
	for {
		if ctx.Err() != nil {
			return
		}
		idleOnce(ctx, cfg, onChange) //nolint:errcheck
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func idleOnce(ctx context.Context, cfg IMAPConfig, onChange func()) error {
	triggered := make(chan struct{}, 1)
	knownCount := uint32(0)
	ready := false

	opts := &imapclient.Options{
		TLSConfig: &tls.Config{ServerName: cfg.Host},
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			Mailbox: func(data *imapclient.UnilateralDataMailbox) {
				if !ready || data.NumMessages == nil {
					return
				}
				if *data.NumMessages > knownCount {
					knownCount = *data.NumMessages
					select {
					case triggered <- struct{}{}:
					default:
					}
				}
			},
		},
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	var (
		c   *imapclient.Client
		err error
	)
	switch cfg.TLSMode {
	case "starttls":
		c, err = imapclient.DialStartTLS(addr, opts)
	case "plain":
		c, err = imapclient.DialInsecure(addr, opts)
	default:
		c, err = imapclient.DialTLS(addr, opts)
	}
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()

	if err := c.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		return fmt.Errorf("select: %w", err)
	}
	knownCount = selectData.NumMessages
	ready = true

	idleCmd, err := c.Idle()
	if err != nil {
		return fmt.Errorf("idle: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- idleCmd.Wait() }()

	select {
	case <-ctx.Done():
		idleCmd.Close() //nolint:errcheck
		<-done
		return nil
	case <-triggered:
		idleCmd.Close() //nolint:errcheck
		<-done
		onChange()
		return nil
	case err := <-done:
		return err
	}
}

// parseRawMessage converts a raw MIME email into a JMAP Email object.
func parseRawMessage(raw []byte, selfAddr, inboxKey string, seen bool) (*core.Email, error) {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}

	subject := decodeHeader(msg.Header.Get("Subject"))
	messageID := normalizeID(msg.Header.Get("Message-Id"))
	parentID := normalizeID(msg.Header.Get("In-Reply-To"))
	fromAddr, fromName := parseAddress(msg.Header.Get("From"))
	ts := parseDate(msg.Header.Get("Date"))
	receivedAt := time.UnixMilli(ts)

	text, _ := extractText(raw)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = stripEmailQuote(text)
	if text == "" {
		return nil, nil
	}

	toAddrs := parseAddresses(msg.Header.Get("To"))
	ccAddrs := parseAddresses(msg.Header.Get("Cc"))

	// Determine inbox key: emails TO selfAddr are received; from selfAddr are sent
	mailboxID := core.MakeMailboxID(inboxKey)
	emailID := core.MakeEmailID(messageID, inboxKey, receivedAt)

	keywords := map[string]bool{}
	if seen {
		keywords["$seen"] = true
	}

	var to, cc []core.Address
	for _, a := range toAddrs {
		to = append(to, core.Address{Email: a})
	}
	for _, a := range ccAddrs {
		cc = append(cc, core.Address{Email: a})
	}

	partID := "1"
	e := &core.Email{
		ID:         emailID,
		BlobID:     "blob-" + emailID,
		MailboxIDs: map[string]bool{mailboxID: true},
		Keywords:   keywords,
		From:       []core.Address{{Email: fromAddr, Name: fromName}},
		To:         to,
		Cc:         cc,
		Subject:    subject,
		ReceivedAt: receivedAt,
		BodyValues: map[string]core.BodyValue{partID: {Value: text}},
		TextBody:   []core.BodyPart{{PartID: partID, BlobID: "blob-" + emailID + "-body", Type: "text/plain", Charset: "utf-8", Size: len(text)}},
		HtmlBody:   []core.BodyPart{},
		Preview:    previewText(text),
		Size:       len(text),
	}
	if messageID != "" {
		e.MessageID = []string{messageID}
	}
	if parentID != "" {
		e.InReplyTo = []string{parentID}
		e.References = []string{parentID}
	}
	_ = selfAddr // used by caller for self-detection logic
	return e, nil
}

func previewText(s string) string {
	r := []rune(s)
	if len(r) > 256 {
		return string(r[:256])
	}
	return s
}

func imapDial(cfg IMAPConfig) (*imapclient.Client, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	opts := &imapclient.Options{TLSConfig: &tls.Config{ServerName: cfg.Host}}
	switch cfg.TLSMode {
	case "plain":
		return imapclient.DialInsecure(addr, nil)
	case "starttls":
		return imapclient.DialStartTLS(addr, opts)
	default:
		return imapclient.DialTLS(addr, opts)
	}
}

func decodeHeader(s string) string {
	dec := mime.WordDecoder{}
	decoded, err := dec.DecodeHeader(s)
	if err != nil {
		return s
	}
	return decoded
}

func normalizeID(s string) string {
	s = strings.Trim(s, " <>")
	if s == "" {
		return ""
	}
	return "<" + s + ">"
}

func parseAddress(s string) (addr, name string) {
	if a, err := mail.ParseAddress(s); err == nil {
		return a.Address, a.Name
	}
	return s, ""
}

func parseAddresses(s string) []string {
	addrs, err := mail.ParseAddressList(s)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Address)
	}
	return out
}

func parseDate(s string) int64 {
	if d, err := mail.ParseDate(s); err == nil {
		if d.After(time.Now()) {
			return time.Now().UnixMilli()
		}
		return d.UnixMilli()
	}
	return time.Now().UnixMilli()
}

func extractText(raw []byte) (text, htmlText string) {
	mr, err := gomessage.CreateReader(strings.NewReader(string(raw)))
	if err != nil {
		return "", ""
	}
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		if ih, ok := p.Header.(*gomessage.InlineHeader); ok {
			ct, _, _ := ih.ContentType()
			b, _ := io.ReadAll(p.Body)
			if strings.HasPrefix(ct, "text/plain") && text == "" {
				text = string(b)
			} else if strings.HasPrefix(ct, "text/html") && htmlText == "" {
				htmlText = string(b)
			}
		}
	}
	if text == "" && htmlText != "" {
		text = stripHTMLTags(htmlText)
	}
	return
}

var htmlTagRe = regexp.MustCompile(`<[^>]+>`)

func stripHTMLTags(s string) string {
	return strings.TrimSpace(htmlTagRe.ReplaceAllString(s, ""))
}

var quoteRe = regexp.MustCompile(`(?s)\n\n(On [A-Z].+?wrote:|Le [a-z].+?a écrit :|Am [A-Z].+?schrieb:|El [a-záéíóúñ].+?escribió:|\d{4}年\d{1,2}月\d{1,2}日.+?:).*`)

func stripEmailQuote(s string) string {
	return strings.TrimSpace(quoteRe.ReplaceAllString(s, ""))
}
