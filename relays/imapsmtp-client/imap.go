package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	gomessage "github.com/emersion/go-message/mail"
	jmap "git.sr.ht/~rockorager/go-jmap"
	"biset/vault"
)

type IMAPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	TLSMode  string `json:"tls_mode"` // "tls" | "starttls" | "plain"
	Username string `json:"username"`
	Password string `json:"password"`
}

// FetchState tracks incremental IMAP fetch progress per account.
type FetchState struct {
	LastUID     string            `json:"last_uid"`
	SentLastUID string            `json:"sent_last_uid"`
	SentMailbox string            `json:"sent_mailbox"`
	EmailUIDs   map[string]uint32 `json:"email_uids,omitempty"` // msgID → IMAP UID
}

// ── fetch ─────────────────────────────────────────────────────────────────────

// FetchNew returns messages received since state and an updated FetchState.
func FetchNew(cfg IMAPConfig, inboxKey string, state FetchState) ([]vault.Message, FetchState, error) {
	c, err := imapDial(cfg)
	if err != nil {
		return nil, state, fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		return nil, state, fmt.Errorf("login: %w", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		return nil, state, fmt.Errorf("select: %w", err)
	}

	lastUID := uint32(0)
	fmt.Sscanf(state.LastUID, "%d", &lastUID)

	var criteria *imap.SearchCriteria
	if lastUID > 0 {
		criteria = &imap.SearchCriteria{UID: []imap.UIDSet{{imap.UIDRange{Start: imap.UID(lastUID + 1), Stop: 0}}}}
	} else {
		criteria = &imap.SearchCriteria{}
	}

	searchData, err := c.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return nil, state, fmt.Errorf("search: %w", err)
	}

	msgUIDs := state.EmailUIDs
	if msgUIDs == nil {
		msgUIDs = map[string]uint32{}
	}

	var messages []vault.Message
	var maxUID imap.UID
	if uids := searchData.AllUIDs(); len(uids) > 0 {
		messages, maxUID = fetchUIDs(c, uids, cfg.Username, inboxKey, msgUIDs)
	}
	if maxUID == 0 {
		maxUID = imap.UID(lastUID)
	}

	newState := FetchState{
		LastUID:     fmt.Sprintf("%d", maxUID),
		SentLastUID: state.SentLastUID,
		SentMailbox: state.SentMailbox,
		EmailUIDs:   msgUIDs,
	}
	sentMsgs, sentState := fetchSent(cfg, inboxKey, state, msgUIDs)
	messages = append(messages, sentMsgs...)
	newState.SentLastUID = sentState.SentLastUID
	newState.SentMailbox = sentState.SentMailbox

	return messages, newState, nil
}

func fetchUIDs(c *imapclient.Client, uids []imap.UID, selfAddr, inboxKey string, msgUIDs map[string]uint32) ([]vault.Message, imap.UID) {
	bodySection := &imap.FetchItemBodySection{Peek: true}
	fetchCmd := c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{
		UID:         true,
		Flags:       true,
		BodySection: []*imap.FetchItemBodySection{bodySection},
	})
	defer fetchCmd.Close()

	var messages []vault.Message
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
			m, err := parseRawMessage(bodyData, selfAddr, inboxKey, hasSeen)
			if err != nil || m == nil {
				continue
			}
			if uid > 0 {
				msgUIDs[string(m.ID)] = uint32(uid)
			}
			messages = append(messages, *m)
		}
	}
	return messages, maxUID
}

func fetchSent(cfg IMAPConfig, inboxKey string, state FetchState, msgUIDs map[string]uint32) ([]vault.Message, FetchState) {
	c, err := imapDial(cfg)
	if err != nil {
		return nil, state
	}
	defer c.Close()
	if err := c.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		return nil, state
	}

	sentMailbox := state.SentMailbox
	if sentMailbox == "" {
		sentMailbox = detectSentMailbox(c)
		if sentMailbox == "" {
			return nil, state
		}
	}
	if _, err := c.Select(sentMailbox, nil).Wait(); err != nil {
		return nil, state
	}

	sentLastUID := uint32(0)
	fmt.Sscanf(state.SentLastUID, "%d", &sentLastUID)

	var criteria *imap.SearchCriteria
	if sentLastUID > 0 {
		criteria = &imap.SearchCriteria{UID: []imap.UIDSet{{imap.UIDRange{Start: imap.UID(sentLastUID + 1), Stop: 0}}}}
	} else {
		criteria = &imap.SearchCriteria{}
	}

	searchData, err := c.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return nil, FetchState{SentMailbox: sentMailbox, SentLastUID: state.SentLastUID}
	}
	uids := searchData.AllUIDs()
	if len(uids) == 0 {
		return nil, FetchState{SentMailbox: sentMailbox, SentLastUID: state.SentLastUID}
	}

	bodySection := &imap.FetchItemBodySection{}
	fetchCmd := c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{bodySection},
	})
	defer fetchCmd.Close()

	var messages []vault.Message
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
			m, err := parseRawMessage(bodyData, cfg.Username, inboxKey, true)
			if err != nil || m == nil {
				continue
			}
			m.Keywords["$seen"] = true
			if uid > 0 {
				msgUIDs[string(m.ID)] = uint32(uid)
			}
			messages = append(messages, *m)
		}
	}
	return messages, FetchState{
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

// ── flag / expunge ────────────────────────────────────────────────────────────

// SetFlag marks a message \Seen on the IMAP server.
func SetFlag(cfg IMAPConfig, state FetchState, msgID string) error {
	uid, hasUID := state.EmailUIDs[msgID]
	headerID := vault.MessageIDFromMsgID(msgID)
	if hasUID && uid > 0 {
		return imapMarkSeenUID(cfg, imap.UID(uid))
	}
	if headerID != "" {
		return imapMarkSeen(cfg, headerID)
	}
	return fmt.Errorf("cannot determine UID for %q", msgID)
}

// Expunge deletes a message from the IMAP server.
func Expunge(cfg IMAPConfig, state FetchState, msgID string) error {
	uid, hasUID := state.EmailUIDs[msgID]
	headerID := vault.MessageIDFromMsgID(msgID)
	if hasUID && uid > 0 {
		return imapExpungeUID(cfg, imap.UID(uid))
	}
	if headerID != "" {
		return imapExpunge(cfg, headerID)
	}
	return fmt.Errorf("cannot determine UID for %q", msgID)
}

// AppendToSent appends raw RFC 5322 bytes to the IMAP Sent folder.
func AppendToSent(cfg IMAPConfig, raw []byte) {
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

// Watch runs IMAP IDLE and calls onChange on new messages. Loops on disconnect.
func Watch(ctx context.Context, cfg IMAPConfig, onChange func()) {
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
		Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagSeen}, Silent: true,
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
	return c.Store(imap.UIDSetNum(searchData.AllUIDs()...), &imap.StoreFlags{
		Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagSeen}, Silent: true,
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
	if err := c.Store(imap.UIDSetNum(uid), &imap.StoreFlags{
		Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}, Silent: true,
	}, nil).Close(); err != nil {
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
	searchData, err := c.UIDSearch(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: messageID}},
	}, nil).Wait()
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}
	uids := searchData.AllUIDs()
	if len(uids) == 0 {
		return nil
	}
	if err := c.Store(imap.UIDSetNum(uids...), &imap.StoreFlags{
		Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}, Silent: true,
	}, nil).Close(); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return c.Expunge().Close()
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

	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
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
	case <-triggered:
		idleCmd.Close() //nolint:errcheck
		<-done
		onChange()
	case err := <-done:
		return err
	}
	return nil
}

func imapDial(cfg IMAPConfig) (*imapclient.Client, error) {
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
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

// ── MIME / RFC 5322 parsing ───────────────────────────────────────────────────

func parseRawMessage(raw []byte, selfAddr, inboxKey string, seen bool) (*vault.Message, error) {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}

	subject := decodeHeader(msg.Header.Get("Subject"))
	messageID := normalizeID(msg.Header.Get("Message-Id"))
	parentID := normalizeID(msg.Header.Get("In-Reply-To"))
	fromAddr, fromName := parseAddress(msg.Header.Get("From"))
	receivedAt := time.UnixMilli(parseDate(msg.Header.Get("Date")))

	text, _ := extractText(raw)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = stripEmailQuote(text)
	if text == "" {
		return nil, nil
	}

	toAddrs := parseAddresses(msg.Header.Get("To"))
	ccAddrs := parseAddresses(msg.Header.Get("Cc"))

	mailboxID := vault.MakeMailboxID(inboxKey)
	msgID := jmap.ID(vault.MakeMessageID(messageID, inboxKey, receivedAt))

	keywords := map[string]bool{}
	if seen {
		keywords["$seen"] = true
	}

	var to, cc []*vault.Address
	for _, a := range toAddrs {
		to = append(to, &vault.Address{Email: a})
	}
	for _, a := range ccAddrs {
		cc = append(cc, &vault.Address{Email: a})
	}

	partID := "1"
	m := &vault.Message{
		ID:         msgID,
		BlobID:     jmap.ID("blob-" + string(msgID)),
		MailboxIDs: map[jmap.ID]bool{jmap.ID(mailboxID): true},
		Keywords:   keywords,
		From:       []*vault.Address{{Email: fromAddr, Name: fromName}},
		To:         to,
		CC:         cc,
		Subject:    subject,
		ReceivedAt: vault.TimePtr(receivedAt),
		BodyValues: map[string]*vault.BodyValue{partID: {Value: text}},
		TextBody: []*vault.BodyPart{{
			PartID:  partID,
			BlobID:  jmap.ID("blob-" + string(msgID) + "-body"),
			Type:    "text/plain",
			Charset: "utf-8",
			Size:    uint64(len(text)),
		}},
		HTMLBody: []*vault.BodyPart{},
		Preview:  previewText(text),
		Size:     uint64(len(text)),
	}
	if messageID != "" {
		m.MessageID = []string{messageID}
	}
	if parentID != "" {
		m.InReplyTo = []string{parentID}
		m.References = []string{parentID}
	}
	_ = selfAddr
	return m, nil
}

func previewText(s string) string {
	r := []rune(s)
	if len(r) > 256 {
		return string(r[:256])
	}
	return s
}

func decodeHeader(s string) string {
	dec := mime.WordDecoder{}
	if decoded, err := dec.DecodeHeader(s); err == nil {
		return decoded
	}
	return s
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
		ih, ok := p.Header.(*gomessage.InlineHeader)
		if !ok {
			continue
		}
		ct, _, _ := ih.ContentType()
		b, _ := io.ReadAll(p.Body)
		switch {
		case strings.HasPrefix(ct, "text/plain") && text == "":
			text = string(b)
		case strings.HasPrefix(ct, "text/html") && htmlText == "":
			htmlText = string(b)
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
