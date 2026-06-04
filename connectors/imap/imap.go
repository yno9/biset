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

// imapFetch retrieves new messages from INBOX and Sent.
func imapFetch(cfg IMAPConfig, inboxKey string, since AccountState) ([]core.Message, AccountState, error) {
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

	var messages []core.Message
	var maxUID imap.UID
	newUIDs := searchData.AllUIDs()
	if len(newUIDs) > 0 {
		messages, maxUID = fetchUIDs(c, newUIDs, cfg.Username, inboxKey)
	}
	if maxUID == 0 {
		maxUID = imap.UID(lastUID)
	}

	newState := AccountState{
		LastUID:     fmt.Sprintf("%d", maxUID),
		SentLastUID: since.SentLastUID,
		SentMailbox: since.SentMailbox,
	}

	// fetch Sent
	sentMsgs, sentState := fetchSent(cfg, inboxKey, since)
	messages = append(messages, sentMsgs...)
	newState.SentLastUID = sentState.SentLastUID
	newState.SentMailbox = sentState.SentMailbox

	return messages, newState, nil
}

func fetchUIDs(c *imapclient.Client, uids []imap.UID, selfAddr, inboxKey string) ([]core.Message, imap.UID) {
	bodySection := &imap.FetchItemBodySection{}
	fetchCmd := c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{
		UID:         true,
		Flags:       true,
		BodySection: []*imap.FetchItemBodySection{bodySection},
	})
	defer fetchCmd.Close()

	var messages []core.Message
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
			m, err := parseRawMessage(bodyData, selfAddr, inboxKey)
			if err != nil || m == nil {
				continue
			}
			m.Seen = hasSeen
			messages = append(messages, *m)
		}
	}
	return messages, maxUID
}

func fetchSent(cfg IMAPConfig, inboxKey string, since AccountState) ([]core.Message, AccountState) {
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

	var messages []core.Message
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
			m, err := parseRawMessage(bodyData, cfg.Username, inboxKey)
			if err != nil || m == nil {
				continue
			}
			delete(m.Meta, core.MetaMyRole)
			m.Seen = true // sent by self — always seen
			messages = append(messages, *m)
		}
	}

	return messages, AccountState{
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

func imapHandle(cfg IMAPConfig, messageID string, action core.Action) error {
	switch action {
	case core.ActionDelete, core.ActionArchive, core.ActionSpam:
		return imapExpunge(cfg, messageID)
	default:
		return nil
	}
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

func parseRawMessage(raw []byte, selfAddr, inboxKey string) (*core.Message, error) {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}

	subject := decodeHeader(msg.Header.Get("Subject"))
	messageID := normalizeID(msg.Header.Get("Message-Id"))
	parentID := normalizeID(msg.Header.Get("In-Reply-To"))
	fromAddr, fromName := parseAddress(msg.Header.Get("From"))
	ts := parseDate(msg.Header.Get("Date"))

	text, _ := extractText(raw)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = stripEmailQuote(text)
	if text == "" {
		return nil, nil
	}

	toAddrs := parseAddresses(msg.Header.Get("To"))
	ccAddrs := parseAddresses(msg.Header.Get("Cc"))
	myRole := resolveMyRole(selfAddr, toAddrs, ccAddrs, msg.Header.Get("To"))

	meta := map[string]string{"inbox_key": inboxKey}
	if fromName != "" {
		meta[core.MetaFromName] = fromName
	}
	if subject != "" {
		meta[core.MetaSubject] = subject
	}
	if myRole != "" {
		meta[core.MetaMyRole] = myRole
	}
	if len(toAddrs) > 0 {
		meta[core.MetaToAddrs] = joinJSON(toAddrs)
	}
	if len(ccAddrs) > 0 {
		meta[core.MetaCcAddrs] = joinJSON(ccAddrs)
	}

	return &core.Message{
		From:      fromAddr,
		Body:      text,
		Ts:        ts,
		MessageID: messageID,
		ParentID:  parentID,
		Meta:      meta,
	}, nil
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
	now := time.Now()
	if d, err := mail.ParseDate(s); err == nil {
		if d.Before(now.Add(5 * time.Minute)) {
			return d.UnixMilli()
		}
	}
	return now.UnixMilli()
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

func resolveMyRole(selfAddr string, toAddrs, ccAddrs []string, toHeader string) string {
	if strings.Contains(toHeader, "hidden-recipients") {
		return ""
	}
	self := strings.ToLower(selfAddr)
	for _, a := range toAddrs {
		if strings.EqualFold(a, self) {
			return "to"
		}
	}
	for _, a := range ccAddrs {
		if strings.EqualFold(a, self) {
			return "cc"
		}
	}
	return "bcc"
}

var htmlTagRe = regexp.MustCompile(`<[^>]+>`)

func stripHTMLTags(s string) string {
	return strings.TrimSpace(htmlTagRe.ReplaceAllString(s, ""))
}

var quoteRe = regexp.MustCompile(`(?s)\n\n(On [A-Z].+?wrote:|Le [a-z].+?a écrit :|Am [A-Z].+?schrieb:|El [a-záéíóúñ].+?escribió:|\d{4}年\d{1,2}月\d{1,2}日.+?:).*`)

func stripEmailQuote(s string) string {
	return strings.TrimSpace(quoteRe.ReplaceAllString(s, ""))
}

func joinJSON(ss []string) string {
	var b strings.Builder
	b.WriteString("[")
	for i, s := range ss {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"`)
		b.WriteString(strings.ReplaceAll(s, `"`, `\"`))
		b.WriteString(`"`)
	}
	b.WriteString("]")
	return b.String()
}
