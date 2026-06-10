package core

import "time"

// ── JMAP types (RFC 8621) ─────────────────────────────────────────────────────

type Email struct {
	ID         string          `json:"id"`
	BlobID     string          `json:"blobId"`
	ThreadID   string          `json:"threadId"`
	MailboxIDs map[string]bool `json:"mailboxIds"`
	Keywords   map[string]bool `json:"keywords"` // "$seen", "$draft", "$flagged"

	MessageID  []string `json:"messageId"`
	InReplyTo  []string `json:"inReplyTo"`
	References []string `json:"references"`

	From []Address `json:"from"`
	To   []Address `json:"to"`
	Cc   []Address `json:"cc"`
	Bcc  []Address `json:"bcc"`

	Subject    string    `json:"subject"`
	ReceivedAt time.Time `json:"receivedAt"`

	BodyValues map[string]BodyValue `json:"bodyValues"`
	TextBody   []BodyPart           `json:"textBody"`
	HtmlBody   []BodyPart           `json:"htmlBody"`

	Preview string `json:"preview"`
	Size    int    `json:"size"`
}

type Address struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type BodyValue struct {
	Value             string `json:"value"`
	IsEncodingProblem bool   `json:"isEncodingProblem"`
	IsTruncated       bool   `json:"isTruncated"`
}

type BodyPart struct {
	PartID  string `json:"partId"`
	BlobID  string `json:"blobId"`
	Type    string `json:"type"`
	Charset string `json:"charset,omitempty"`
	Size    int    `json:"size"`
}

type Mailbox struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	ParentID     *string       `json:"parentId"`
	Role         string        `json:"role,omitempty"`
	SortOrder    int           `json:"sortOrder"`
	TotalEmails  int           `json:"totalEmails"`
	UnreadEmails int           `json:"unreadEmails"`
	MyRights     MailboxRights `json:"myRights"`
	IsSubscribed bool          `json:"isSubscribed"`
}

type MailboxRights struct {
	MayReadItems   bool `json:"mayReadItems"`
	MayAddItems    bool `json:"mayAddItems"`
	MayRemoveItems bool `json:"mayRemoveItems"`
	MaySetSeen     bool `json:"maySetSeen"`
	MaySetKeywords bool `json:"maySetKeywords"`
	MayCreateChild bool `json:"mayCreateChild"`
	MayRename      bool `json:"mayRename"`
	MayDelete      bool `json:"mayDelete"`
	MaySubmit      bool `json:"maySubmit"`
}

type Thread struct {
	ID       string   `json:"id"`
	EmailIDs []string `json:"emailIds"`
}

type Identity struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	ReplyTo       []Address `json:"replyTo,omitempty"`
	Bcc           []Address `json:"bcc,omitempty"`
	TextSignature string    `json:"textSignature"`
	HTMLSignature string    `json:"htmlSignature"`
	MayDelete     bool      `json:"mayDelete"`
}

type Envelope struct {
	MailFrom EnvelopeAddress   `json:"mailFrom"`
	RcptTo   []EnvelopeAddress `json:"rcptTo"`
}

type EnvelopeAddress struct {
	Email string `json:"email"`
}

type EmailSubmission struct {
	ID         string    `json:"id"`
	EmailID    string    `json:"emailId"`
	ThreadID   string    `json:"threadId"`
	Envelope   *Envelope `json:"envelope"`
	SendAt     time.Time `json:"sendAt"`
	UndoStatus string    `json:"undoStatus"`
}
