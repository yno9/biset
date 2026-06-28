package main

import (
	"fmt"
	"log"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"git.sr.ht/~rockorager/go-jmap/mail/email"
	"git.sr.ht/~rockorager/go-jmap/mail/emailsubmission"
	"git.sr.ht/~rockorager/go-jmap/mail/mailbox"
	"biset/vault"
)

// Send creates a draft email on the relay and submits it for delivery.
func (r *Relay) Send(msg vault.Message, envelope vault.Envelope) (time.Time, error) {
	if err := r.ensureAuth(); err != nil {
		return time.Time{}, err
	}

	// Layer 2: encrypt+sign for single-recipient sends if peer key is available.
	if len(envelope.RcptTo) == 1 && r.accountEmail != "" {
		toEmail := envelope.RcptTo[0].Email
		body := messageBody(msg)
		if body != "" {
			enc := EncryptBodyForPeer(r, toEmail, body)
			if enc != body {
				replaceMessageBody(&msg, enc)
				log.Printf("[pgp] encrypted outgoing message to %s", toEmail)
			}
		}
	}

	createKey := jmap.ID("draft")
	setReq := &jmap.Request{}
	setReq.Invoke(&email.Set{
		Account: r.accountID,
		Create:  map[jmap.ID]*email.Email{createKey: &msg},
	})
	setResp, err := r.client.Do(setReq)
	if err != nil {
		return time.Time{}, fmt.Errorf("email/set: %w", err)
	}

	var serverEmailID jmap.ID
	var serverReceivedAt time.Time
	for _, inv := range setResp.Responses {
		if res, ok := inv.Args.(*email.SetResponse); ok {
			if obj, ok2 := res.Created[createKey]; ok2 && obj != nil {
				serverEmailID = obj.ID
				if obj.ReceivedAt != nil {
					serverReceivedAt = *obj.ReceivedAt
				}
			}
			if e, ok2 := res.NotCreated[createKey]; ok2 {
				return time.Time{}, fmt.Errorf("email/set create: %s", setErrMsg(e))
			}
		}
	}
	if serverEmailID == "" {
		return time.Time{}, fmt.Errorf("email/set: no created ID in response")
	}

	subReq := &jmap.Request{}
	subReq.Invoke(&emailsubmission.Set{
		Account: r.accountID,
		Create: map[jmap.ID]*emailsubmission.EmailSubmission{
			"sub": {
				EmailID:  serverEmailID,
				Envelope: &envelope,
			},
		},
	})
	subResp, err := r.client.Do(subReq)
	if err != nil {
		return time.Time{}, fmt.Errorf("submission/set: %w", err)
	}
	for _, inv := range subResp.Responses {
		if res, ok := inv.Args.(*emailsubmission.SetResponse); ok {
			if e, ok2 := res.NotCreated["sub"]; ok2 {
				return time.Time{}, fmt.Errorf("submission/set create: %s", setErrMsg(e))
			}
		}
	}
	return serverReceivedAt, nil
}

// Follow creates a Mailbox on the relay with the contact as its name,
// which the relay interprets as a subscription request (feed URL, AP handle, etc).
func (r *Relay) Follow(contact string) error {
	if err := r.ensureAuth(); err != nil {
		return err
	}
	req := &jmap.Request{}
	req.Invoke(&mailbox.Set{
		Account: r.accountID,
		Create: map[jmap.ID]*mailbox.Mailbox{
			"follow": {Name: contact},
		},
	})
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("follow: mailbox/set: %w", err)
	}
	for _, inv := range resp.Responses {
		if res, ok := inv.Args.(*mailbox.SetResponse); ok {
			if e, ok2 := res.NotCreated["follow"]; ok2 {
				return fmt.Errorf("follow: %s", setErrMsg(e))
			}
		}
	}
	return nil
}

// Handle performs the JMAP operation for seen/archived/deleted/spam actions.
//   - seen: Email/set update keywords/$seen
//   - deleted: Email/set destroy
//   - archived: Email/set update mailboxIds (move to role:archive mailbox)
//   - spam: Email/set update mailboxIds (move to role:junk mailbox)
func (r *Relay) Handle(msgID, action string) error {
	if err := r.ensureAuth(); err != nil {
		return err
	}

	switch action {
	case "seen":
		return r.emailSetUpdate(msgID, jmap.Patch{"keywords/$seen": true})
	case "deleted":
		return r.emailSetDestroy(msgID)
	case "archived":
		return r.emailMoveToRole(msgID, "archive")
	case "spam":
		return r.emailMoveToRole(msgID, "junk")
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
}

func (r *Relay) emailSetUpdate(msgID string, patch jmap.Patch) error {
	req := &jmap.Request{}
	req.Invoke(&email.Set{
		Account: r.accountID,
		Update:  map[jmap.ID]jmap.Patch{jmap.ID(msgID): patch},
	})
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("email/set update: %w", err)
	}
	for _, inv := range resp.Responses {
		if res, ok := inv.Args.(*email.SetResponse); ok {
			if e, ok2 := res.NotUpdated[jmap.ID(msgID)]; ok2 {
				return fmt.Errorf("email/set update: %s", setErrMsg(e))
			}
		}
	}
	return nil
}

func (r *Relay) emailSetDestroy(msgID string) error {
	req := &jmap.Request{}
	req.Invoke(&email.Set{
		Account: r.accountID,
		Destroy: []jmap.ID{jmap.ID(msgID)},
	})
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("email/set destroy: %w", err)
	}
	for _, inv := range resp.Responses {
		if res, ok := inv.Args.(*email.SetResponse); ok {
			for _, id := range res.NotDestroyed {
				return fmt.Errorf("email/set destroy: %s", setErrMsg(id))
			}
		}
	}
	return nil
}

func (r *Relay) emailMoveToRole(msgID, role string) error {
	targetID, srcID, err := r.resolveMailboxRole(msgID, role)
	if err != nil {
		return err
	}
	patch := jmap.Patch{"mailboxIds/" + string(targetID): true}
	if srcID != "" {
		patch["mailboxIds/"+string(srcID)] = nil
	}
	return r.emailSetUpdate(msgID, patch)
}

func (r *Relay) resolveMailboxRole(msgID, role string) (target, src jmap.ID, err error) {
	req := &jmap.Request{}
	req.Invoke(&mailbox.Get{Account: r.accountID})
	req.Invoke(&email.Get{
		Account: r.accountID,
		IDs:     []jmap.ID{jmap.ID(msgID)},
	})
	resp, err := r.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("resolveMailboxRole: %w", err)
	}
	var mbs []*mailbox.Mailbox
	var msgMailboxIDs map[jmap.ID]bool
	for _, inv := range resp.Responses {
		switch res := inv.Args.(type) {
		case *mailbox.GetResponse:
			mbs = res.List
		case *email.GetResponse:
			if len(res.List) > 0 && res.List[0] != nil {
				msgMailboxIDs = res.List[0].MailboxIDs
			}
		}
	}
	for _, mb := range mbs {
		if mb != nil && string(mb.Role) == role {
			target = mb.ID
		}
	}
	if target == "" {
		return "", "", fmt.Errorf("no mailbox with role %q on relay", role)
	}
	for id := range msgMailboxIDs {
		if id != target {
			src = id
			break
		}
	}
	return target, src, nil
}
