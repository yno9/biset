package main

import (
	"encoding/json"
	"fmt"
	"time"

	"biset/vault"

	jmap "git.sr.ht/~rockorager/go-jmap"
	jmapserver "github.com/yno9/go-jmapserver"
)

// jmapHandler implements jmapserver.Handler and jmapserver.BlobHandler.
// It serves the aggregated view of all relays' emails.
// Reads are fully delegated to go-jmapserver Store.
// Writes (create/update/destroy) are routed to the appropriate relay via mailboxIds.
type jmapHandler struct {
	accountID jmap.ID
	store     *jmapserver.Store
	mgr       *Manager
}

func (s *jmapHandler) Capabilities() []jmap.URI {
	return []jmap.URI{
		"urn:ietf:params:jmap:mail",
		"urn:ietf:params:jmap:submission",
	}
}

func (s *jmapHandler) Accounts() []jmapserver.Account {
	return []jmapserver.Account{{ID: s.accountID, Name: string(s.accountID)}}
}

func (s *jmapHandler) Handle(method string, args json.RawMessage) (any, error) {
	switch method {
	case "Email/set":
		return s.serveEmailSet(args)
	case "EmailSubmission/set":
		return s.serveEmailSubmissionSet(args)
	default:
		return s.store.Dispatch(s.accountID, method, args)
	}
}

// UploadBlob and DownloadBlob implement jmapserver.BlobHandler.
func (s *jmapHandler) UploadBlob(contentType string, data []byte) string {
	return s.store.UploadBlob(contentType, data)
}
func (s *jmapHandler) DownloadBlob(blobID string) ([]byte, bool) {
	return s.store.DownloadBlob(blobID)
}

// serveEmailSet handles Email/set.
// create: puts email in store as pending (for EmailSubmission/set to pick up).
// update/destroy: delegates to store, then propagates to relay via mailboxIds.
func (s *jmapHandler) serveEmailSet(args json.RawMessage) (any, error) {
	var req struct {
		Create  map[jmap.ID]json.RawMessage `json:"create"`
		Update  map[jmap.ID]json.RawMessage `json:"update"`
		Destroy []jmap.ID                   `json:"destroy"`
	}
	json.Unmarshal(args, &req) //nolint:errcheck

	oldState := s.store.State()
	created := map[jmap.ID]any{}
	notCreated := map[jmap.ID]any{}

	for createID, raw := range req.Create {
		var msg vault.Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			notCreated[createID] = errObj("invalidArguments", err.Error())
			continue
		}
		now := time.Now().UTC()
		msg.ReceivedAt = &now
		if msg.ID == "" {
			msg.ID = jmap.ID(fmt.Sprintf("msg-draft-%d", now.UnixMilli()))
		}
		s.store.PutPending(msg)
		created[createID] = map[string]any{"id": msg.ID, "receivedAt": now.Format(time.RFC3339Nano)}
	}

	// update and destroy: store handles state, relay propagation follows
	delegateArgs, _ := json.Marshal(map[string]any{
		"accountId": s.accountID,
		"update":    req.Update,
		"destroy":   req.Destroy,
	})
	delegateResp, err := s.store.HandleEmailSet(s.accountID, delegateArgs)
	if err != nil {
		return nil, err
	}

	// propagate keyword updates and destroys to the originating relay
	for msgID, patch := range req.Update {
		s.propagateUpdate(string(msgID), patch)
	}
	for _, msgID := range req.Destroy {
		s.propagateDestroy(string(msgID))
	}

	type setResp struct {
		Updated      map[jmap.ID]any `json:"updated"`
		NotUpdated   map[jmap.ID]any `json:"notUpdated"`
		Destroyed    []jmap.ID       `json:"destroyed"`
		NotDestroyed map[jmap.ID]any `json:"notDestroyed"`
	}
	b, _ := json.Marshal(delegateResp)
	var dr setResp
	json.Unmarshal(b, &dr) //nolint:errcheck

	return map[string]any{
		"accountId":    s.accountID,
		"oldState":     oldState,
		"newState":     s.store.State(),
		"created":      created,
		"updated":      dr.Updated,
		"destroyed":    orEmpty(dr.Destroyed),
		"notCreated":   notCreated,
		"notUpdated":   dr.NotUpdated,
		"notDestroyed": dr.NotDestroyed,
	}, nil
}

// serveEmailSubmissionSet routes the submission to the relay determined by mailboxIds.
func (s *jmapHandler) serveEmailSubmissionSet(args json.RawMessage) (any, error) {
	var req struct {
		Create map[jmap.ID]struct {
			EmailID  jmap.ID         `json:"emailId"`
			Envelope *vault.Envelope `json:"envelope"`
		} `json:"create"`
	}
	json.Unmarshal(args, &req) //nolint:errcheck

	created := map[jmap.ID]any{}
	notCreated := map[jmap.ID]any{}

	for key, sub := range req.Create {
		msg, ok := s.store.TakePending(sub.EmailID)
		if !ok {
			msg, ok = s.store.Get(sub.EmailID)
		}
		if !ok {
			notCreated[key] = errObj("notFound", fmt.Sprintf("email %q not found", sub.EmailID))
			continue
		}

		relay := s.relayForMailboxIDs(msg.MailboxIDs)
		if relay == nil {
			notCreated[key] = errObj("serverFail", "no relay for mailboxIds")
			continue
		}

		env := envelopeFrom(msg, sub.Envelope)
		sentAt, err := relay.Send(msg, env)
		if err != nil {
			notCreated[key] = errObj("serverFail", err.Error())
			continue
		}
		if sentAt.IsZero() {
			sentAt = time.Now().UTC()
		}
		created[key] = map[string]any{
			"id":         fmt.Sprintf("sub-%d", time.Now().UnixMilli()),
			"sendAt":     sentAt.Format(time.RFC3339),
			"undoStatus": "final",
		}
	}

	return map[string]any{
		"accountId":    s.accountID,
		"oldState":     "0",
		"newState":     "1",
		"created":      created,
		"notCreated":   notCreated,
		"updated":      map[jmap.ID]any{},
		"notUpdated":   map[jmap.ID]any{},
		"destroyed":    []string{},
		"notDestroyed": map[jmap.ID]any{},
	}, nil
}

// ── relay routing ─────────────────────────────────────────────────────────────

func (s *jmapHandler) relayForMailboxIDs(mailboxIDs map[jmap.ID]bool) *Relay {
	for mbxID := range mailboxIDs {
		inboxKey := vault.InboxKeyFromMailboxID(string(mbxID))
		if r := s.mgr.RelayForInboxKey(inboxKey); r != nil {
			return r
		}
	}
	return nil
}

func (s *jmapHandler) propagateUpdate(msgID string, patch json.RawMessage) {
	msg, ok := s.store.Get(jmap.ID(msgID))
	if !ok {
		return
	}
	relay := s.relayForMailboxIDs(msg.MailboxIDs)
	if relay == nil {
		return
	}
	var p map[string]any
	if json.Unmarshal(patch, &p) != nil {
		return
	}
	switch {
	case p["keywords/$seen"] == true:
		relay.Handle(msgID, "seen") //nolint:errcheck
	case p["keywords/$deleted"] == true:
		relay.Handle(msgID, "deleted") //nolint:errcheck
	case p["keywords/$biset_archived"] == true:
		relay.Handle(msgID, "archived") //nolint:errcheck
	case p["keywords/$spam"] == true:
		relay.Handle(msgID, "spam") //nolint:errcheck
	}
}

func (s *jmapHandler) propagateDestroy(msgID string) {
	msg, ok := s.store.Get(jmap.ID(msgID))
	if !ok {
		return
	}
	relay := s.relayForMailboxIDs(msg.MailboxIDs)
	if relay == nil {
		return
	}
	relay.Handle(msgID, "deleted") //nolint:errcheck
}

// ── helpers ───────────────────────────────────────────────────────────────────

func errObj(typ, desc string) map[string]string {
	return map[string]string{"type": typ, "description": desc}
}

func envelopeFrom(msg vault.Message, env *vault.Envelope) vault.Envelope {
	if env != nil {
		return *env
	}
	out := vault.Envelope{}
	for _, addr := range msg.To {
		if addr != nil {
			out.RcptTo = append(out.RcptTo, &vault.EnvelopeAddress{Email: addr.Email})
		}
	}
	for _, addr := range msg.CC {
		if addr != nil {
			out.RcptTo = append(out.RcptTo, &vault.EnvelopeAddress{Email: addr.Email})
		}
	}
	if len(msg.From) > 0 && msg.From[0] != nil {
		out.MailFrom = &vault.EnvelopeAddress{Email: msg.From[0].Email}
	}
	return out
}
