package main

import (
	"encoding/json"
	"fmt"
	"strings"
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
	vaultDir  string
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
	case "Identity/get":
		return s.serveIdentityGet()
	default:
		return s.store.Dispatch(s.accountID, method, args)
	}
}

// serveIdentityGet returns the aggregated Identity list synced from all
// relays (stored at <vault>/.data/identities.json by sync.go). Without this,
// the gateway would fall back to go-jmapserver's defaultIdentity, which only
// exposes one synthetic identity named after the accountID — losing per-
// mailbox sender names (e.g. claude relay's per-project user_name).
func (s *jmapHandler) serveIdentityGet() (any, error) {
	ids := vault.GetIdentities(s.vaultDir)
	list := make([]any, 0, len(ids))
	for _, id := range ids {
		list = append(list, id)
	}
	return map[string]any{
		"accountId": s.accountID,
		"state":     "0",
		"list":      list,
		"notFound":  []jmap.ID{},
	}, nil
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

		// biset core acts as the MUA: it generates the RFC 5322 Message-Id
		// here so the relay's SMTP layer doesn't have to invent one. The
		// recipient sees this Message-Id; their reply's In-Reply-To then
		// resolves to the persisted copy below, giving deterministic
		// threading even before the IMAP Sent-folder fetch round-trips.
		mailboxName := mailboxNameFromMailboxIDs(msg.MailboxIDs)
		if len(msg.MessageID) == 0 || msg.MessageID[0] == "" {
			msg.MessageID = []string{vault.NewRFCMessageID(mailboxName)}
		}
		// Use the Message-Id as the JMAP store key so an IMAP-Sent-folder
		// re-fetch of the same RFC 5322 message overwrites this row instead
		// of creating a duplicate. (vault.MakeMessageID does the conversion.)
		msg.ID = jmap.ID(vault.MakeMessageID(msg.MessageID[0], mailboxName, now))

		// Persist immediately (not PutPending) so the outgoing message is
		// part of the store before its first reply can arrive. Store.Put
		// resolves ThreadID from InReplyTo when not set.
		if err := s.store.Put(msg); err != nil {
			notCreated[createID] = errObj("serverFail", err.Error())
			continue
		}
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
		msg, ok := s.store.Get(sub.EmailID)
		if !ok {
			// Legacy path: drafts created before the Message-Id rewrite are
			// still in PutPending; drain them so existing in-flight sends
			// don't fail across the upgrade.
			msg, ok = s.store.TakePending(sub.EmailID)
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
		// Deep-copy before relay.Send so its in-flight PGP encryption can't
		// mutate the store's in-memory BodyValues map (Go map reference
		// semantics meant the encrypted ciphertext leaked back into the
		// persisted draft, surfacing as "encrypted message" in biset-ui).
		sendMsg := cloneMessage(msg)
		sentAt, err := relay.Send(sendMsg, env)
		if err != nil {
			notCreated[key] = errObj("serverFail", err.Error())
			continue
		}
		// If Relay.Send encrypted the body (peer pubkey was available),
		// record that on the persisted draft so biset-ui shows the lock icon.
		if strings.Contains(vault.MessageBody(sendMsg), "-----BEGIN PGP MESSAGE-----") {
			if msg.Keywords == nil {
				msg.Keywords = map[string]bool{}
			}
			msg.Keywords["$e2e"] = true
			s.store.Put(msg) //nolint:errcheck
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
		mailboxName := vault.MailboxNameFromID(string(mbxID))
		if r := s.mgr.RelayForMailbox(mailboxName); r != nil {
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

// cloneMessage returns a deep copy of m sufficient to isolate downstream
// mutations to map/slice fields that we share with the in-memory store.
func cloneMessage(m vault.Message) vault.Message {
	b, err := json.Marshal(m)
	if err != nil {
		return m
	}
	var out vault.Message
	if err := json.Unmarshal(b, &out); err != nil {
		return m
	}
	return out
}

// mailboxNameFromMailboxIDs picks one mailboxName from a draft's mailboxIds. Used
// at draft-create time to seed RFC Message-Id with the right id-right host
// ("non.md" for test@non.md, "localhost" for non-email mailboxNames).
func mailboxNameFromMailboxIDs(mailboxIDs map[jmap.ID]bool) string {
	for mbxID := range mailboxIDs {
		if k := vault.MailboxNameFromID(string(mbxID)); k != "" {
			return k
		}
	}
	return ""
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
