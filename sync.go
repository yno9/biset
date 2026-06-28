package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"git.sr.ht/~rockorager/go-jmap/mail/mailbox"
	"biset/vault"
	jmapserver "github.com/yno9/go-jmapserver"
)

// mergeMailboxes returns the union of existing and incoming, with incoming
// entries overriding existing entries that share the same ID. Used by runSync
// so per-cycle Mailbox/get results from one relay don't erase mailboxes from
// other relays.
func mergeMailboxes(existing, incoming []mailbox.Mailbox) []mailbox.Mailbox {
	byID := make(map[jmap.ID]mailbox.Mailbox, len(existing)+len(incoming))
	for _, m := range existing {
		byID[m.ID] = m
	}
	for _, m := range incoming {
		byID[m.ID] = m
	}
	out := make([]mailbox.Mailbox, 0, len(byID))
	for _, m := range byID {
		out = append(out, m)
	}
	return out
}

func runSync(cfg *vault.Config, mgr *Manager, store *jmapserver.Store) (int, []vault.SyncNotification) {
	lockPath, ok := acquireSyncLock(cfg.Vault)
	if !ok {
		log.Printf("sync already running — skipping")
		return 0, nil
	}
	defer os.Remove(lockPath)

	if err := os.MkdirAll(cfg.Vault, 0755); err != nil {
		log.Printf("mkdir vault: %v", err)
		return 0, nil
	}

	// 1. flush outgoing → queue submissions
	FlushOutgoing(cfg.Vault, mgr, store)

	// 1b. dispatch queued submissions
	dispatchSubmissions(cfg, mgr, store)

	// 2. flush actions
	FlushActions(cfg, mgr, store)

	// 3. fetch from all connectors
	state := vault.LoadState(cfg.Vault)
	var allMessages []vault.Message
	var allThreads []vault.Thread
	var allInboxes []vault.Mailbox
	var allIdentities []vault.Identity
	var allRemovedIDs []jmap.ID
	inboxSeen := map[string]bool{}
	respondedRelays := map[string][]string{}       // relayURL → mailboxNames
	inboxConfigs := map[string]vault.MailboxConfig{} // mailboxName → MailboxConfig
	notifEnabled := map[string]bool{}              // mailboxName → notification enabled
	for _, c := range mgr.Relays() {
		if !c.Has("fetch") {
			continue
		}
		sinceQueryState := state.GetQueryState(c.Name(), string(c.AccountID()))
		sinceEmailState := state.GetEmailState(c.Name(), string(c.AccountID()))
		sinceMailboxState := state.GetMailboxState(c.Name(), string(c.AccountID()))
		result, err := c.Fetch(sinceQueryState, sinceEmailState, sinceMailboxState)
		if err != nil {
			log.Printf("[%s] fetch: %v", c.Name(), err)
			continue
		}
		// jmapsmtp messages carry PGP-encrypted bodies; decrypt and re-resolve
		// ThreadID via inner Protected Headers' InReplyTo before persisting.
		if c.RelayName() == "jmapsmtp" {
			ConvertRelayView(result.Messages, c.AccountEmail())
			ConvertRelayView(result.UpdatedMessages, c.AccountEmail())
		}
		// Persist relay-supplied messages into biset's store (all relays).
		result.Messages = PersistMessages(result.Messages, store)
		result.UpdatedMessages = PersistMessages(result.UpdatedMessages, store)
		allMessages = append(allMessages, result.Messages...)
		allThreads = append(allThreads, result.Threads...)
		allIdentities = append(allIdentities, result.Identities...)
		allRemovedIDs = append(allRemovedIDs, result.RemovedIDs...)
		if result.QueryState != "" {
			state.UpdateQueryState(c.Name(), string(c.AccountID()), result.QueryState)
		}
		if result.EmailState != "" {
			state.UpdateEmailState(c.Name(), string(c.AccountID()), result.EmailState)
		}
		if result.MailboxState != "" {
			state.UpdateMailboxState(c.Name(), string(c.AccountID()), result.MailboxState)
		}
		// apply keyword/flag updates from Email/changes
		for _, m := range result.UpdatedMessages {
			store.Put(m) //nolint:errcheck
		}
		var keys []string
		for _, ib := range result.Mailboxes {
			if !inboxSeen[string(ib.ID)] {
				inboxSeen[string(ib.ID)] = true
				allInboxes = append(allInboxes, ib)
			}
			key := vault.MailboxNameFromID(string(ib.ID))
			keys = append(keys, key)
			inboxConfigs[key] = c.MailboxConfigFor(key, cfg)
			notifEnabled[key] = c.NotificationEnabled(key, cfg)
		}
		// Delta sync may return empty Mailboxes when nothing changed.
		// Fall back to state's known keys so CleanupOrphanedInboxes
		// doesn't treat them as orphaned.
		if len(keys) == 0 {
			if rs := state.Relays[c.Name()]; rs != nil {
				keys = rs.MailboxNames
				for _, key := range keys {
					inboxConfigs[key] = c.MailboxConfigFor(key, cfg)
					notifEnabled[key] = c.NotificationEnabled(key, cfg)
				}
			}
		}
		respondedRelays[c.Name()] = keys
		for _, key := range keys {
			mgr.SetMailboxRelay(key, c)
		}
	}

	fmt.Printf("fetched %d messages, %d threads\n", len(allMessages), len(allThreads))

	// persist identities to vault cache (store handles message/thread data)
	if len(allIdentities) > 0 {
		vault.WriteIdentities(cfg.Vault, allIdentities) //nolint:errcheck
	}

	// collect notifications (received messages newer than 5 minutes ago)
	cutoff := time.Now().Add(-5 * time.Minute).UnixMilli()
	var notifications []vault.SyncNotification
	for _, m := range allMessages {
		mailboxName := vault.MailboxNameFromID(vault.MessageMailboxID(m))
		fromAddr := vault.MessageFromAddr(m)
		if strings.EqualFold(fromAddr, mailboxName) {
			continue // sent by self
		}
		if vault.TimeVal(m.ReceivedAt).UnixMilli() < cutoff {
			continue
		}
		if !notifEnabled[mailboxName] {
			continue
		}
		body := messageBodyPreview(m, 80)
		notifications = append(notifications, vault.SyncNotification{
			Contact:   fromAddr,
			Body:      body,
			Ts:        vault.TimeVal(m.ReceivedAt).UnixMilli(),
			MessageID: vault.MessageHeaderID(m),
		})
	}

	// 5. write inboxes — MERGE with existing rather than overwrite. Each sync
	// cycle only sees mailboxes from the relays that responded (delta fetches
	// often skip Mailbox/get entirely), so a plain replace would erase every
	// other relay's mailbox from biset's store. Mailboxes are scoped per
	// mailboxName, which is unique across relays.
	validInboxKeys := map[string]bool{}
	for _, ib := range allInboxes {
		validInboxKeys[vault.MailboxNameFromID(string(ib.ID))] = true
	}
	// Synthesize mailbox stubs for every mailboxName a relay reported this cycle,
	// even when its delta fetch returned no Mailbox/get list. Without this,
	// relays in delta mode silently drop out of the merged mailbox set.
	existing := store.Mailboxes()
	existingByID := map[jmap.ID]bool{}
	for _, m := range existing {
		existingByID[m.ID] = true
	}
	synthesized := make([]mailbox.Mailbox, 0)
	for _, keys := range respondedRelays {
		for _, key := range keys {
			mbID := jmap.ID(vault.MakeMailboxID(key))
			if existingByID[mbID] {
				continue
			}
			seen := false
			for _, ib := range allInboxes {
				if ib.ID == mbID {
					seen = true
					break
				}
			}
			if seen {
				continue
			}
			role := mailbox.Role("")
			if !strings.Contains(key, "/") {
				role = mailbox.RoleInbox
			}
			synthesized = append(synthesized, mailbox.Mailbox{
				ID:   mbID,
				Name: key,
				Role: role,
			})
		}
	}
	if len(allInboxes) > 0 || len(synthesized) > 0 {
		merged := mergeMailboxes(existing, append(allInboxes, synthesized...))
		store.PutMailboxes(merged) //nolint:errcheck
	}
	// Ensure _new.md exists for every inbox the relays acknowledged this cycle,
	// even when a delta fetch returned no Mailbox/get list. Prior code only
	// touched inboxes returned in this run, which let _new.md silently vanish
	// from inboxes between full fetches.
	for _, keys := range respondedRelays {
		for _, key := range keys {
			vault.EnsureNewFile(cfg.Vault, key, inboxConfigs[key])
		}
	}

	// 5b. remove messages deleted on relay (delta sync). store.Delete handles
	// both the in-memory index and the on-disk JSON file.
	for _, id := range allRemovedIDs {
		store.Delete(id)
	}

	// 5c. update state and clean up orphaned inboxes per relay scope
	vault.CleanupOrphanedInboxes(cfg.Vault, state, respondedRelays)
	for name, keys := range respondedRelays {
		state.UpdateRelay(name, keys)
	}
	vault.SaveState(cfg.Vault, state)

	// 6. write messages to store and render threads
	totalUpdated := 0
	if len(allMessages) > 0 {
		// index relay-provided threads by ID
		relayThreadByID := make(map[jmap.ID]vault.Thread, len(allThreads))
		for _, t := range allThreads {
			relayThreadByID[t.ID] = t
		}

		// ConvertRelayView already persisted to the store with resolved ThreadIDs;
		// allMessages already has biset's view. Build an ID lookup for the
		// thread-rendering loop below.
		newByID := make(map[jmap.ID]vault.Message, len(allMessages))
		for _, m := range allMessages {
			newByID[m.ID] = m
		}

		byInbox := groupMessagesByInbox(allMessages)
		for mailboxName, msgs := range byInbox {
			threads := vault.GroupByThread(msgs)
			mbxID := jmap.ID(vault.MakeMailboxID(mailboxName))
			for _, t := range threads {
				if t.ID == "" {
					continue // empty threadID collides across inboxes — skip
				}
				// Always use biset's own view of the thread (store.AllForThread).
			// The relay's Thread/get may return a different message set because
			// relays and biset can have divergent threading (biset re-resolves
			// via inner-header InReplyTo extracted from PGP-decrypted bodies).
			var threadMsgs []vault.Message
			threadMsgs = append(threadMsgs, messagesForThread(msgs, t.ID)...)
			for _, cached := range store.AllForThread(t.ID) {
				if _, already := newByID[cached.ID]; !already {
					threadMsgs = append(threadMsgs, cached)
				}
			}
			_ = relayThreadByID // intentionally unused; relay's view is informational only
				// Filter to this inbox's mailbox only (defensive: in case any message has multi-mailbox).
				threadMsgs = filterByMailbox(threadMsgs, mbxID)
				if len(threadMsgs) == 0 {
					continue
				}
				if vault.WriteThreadMD(cfg.Vault, mailboxName, threadMsgs, inboxConfigs[mailboxName]) {
					totalUpdated++
				}
			}
			vault.EnsureNewFile(cfg.Vault, mailboxName, inboxConfigs[mailboxName])
			writeSyncLog(cfg.Vault, mailboxName, messagesForInbox(msgs, mailboxName))
		}
	}

	// RenderMissingMDs for all known mailboxes (catches sent-only threads not
	// returned by relay). Threads come from the JMAP store, not vault file
	// scans — render no longer needs to know how messages are persisted.
	var allThreadViews []vault.ThreadView
	for _, t := range store.AllThreads() {
		allThreadViews = append(allThreadViews, vault.ThreadView{
			ID:       t.ID,
			Messages: store.AllForThread(t.ID),
		})
	}
	for key := range validInboxKeys {
		vault.RenderMissingMDs(cfg.Vault, key, inboxConfigs[key], allThreadViews)
	}

	fmt.Printf("done — updated: %d\n", totalUpdated)
	return totalUpdated, notifications
}

// dispatchSubmissions sends all queued PendingSubmissions and records results in store.
func dispatchSubmissions(cfg *vault.Config, mgr *Manager, store *jmapserver.Store) {
	vaultDir := cfg.Vault
	subs, err := vault.ScanSubmissions(vaultDir)
	if err != nil || len(subs) == 0 {
		return
	}
	for _, s := range subs {
		c := mgr.RelayForAccount(s.MailboxName)
		if c == nil {
			log.Printf("[dispatch] no relay for inbox %q (submission %s)", s.MailboxName, s.ID)
			continue
		}
		serverReceivedAt, err := c.Send(s.Message, s.Envelope)
		if err != nil {
			log.Printf("[dispatch] send error %s: %v", s.ID, err)
			continue
		}
		if !serverReceivedAt.IsZero() {
			s.Message.ReceivedAt = vault.TimePtr(serverReceivedAt)
		}
		// Run the sent message through the same view conversion as received
		// messages so it joins biset's authoritative thread (jmapsmtp only).
		if c.RelayName() == "jmapsmtp" {
			msgs := []vault.Message{s.Message}
			ConvertRelayView(msgs, c.AccountEmail())
			s.Message = msgs[0]
		}
		persisted := PersistMessages([]vault.Message{s.Message}, store)
		if len(persisted) > 0 {
			s.Message = persisted[0]
		}
		existing := store.AllForThread(s.Message.ThreadID)
		if len(existing) == 0 {
			existing = []vault.Message{s.Message}
		}
		vault.WriteThreadMD(vaultDir, s.MailboxName, existing, mgr.MailboxConfigFor(s.MailboxName, cfg))
		vault.DeleteSubmission(vaultDir, s.ID) //nolint:errcheck
		fmt.Printf("sent: %s → %v\n", s.ID, s.Envelope.RcptTo)
	}
}


func groupMessagesByInbox(messages []vault.Message) map[string][]vault.Message {
	result := map[string][]vault.Message{}
	for _, m := range messages {
		mbxID := vault.MessageMailboxID(m)
		mailboxName := vault.MailboxNameFromID(mbxID)
		if mailboxName == "" {
			mailboxName = vault.MessageFromAddr(m)
		}
		result[mailboxName] = append(result[mailboxName], m)
	}
	return result
}

func filterByMailbox(messages []vault.Message, mbxID jmap.ID) []vault.Message {
	out := make([]vault.Message, 0, len(messages))
	for _, m := range messages {
		if m.MailboxIDs[mbxID] {
			out = append(out, m)
		}
	}
	return out
}

func messagesForThread(messages []vault.Message, threadID jmap.ID) []vault.Message {
	var out []vault.Message
	for _, m := range messages {
		if m.ThreadID == threadID {
			out = append(out, m)
		}
	}
	return out
}

func messagesForInbox(messages []vault.Message, mailboxName string) []vault.Message {
	mbxID := jmap.ID(vault.MakeMailboxID(mailboxName))
	var out []vault.Message
	for _, m := range messages {
		if m.MailboxIDs[mbxID] {
			out = append(out, m)
		}
	}
	return out
}

func messageBodyPreview(m vault.Message, maxRunes int) string {
	body := vault.MessageBody(m)
	r := []rune(body)
	if len(r) > maxRunes {
		return string(r[:maxRunes])
	}
	return body
}

