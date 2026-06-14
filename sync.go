package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	jmap "git.sr.ht/~rockorager/go-jmap"
	"biset/vault"
	jmapserver "github.com/yno9/go-jmapserver"
)

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

	vault.MigrateVault(cfg.Vault)

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
	var allInboxes []vault.Inbox
	var allIdentities []vault.Identity
	var allRemovedIDs []jmap.ID
	inboxSeen := map[string]bool{}
	respondedRelays := map[string][]string{}       // relayURL → inboxKeys
	inboxConfigs := map[string]vault.InboxConfig{} // inboxKey → InboxConfig
	notifEnabled := map[string]bool{}              // inboxKey → notification enabled
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
		for _, ib := range result.Inboxes {
			if !inboxSeen[string(ib.ID)] {
				inboxSeen[string(ib.ID)] = true
				allInboxes = append(allInboxes, ib)
			}
			key := vault.InboxKeyFromMailboxID(string(ib.ID))
			keys = append(keys, key)
			inboxConfigs[key] = c.InboxConfigFor(key, cfg)
			notifEnabled[key] = c.NotificationEnabled(key, cfg)
		}
		respondedRelays[c.Name()] = keys
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
		inboxKey := vault.InboxKeyFromMailboxID(vault.MessageMailboxID(m))
		fromAddr := vault.MessageFromAddr(m)
		if strings.EqualFold(fromAddr, inboxKey) {
			continue // sent by self
		}
		if vault.TimeVal(m.ReceivedAt).UnixMilli() < cutoff {
			continue
		}
		if !notifEnabled[inboxKey] {
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

	// 5. write inboxes
	validInboxKeys := map[string]bool{}
	if len(allInboxes) > 0 {
		store.PutMailboxes(allInboxes) //nolint:errcheck
		for _, ib := range allInboxes {
			key := vault.InboxKeyFromMailboxID(string(ib.ID))
			validInboxKeys[key] = true
			vault.EnsureNewFile(cfg.Vault, key, inboxConfigs[key])
		}
	}

	// 5b. remove messages deleted on relay (delta sync)
	for _, id := range allRemovedIDs {
		store.Delete(id)
		vault.DeleteMessage(cfg.Vault, id) //nolint:errcheck
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

		// write new messages to store and index by ID
		newByID := make(map[jmap.ID]vault.Message, len(allMessages))
		for _, m := range allMessages {
			store.Put(m) //nolint:errcheck
			newByID[m.ID] = m
		}

		byInbox := groupMessagesByInbox(allMessages)
		for inboxKey, msgs := range byInbox {
			threads := vault.GroupByThread(msgs)
			for _, t := range threads {
				var threadMsgs []vault.Message
				if rt, ok := relayThreadByID[t.ID]; ok && len(rt.EmailIDs) > 0 {
					// relay provided ordered email IDs — use them, filling from store when needed
					for _, eid := range rt.EmailIDs {
						if m, ok := newByID[eid]; ok {
							threadMsgs = append(threadMsgs, m)
						} else if cached, ok := store.Get(eid); ok {
							threadMsgs = append(threadMsgs, cached)
						}
					}
				} else {
					threadMsgs = messagesForThread(msgs, t.ID)
					// supplement with cached messages not in this fetch
					for _, cached := range store.AllForThread(t.ID) {
						if _, already := newByID[cached.ID]; !already {
							threadMsgs = append(threadMsgs, cached)
						}
					}
				}
				if vault.WriteThreadMD(cfg.Vault, inboxKey, threadMsgs, inboxConfigs[inboxKey]) {
					totalUpdated++
				}
			}
			vault.EnsureNewFile(cfg.Vault, inboxKey, inboxConfigs[inboxKey])
			writeSyncLog(cfg.Vault, inboxKey, messagesForInbox(msgs, inboxKey))
		}
	}

	// RenderMissingMDs for all known inboxes (catches sent-only threads not returned by relay).
	for key := range validInboxKeys {
		vault.RenderMissingMDs(cfg.Vault, key, inboxConfigs[key])
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
		c := mgr.RelayForAccount(s.InboxKey)
		if c == nil {
			log.Printf("[dispatch] no relay for inbox %q (submission %s)", s.InboxKey, s.ID)
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
		store.Put(s.Message) //nolint:errcheck
		existing := store.AllForThread(s.Message.ThreadID)
		if len(existing) == 0 {
			existing = []vault.Message{s.Message}
		}
		vault.WriteThreadMD(vaultDir, s.InboxKey, existing, mgr.InboxConfigFor(s.InboxKey, cfg))
		vault.DeleteSubmission(vaultDir, s.ID) //nolint:errcheck
		fmt.Printf("sent: %s → %v\n", s.ID, s.Envelope.RcptTo)
	}
}


func groupMessagesByInbox(messages []vault.Message) map[string][]vault.Message {
	result := map[string][]vault.Message{}
	for _, m := range messages {
		mbxID := vault.MessageMailboxID(m)
		inboxKey := vault.InboxKeyFromMailboxID(mbxID)
		if inboxKey == "" {
			inboxKey = vault.MessageFromAddr(m)
		}
		result[inboxKey] = append(result[inboxKey], m)
	}
	return result
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

func messagesForInbox(messages []vault.Message, inboxKey string) []vault.Message {
	mbxID := jmap.ID(vault.MakeMailboxID(inboxKey))
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

// ── sync log ──────────────────────────────────────────────────────────────────

func writeSyncLog(vaultDir, inboxKey string, messages []vault.Message) {
	if len(messages) == 0 {
		return
	}
	var lines []string
	mbxID := jmap.ID(vault.MakeMailboxID(inboxKey))
	for _, m := range messages {
		ts := vault.TimeVal(m.ReceivedAt).Local().Format("2006-01-02 15:04")
		from := vault.MessageFromAddr(m)
		if name := vault.MessageFromName(m); name != "" {
			from = name
		}
		var to string
		if m.MailboxIDs[mbxID] && !strings.EqualFold(vault.MessageFromAddr(m), inboxKey) {
			to = inboxKey
		} else if len(m.To) > 0 && m.To[0] != nil {
			to = m.To[0].Email
		} else {
			to = "?"
		}
		lines = append(lines, fmt.Sprintf("%s %s → %s", ts, from, to))
	}
	writeBisetLog(vaultDir, inboxKey, lines)
}

// firstAddr returns the first address from a JSON array string.
func firstAddr(jsonArr string) string {
	if jsonArr == "" {
		return ""
	}
	var addrs []string
	if err := json.Unmarshal([]byte(jsonArr), &addrs); err == nil && len(addrs) > 0 {
		return addrs[0]
	}
	return jsonArr
}

// ── watcher ───────────────────────────────────────────────────────────────────

// WatchVaultEvents returns two channels: action fires when a vault MD file has
// an actionable status change; quit fires when biset-quit.json is created.
func WatchVaultEvents(cfg *vault.Config, configPath string) (action <-chan struct{}, quit <-chan struct{}) {
	ach := make(chan struct{}, 1)
	qch := make(chan struct{})
	bisetDir := filepath.Dir(configPath)
	go watchVault(cfg.Vault, bisetDir, func() {
		select {
		case ach <- struct{}{}:
		default:
		}
	}, func() {
		close(qch)
	})
	return ach, qch
}

func StartWatcher(
	cfg *vault.Config,
	mgr *Manager,
	configPath string,
	interval time.Duration,
	onSync func(notify bool),
	onQuit func(),
) {
	go func() {
		for range mgr.Changed() {
			go onSync(true)
		}
	}()

	bisetDir := filepath.Dir(configPath)
	go watchVault(cfg.Vault, bisetDir, func() { go onSync(false) }, onQuit)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			go onSync(false)
		}
	}()

	go onSync(false)
}

func watchVault(vaultDir, bisetDir string, onAction func(), onQuit func()) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	defer watcher.Close()

	watcher.Add(vaultDir) //nolint:errcheck
	watcher.Add(bisetDir) //nolint:errcheck
	entries, _ := os.ReadDir(vaultDir)
	for _, d := range entries {
		if d.IsDir() {
			watcher.Add(filepath.Join(vaultDir, d.Name())) //nolint:errcheck
		}
	}

	debounce := time.NewTimer(0)
	<-debounce.C
	pending := false

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			base := filepath.Base(event.Name)
			if base == "biset-quit.json" && event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				os.Remove(event.Name) //nolint:errcheck
				if onQuit != nil {
					onQuit()
				}
				return
			}
			if !strings.HasSuffix(event.Name, ".md") {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			b, err := os.ReadFile(event.Name)
			if err != nil {
				continue
			}
			fm := vault.ParseFrontmatter(string(b))
			status := strings.TrimSpace(fm["status"])
			hasBangB := strings.Contains(vault.ExtractBody(string(b)), "!b")
			if status != "send" && status != "seen" && status != "follow" && !hasBangB {
				continue
			}
			if !pending {
				pending = true
				debounce.Reset(500 * time.Millisecond)
			}
		case <-debounce.C:
			if pending {
				pending = false
				onAction()
			}
		case <-watcher.Errors:
		}
	}
}
