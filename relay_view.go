package main

import (
	"sort"

	"biset/vault"
	jmapserver "github.com/yno9/go-jmapserver"
)

// PersistMessages stores relay-supplied messages in biset's store, oldest-first
// so that resolveThreadID can find parents when ThreadID is empty.
// Returns the message list updated with whatever the store resolved (e.g. a
// newly assigned ThreadID).
func PersistMessages(messages []vault.Message, store *jmapserver.Store) []vault.Message {
	if len(messages) == 0 {
		return messages
	}
	ordered := make([]vault.Message, len(messages))
	copy(ordered, messages)
	sort.Slice(ordered, func(i, j int) bool {
		return vault.TimeVal(ordered[i].ReceivedAt).Before(vault.TimeVal(ordered[j].ReceivedAt))
	})
	byID := make(map[string]vault.Message, len(ordered))
	for _, m := range ordered {
		store.Put(m) //nolint:errcheck
		if resolved, ok := store.Get(m.ID); ok {
			m = resolved
		}
		byID[string(m.ID)] = m
	}
	for i := range messages {
		if resolved, ok := byID[string(messages[i].ID)]; ok {
			messages[i] = resolved
		}
	}
	return messages
}

// ConvertRelayView normalizes a batch of PGP-bearing email messages (jmapsmtp
// relay) into biset's authoritative view before persistence:
//  1. PGP decryption of bodies + extraction of inner Protected Headers
//     (sets In-Reply-To from the inner MIME if absent on the outer envelope).
//  2. ThreadID re-resolution: when In-Reply-To is set, the relay-supplied
//     ThreadID is discarded so the store's resolveThreadID walks biset's
//     own InReplyTo chain (which may produce a different — more accurate —
//     thread than the relay's outer-header-only view).
//
// Only call for the jmapsmtp relay; other relays (claude, rss, etc.) supply
// already-canonical messages and should go straight to PersistMessages.
func ConvertRelayView(messages []vault.Message, accountEmail string) {
	if len(messages) == 0 {
		return
	}
	DecryptMessageBodies(messages, accountEmail)
	for i := range messages {
		if len(messages[i].InReplyTo) > 0 && messages[i].InReplyTo[0] != "" {
			messages[i].ThreadID = ""
		}
	}
}
