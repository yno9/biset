package main

import (
	"fmt"
	"log"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"git.sr.ht/~rockorager/go-jmap/mail/email"
	"git.sr.ht/~rockorager/go-jmap/mail/identity"
	"git.sr.ht/~rockorager/go-jmap/mail/mailbox"
	"git.sr.ht/~rockorager/go-jmap/mail/thread"
	"biset/vault"
)

// Fetch retrieves messages and inboxes from the relay.
// If sinceQueryState is non-empty, attempts a delta fetch via Email/queryChanges + Email/changes.
// Falls back to full fetch on any error.
func (r *Relay) Fetch(sinceQueryState, sinceEmailState, sinceMailboxState string) (FetchResult, error) {
	if sinceQueryState != "" {
		result, err := r.fetchDelta(sinceQueryState, sinceEmailState, sinceMailboxState)
		if err == nil {
			return result, nil
		}
		log.Printf("[relay] %s: delta fetch failed (%v), falling back to full fetch", r.cfg.URL, err)
	}
	return r.fetchFull()
}

func (r *Relay) fetchFull() (FetchResult, error) {
	if err := r.ensureAuth(); err != nil {
		return FetchResult{}, err
	}

	req := &jmap.Request{}
	queryCallID := req.Invoke(&email.Query{
		Account: r.accountID,
		Sort:    []*email.SortComparator{{Property: "receivedAt", IsAscending: false}},
	})
	req.Invoke(&email.Get{
		Account: r.accountID,
		ReferenceIDs: &jmap.ResultReference{
			ResultOf: queryCallID,
			Name:     "Email/query",
			Path:     "/ids",
		},
		FetchAllBodyValues: true,
	})
	req.Invoke(&mailbox.Get{Account: r.accountID})
	req.Invoke(&identity.Get{Account: r.accountID})
	req.Invoke(&email.Changes{Account: r.accountID, SinceState: ""})

	resp, err := r.client.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("fetch: %w", err)
	}

	var result FetchResult
	for _, inv := range resp.Responses {
		switch res := inv.Args.(type) {
		case *email.QueryResponse:
			result.QueryState = res.QueryState
		case *email.GetResponse:
			for _, e := range res.List {
				if e != nil {
					result.Messages = append(result.Messages, *e)
				}
			}
		case *mailbox.GetResponse:
			result.MailboxState = res.State
			for _, mb := range res.List {
				if mb != nil {
					result.Mailboxes = append(result.Mailboxes, *mb)
				}
			}
		case *email.ChangesResponse:
			result.EmailState = res.NewState
		case *identity.GetResponse:
			for _, id := range res.List {
				if id != nil {
					result.Identities = append(result.Identities, *id)
				}
			}
		}
	}

	result.Threads, _ = r.fetchThreads(threadIDsFrom(result.Messages))
	return result, nil
}

func (r *Relay) fetchDelta(sinceQueryState, sinceEmailState, sinceMailboxState string) (FetchResult, error) {
	if err := r.ensureAuth(); err != nil {
		return FetchResult{}, err
	}

	// Step 1: queryChanges + Email/changes + Mailbox/changes (or get) in one request
	req := &jmap.Request{}
	req.Invoke(&email.QueryChanges{
		Account:         r.accountID,
		SinceQueryState: sinceQueryState,
	})
	if sinceEmailState != "" {
		req.Invoke(&email.Changes{
			Account:    r.accountID,
			SinceState: sinceEmailState,
		})
	}
	if sinceMailboxState != "" {
		req.Invoke(&mailbox.Changes{
			Account:    r.accountID,
			SinceState: sinceMailboxState,
		})
	} else {
		req.Invoke(&mailbox.Get{Account: r.accountID})
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("queryChanges: %w", err)
	}

	var qcResp *email.QueryChangesResponse
	var changesResp *email.ChangesResponse
	var result FetchResult
	for _, inv := range resp.Responses {
		switch res := inv.Args.(type) {
		case *email.QueryChangesResponse:
			qcResp = res
		case *email.ChangesResponse:
			changesResp = res
		case *mailbox.GetResponse:
			result.MailboxState = res.State
			for _, mb := range res.List {
				if mb != nil {
					result.Mailboxes = append(result.Mailboxes, *mb)
				}
			}
		case *mailbox.ChangesResponse:
			result.MailboxState = res.NewState
			// Mailbox/changes only returns IDs; if anything changed, fall back to full Mailbox/get
			if len(res.Created)+len(res.Updated)+len(res.Destroyed) > 0 {
				if mbResp, err := r.fetchMailboxes(); err == nil {
					result.Mailboxes = mbResp
				}
			}
		}
	}

	if qcResp == nil {
		return FetchResult{}, fmt.Errorf("no queryChanges response")
	}

	result.QueryState = qcResp.NewQueryState
	result.RemovedIDs = qcResp.Removed
	if changesResp != nil {
		result.EmailState = changesResp.NewState
	}

	// Step 2: fetch new messages + updated messages (keywords/flags)
	addedIDs := make([]jmap.ID, 0, len(qcResp.Added))
	for _, a := range qcResp.Added {
		addedIDs = append(addedIDs, a.ID)
	}

	var updatedIDs []jmap.ID
	if changesResp != nil {
		updatedIDs = changesResp.Updated
	}

	toFetch := deduplicateIDs(append(addedIDs, updatedIDs...))
	if len(toFetch) > 0 {
		getReq := &jmap.Request{}
		getReq.Invoke(&email.Get{
			Account:            r.accountID,
			IDs:                toFetch,
			FetchAllBodyValues: true,
		})
		getResp, err := r.client.Do(getReq)
		if err != nil {
			return FetchResult{}, fmt.Errorf("email/get: %w", err)
		}
		addedSet := make(map[jmap.ID]bool, len(addedIDs))
		for _, id := range addedIDs {
			addedSet[id] = true
		}
		for _, inv := range getResp.Responses {
			if res, ok := inv.Args.(*email.GetResponse); ok {
				for _, e := range res.List {
					if e == nil {
						continue
					}
					if addedSet[e.ID] {
						result.Messages = append(result.Messages, *e)
					} else {
						result.UpdatedMessages = append(result.UpdatedMessages, *e)
					}
				}
			}
		}
	}

	result.Threads, _ = r.fetchThreads(threadIDsFrom(result.Messages))
	return result, nil
}

func deduplicateIDs(ids []jmap.ID) []jmap.ID {
	seen := make(map[jmap.ID]bool, len(ids))
	out := ids[:0]
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func threadIDsFrom(msgs []vault.Message) []jmap.ID {
	seen := map[jmap.ID]bool{}
	var ids []jmap.ID
	for _, m := range msgs {
		if tid := m.ThreadID; tid != "" && !seen[tid] {
			seen[tid] = true
			ids = append(ids, tid)
		}
	}
	return ids
}

func (r *Relay) fetchMailboxes() ([]vault.Mailbox, error) {
	req := &jmap.Request{}
	req.Invoke(&mailbox.Get{Account: r.accountID})
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	var out []vault.Mailbox
	for _, inv := range resp.Responses {
		if res, ok := inv.Args.(*mailbox.GetResponse); ok {
			for _, mb := range res.List {
				if mb != nil {
					out = append(out, *mb)
				}
			}
		}
	}
	return out, nil
}

func (r *Relay) fetchThreads(ids []jmap.ID) ([]vault.Thread, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	req := &jmap.Request{}
	req.Invoke(&thread.Get{Account: r.accountID, IDs: ids})
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	var out []vault.Thread
	for _, inv := range resp.Responses {
		if res, ok := inv.Args.(*thread.GetResponse); ok {
			for _, t := range res.List {
				if t != nil {
					out = append(out, *t)
				}
			}
		}
	}
	return out, nil
}
