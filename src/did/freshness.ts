// Rollback/stale-record defense (DID.md freshness rule): remember the highest
// seq seen per DID and reject anything lower. A gateway can serve an old but
// validly-signed record; without this a downgrade would silently succeed.
//
// The store is INJECTED rather than being `localStorage` directly, because this
// file is the only thing that kept `resolver.ts` — and therefore the whole
// did:dht wire layer — browser-only. Anything running outside a browser (the
// mediator, biset-anchor, a verification script) had to reimplement resolution
// or shim `localStorage` to use it; that is exactly how the wire format ended
// up implemented three times over. See ANCHOR.md.
//
// Deliberately NO default store: an implicit fallback would be a *silent*
// downgrade of a security property — a memory store resets the floor on every
// page load, quietly re-opening the rollback attack this file exists to close.
// Unconfigured therefore throws, loudly, on first use. `localStorage` satisfies
// SeqStore as-is, so a browser wires it up in one line.
export interface SeqStore {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
}

const PREFIX = 'biset_did_seq:'

let store: SeqStore | null = null

/** Call once at startup, before anything resolves. Browsers pass `localStorage`. */
export function useSeqStore(s: SeqStore): void {
  store = s
}

function required(): SeqStore {
  if (!store) {
    throw new Error(
      'did/freshness: no seq store configured — call useSeqStore() at startup ' +
      '(browser: useSeqStore(localStorage)). Refusing to resolve without rollback defense.',
    )
  }
  return store
}

/** Throws unless a store is configured. `resolve()` calls this up front rather
 * than waiting for noteSeq: otherwise a misconfigured deployment only finds out
 * on its first *successful* resolve (a lookup that finds nothing short-circuits
 * before the floor is ever consulted), so the mistake could sit latent for a
 * long time. Failing on any resolve attempt makes the contract — "no resolution
 * without rollback defense" — immediate and testable. */
export function requireSeqStore(): void {
  required()
}

export function seenSeq(did: string): number {
  const v = required().getItem(PREFIX + did)
  return v ? Number(v) : -1
}

// Records seq as the new floor when it advances. Returns false if seq is a
// rollback (strictly lower than what we've already trusted) — the caller must
// then reject the record.
export function noteSeq(did: string, seq: number): boolean {
  if (seq < seenSeq(did)) return false
  required().setItem(PREFIX + did, String(seq))
  return true
}
