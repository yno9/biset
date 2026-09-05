// Shared "how do I show this DID to a human" rule -- account-page.ts (the
// signed-in identity's own DID) and compose-page.ts (a typed recipient's
// DID) both need the exact same elision, and duplicating it was already the
// kind of divergence that bit this codebase once (state.ts/message-view.ts).
//
// Ported from src.bak/did/contacts.ts's ownDidParts, narrowed to what this
// rewrite's did:webvh actually produces: subdomain-per-identity, no trailing
// `:{username}` path segment (identity/webvh/create-genesis.ts) -- so hiding
// the 46-char SCID and keeping `did:webvh:{domain}` is the whole rule, not
// src.bak's more general prefix/hidden/suffix split (which existed to also
// handle a foreign did:webvh's own path convention).
import { parseWebvhDid } from '../../identity/webvh/identifier.ts'

/** Elided display form -- `did:webvh:t.biset.md` for a did:webvh, the raw
 * string unchanged for anything else (a bare email, or a DID method this
 * rewrite doesn't create). Never lossy: the caller keeps the real value
 * separately (e.g. an input's `dataset.fullDid`) for anything that actually
 * needs it (copy, send). */
export function shortWebvhDid(did: string): string {
  if (!did.startsWith('did:webvh:')) return did
  try {
    return `did:webvh:${parseWebvhDid(did).domain}`
  } catch {
    return did
  }
}

/** src.bak's labelForDid (did/contacts.ts): a did:webvh's identifier bakes
 * the username in, so showing it needs no resolve, no Card, nothing
 * published -- reads the same identifier the peer is already addressed by.
 * This rewrite's did:webvh has no separate `:{username}` path segment the
 * way src.bak's did (bisetWebvhUsername) had; the username IS the domain's
 * first label instead (identity/bootstrap.ts's own `domain =
 * ${username}.${apexDomain}`), so that's what this reads. Falls back to the
 * elided form for anything that isn't shaped like that (a bare email, a
 * foreign did:webvh apex with no subdomain, or any other DID method) --
 * never invents a name from a shape it doesn't recognize. */
export function labelForDid(did: string): string {
  if (!did.startsWith('did:webvh:')) return did
  try {
    const domain = parseWebvhDid(did).domain
    const label = domain.split('.')[0]
    return label && label !== domain ? label : shortWebvhDid(did)
  } catch {
    return did
  }
}

// ── Transport protocol pill ─────────────────────────────────────────────────
// Shared between compose-page.ts (a typed recipient) and thread.ts (a
// conversation's actual participants) -- a "to"/participant is either a
// did:webvh string (DIDComm) or a plain mail address, decided entirely by
// its shape. thread.ts's own conv-via badge used to hardcode 'Mail'
// unconditionally (written before DIDComm chat send existed, never revisited
// once it did) -- this is the one place that decides, so both readers agree.
export type Proto = 'mail' | 'did'
export const PROTO_COLOR: Record<Proto, string> = { mail: '#64748b', did: '#0ea5e9' }
export const PROTO_TEXT: Record<Proto, string> = { mail: 'Mail', did: 'DID' }

export function protocolFor(address: string): Proto {
  return address.startsWith('did:') ? 'did' : 'mail'
}
