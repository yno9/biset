// Shared "how do I show this DID to a human" rule -- the account page (the
// signed-in identity's own DID) and the compose page (a typed recipient's
// DID) both need the exact same elision, and duplicating it was already the
// kind of divergence that bit this codebase once (state.ts/message-view.ts).
//
// Ported from src.bak/did/contacts.ts's ownDidParts, narrowed to what this
// rewrite's did:webvh actually produces: subdomain-per-identity, no trailing
// `:{username}` path segment (identity/webvh/create-genesis.ts) -- so hiding
// the 46-char SCID and keeping `did:webvh:{domain}` is the whole rule, not
// src.bak's more general prefix/hidden/suffix split (which existed to also
// handle a foreign did:webvh's own path convention).
import { parseWebvhDid } from '../../../protocol/webvh/identifier.ts'
import { mailAddressOfBridgeDid } from '../../pgp/autocrypt.ts'

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

/** How a DID is shown to a person: as a mail address, `hrdcv7qkr@nine.testrun.org`, `alice@did.md`. biset's principle is that a
 * person sees addresses, not DIDs; a screen that shows a DID on purpose (the identity card, a debugging line) says so and does
 * not come through here. Everything else that names someone calls this, so a rule changed here changes it everywhere.
 *
 *  - a mail bridge's DID (`did:web:{bridge}:{domain}:{local}`) is the address it stands for (didmail PROTOCOL.md §3.1);
 *  - a did:webvh of this system (`{username}.{apex}`, no separate path: identity/bootstrap.ts) is `username@apex`, the address
 *    didmail gives it;
 *  - anything else (a bare address, another DID method, a did:webvh shaped otherwise) is left as it is, never invented. */
export function labelForDid(did: string): string {
  const bridged = mailAddressOfBridgeDid(did)
  if (bridged) return bridged
  if (!did.startsWith('did:webvh:')) return did
  try {
    const domain = parseWebvhDid(did).domain
    const dot = domain.indexOf('.')
    return dot > 0 ? `${domain.slice(0, dot)}@${domain.slice(dot + 1)}` : shortWebvhDid(did)
  } catch {
    return did
  }
}

// ── Transport protocol pill ─────────────────────────────────────────────────
// Shared between pages/compose-page.tsx (a typed recipient) and right-col.tsx (a
// conversation's actual participants) -- a "to"/participant is either a
// did:webvh string (DIDComm) or a plain mail address, decided entirely by
// its shape. the thread header's own conv-via badge used to hardcode 'Mail'
// unconditionally (written before DIDComm chat send existed, never revisited
// once it did) -- this is the one place that decides, so both readers agree.
export type Proto = 'mail' | 'did'
export const PROTO_COLOR: Record<Proto, string> = { mail: '#64748b', did: '#0ea5e9' }
export const PROTO_TEXT: Record<Proto, string> = { mail: 'Mail', did: 'DID' }

export function protocolFor(address: string): Proto {
  return address.startsWith('did:') ? 'did' : 'mail'
}
