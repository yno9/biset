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
import { identityKey, parseWebvhDid, sameIdentity, scidOf } from '../../../protocol/webvh/identifier.ts'
import { mailAddressOfBridgeDid } from '../../pgp/autocrypt.ts'
import { defaultDisplayName } from './account/default-name.ts'

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

// ── Names ─────────────────────────────────────────────────────────────────────
// Who someone is called, where there is a name: the contact list's (contacts.ts: a name written by hand, the one an invite gave,
// the one on a mail's From:). Without one, the address. The list is filled from the contact cards each time the inbox is
// refreshed (shell.ts); the places that name a person call displayName, the ones that mean the address call labelForDid.
//
// Stored data names this identity and its correspondents by their identity key (identityKey: `did:webvh:<SCID>`, no host), and
// a DID may have changed its alias since: so names, pictures and addresses are looked up under the key as well as the DID. What a
// screen shows is never the key itself: the name, else the address the identity stands for, else (only when nothing is known of
// it) the raw string.
let contactNames: ReadonlyMap<string, string> = new Map()
export function setContactNames(names: ReadonlyMap<string, string>): void { contactNames = names }

// The DIDs the contact cards name (by identity key): the host-less key has no address in it; the DID it stands for does.
let contactDids: ReadonlyMap<string, string> = new Map()
// A card can itself name its person by the key (this identity's own card does: `didContactPatch(identityId)`); such a DID has no
// host, so it tells nothing and is left out: only a DID with a host can stand in for the key.
export function setContactDids(dids: ReadonlyMap<string, string>): void {
  contactDids = new Map([...dids].filter(([, did]) => !isIdentityKey(did)))
}

/** A did:webvh with no host, the form identityKey makes: it names an identity, not a place. */
const isIdentityKey = (did: string): boolean => scidOf(did) !== undefined && did.split(':').length === 3

// This identity's own DID, set when the app starts (before any message is drawn: a screen that read it from the account page's
// state would draw the first messages before that state exists, and not draw them again).
let ownDid: string | undefined
export function setOwnDid(did: string | undefined): void { ownDid = did }

/** This identity's own display name where it has not set one (default-name.ts): worked out from its SCID, so it is always a name. */
export function ownDefaultName(): string | undefined {
  const scid = ownDid && scidOf(ownDid)
  return scid ? defaultDisplayName(scid) : undefined
}

/** The full DID an identity key stands for, as far as it is known: a contact's, or this identity's own. */
function didOfKey(key: string): string | undefined {
  return (ownDid && sameIdentity(ownDid, key) ? ownDid : undefined) ?? contactDids.get(key)
}

export function displayName(did: string): string {
  const named = contactNames.get(did) ?? contactNames.get(identityKey(did))
  if (named) return named
  if (ownDid && sameIdentity(ownDid, did)) return ownDefaultName() ?? labelForDid(ownDid)
  return labelForDid(isIdentityKey(did) ? didOfKey(did) ?? did : did)
}

// Pictures: the card's, as data URLs, set the same way each refresh.
let contactAvatars: ReadonlyMap<string, string> = new Map()
export function setContactAvatars(avatars: ReadonlyMap<string, string>): void { contactAvatars = avatars }
export function avatarOf(did: string | undefined): string | undefined { return did ? contactAvatars.get(did) ?? contactAvatars.get(identityKey(did)) : undefined }

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
