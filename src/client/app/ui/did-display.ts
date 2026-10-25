// Shared "how do I show this DID to a human" rule -- the account page (the
// signed-in identity's own DID) and the compose page (a typed recipient's
// DID) both need the exact same elision, and duplicating it was already the
// kind of divergence that bit this codebase once (state.ts/message-view.ts).
import { identityKey, sameIdentity, vhScidOf } from '../../../protocol/vh/identifier.ts'
import { mailAddressOfBridgeDid } from '../../pgp/autocrypt.ts'

/** Elided display form -- `did:vh:QmfJMA…` for a did:vh (its SCID cut short), the raw string unchanged for anything else (a bare
 * email, another DID method). Never lossy: the caller keeps the real value separately (e.g. an input's `dataset.fullDid`) for
 * anything that actually needs it (copy, send). */
export function shortDid(did: string): string {
  const scid = vhScidOf(did)
  return scid ? `did:vh:${scid.slice(0, 8)}…` : did
}

/** How a DID is shown to a person: as a mail address, `hrdcv7qkr@nine.testrun.org`, `alice@did.md`. biset's principle is that a
 * person sees addresses, not DIDs; a screen that shows a DID on purpose (the identity card, a debugging line) says so and does
 * not come through here. Everything else that names someone calls this, so a rule changed here changes it everywhere.
 *
 *  - a mail bridge's DID (`did:web:{bridge}:{domain}:{local}`) is the address it stands for (didmail PROTOCOL.md §3.1);
 *  - a did:vh names no host, so its address is not in the string: it is the did:web DID its document names (`alice@did.md` for
 *    `did:web:alice.did.md`), once that DID's shadow was checked in both directions (protocol/vh/didweb.ts verifiedAddress);
 *  - anything else (a bare address, another DID method, a did:vh with no verified address) is left as it is, never invented. */
export function labelForDid(did: string): string {
  const bridged = mailAddressOfBridgeDid(did)
  if (bridged) return bridged
  if (vhScidOf(did)) return verifiedAddresses.get(identityKey(did)) ?? did
  return did
}

// The address a did:vh stands for, by identity key, where its did:web shadow was verified (set by whoever verified it).
let verifiedAddresses: ReadonlyMap<string, string> = new Map()
export function setVerifiedAddresses(addresses: ReadonlyMap<string, string>): void { verifiedAddresses = addresses }

// ── Names ─────────────────────────────────────────────────────────────────────
// Who someone is called, where there is a name: the contact list's (contacts.ts: a name written by hand, the one an invite gave,
// the one on a mail's From:). Without one, the address. The list is filled from the contact cards each time the inbox is
// refreshed (shell.ts); the places that name a person call displayName, the ones that mean the address call labelForDid.
//
// Stored data names this identity and its correspondents by their identity key (identityKey: `did:vh:<SCID>`, no host), and
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

/** A bare did:vh, the form identityKey makes: it names an identity, not a place. */
const isIdentityKey = (did: string): boolean => vhScidOf(did) !== undefined && vhScidOf(did) === did.slice('did:vh:'.length)

// This identity's own DID, set when the app starts (before any message is drawn: a screen that read it from the account page's
// state would draw the first messages before that state exists, and not draw them again).
let ownDid: string | undefined
export function setOwnDid(did: string | undefined): void { ownDid = did }

/** The full DID an identity key stands for, as far as it is known: a contact's, or this identity's own. */
function didOfKey(key: string): string | undefined {
  return (ownDid && sameIdentity(ownDid, key) ? ownDid : undefined) ?? contactDids.get(key)
}

export function displayName(did: string): string {
  const named = contactNames.get(did) ?? contactNames.get(identityKey(did))
  if (named) return named
  return labelForDid(isIdentityKey(did) ? didOfKey(did) ?? did : did)
}

// Pictures: the card's, as data URLs, set the same way each refresh.
let contactAvatars: ReadonlyMap<string, string> = new Map()
export function setContactAvatars(avatars: ReadonlyMap<string, string>): void { contactAvatars = avatars }
export function avatarOf(did: string | undefined): string | undefined { return did ? contactAvatars.get(did) ?? contactAvatars.get(identityKey(did)) : undefined }

// ── Transport protocol pill ─────────────────────────────────────────────────
// Shared between pages/compose-page.tsx (a typed recipient) and right-col.tsx (a
// conversation's actual participants) -- a "to"/participant is either a
// did:vh string (DIDComm) or a plain mail address, decided entirely by
// its shape. the thread header's own conv-via badge used to hardcode 'Mail'
// unconditionally (written before DIDComm chat send existed, never revisited
// once it did) -- this is the one place that decides, so both readers agree.
export type Proto = 'mail' | 'did'
export const PROTO_COLOR: Record<Proto, string> = { mail: '#64748b', did: '#0ea5e9' }
export const PROTO_TEXT: Record<Proto, string> = { mail: 'Mail', did: 'DID' }

export function protocolFor(address: string): Proto {
  return address.startsWith('did:') ? 'did' : 'mail'
}
