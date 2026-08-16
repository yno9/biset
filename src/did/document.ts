// The DID document shape biset reads and writes, independent of the method
// that carries it.
//
// These types were born inside `dht/document.ts`, where the did:dht wire
// format lives, and stayed there while did:webvh was added — `webvh/
// document.ts` imported `DidKeyAgreement` from the did:dht module because that
// is where it happened to be, not because did:webvh has anything to do with
// BEP44 or DNS records. Removing did:dht is what makes that accidental
// dependency visible, so the shared half moves here and the wire format stays
// behind.
//
// Nothing in this file knows how a document is stored, fetched or signed. That
// is each method's own business (`webvh/`), and the reason this file has no
// imports beyond a kid helper: it is shared into the anchor's DOM-free build.
import { fragmentOf } from './devicekid.ts'

export interface DidService {
  id: string // fragment only, e.g. "mail" (not the full did#mail)
  type: string
  serviceEndpoint: string[]
  // The transport this relay bridges and the identity's address ON this relay.
  // This is what links a relay endpoint to its own address + protocol — so AP
  // and SMTP endpoints of one DID can carry DIFFERENT addresses (they no
  // longer must match; the DID binds them).
  protocol?: string // e.g. 'mail' | 'activitypub'
  address?: string  // this endpoint's address, e.g. y@biset.md
  // W3C-standard DIDCommMessaging serviceEndpoint fields.
  accept?: string[]
  routingKeys?: string[] // DID URLs — a mediator's kid
}

/** One X25519 keyAgreement key belonging to one DEVICE.
 *
 * Zero or more per identity — **one per device, never one per identity**. Two
 * devices restoring the same seed would derive the IDENTICAL key if this were
 * seed-derived, and the mediator's single-queue-per-kid delivery model means
 * whichever device polled first would silently starve the other. Each device
 * instead mints its own random key (`didcomm-devices.ts`) and holds its own
 * entry here, so a sender fans a message out to every registered device. */
export interface DidKeyAgreement {
  /** The verification-method FRAGMENT naming this device key — `#k_<hash>`
   * for a derived kid (devicekid.ts) or `#k<n>` for one minted before that.
   * Was a slot NUMBER; see devicekid.ts's header for why the number went. */
  kid: string
  publicKey: Uint8Array
}

export interface DidDocument {
  id: string
  identityKey: Uint8Array // raw Ed25519 public key
  keyAgreementKeys?: DidKeyAgreement[]
  alsoKnownAs: string[]
  service: DidService[]
  /** A self-asserted display name — purely a UX label, not verified by
   * anyone. Same trust level as any social profile's display name. */
  name?: string
}

/** This device's own keyAgreement entry (if it has one) plus every known
 * sibling device's — the array a document publish carries. Takes hex strings
 * directly (a `DidRecord`'s own shape) so every caller builds the exact same
 * array from cached record state without re-deriving the hex-decode
 * boilerplate. */
export function keyAgreementKeysFromHex(
  own: { kid: string; publicKeyHex: string } | null,
  siblings: Array<{ kid: string; publicKeyHex: string }>,
): DidKeyAgreement[] {
  // Deduped by kid, own always wins — found live: a device that self-heals to
  // a new kid (didcomm-devices.ts's syncDevicePosition, mismatch branch) keeps
  // its OWN local sibling cache around, and if that cache still had a stale
  // entry at the same kid it just claimed, this used to emit TWO entries for
  // one device — ambiguous the moment anything parses it back, and visibly
  // duplicated in left-pane.ts's device list.
  const byKid = new Map<string, Uint8Array>()
  if (own) byKid.set(fragmentOf(own.kid), hexToBytes(own.publicKeyHex))
  for (const s of siblings) {
    const kid = fragmentOf(s.kid)
    if (!byKid.has(kid)) byKid.set(kid, hexToBytes(s.publicKeyHex))
  }
  return [...byKid.entries()].map(([kid, publicKey]) => ({ kid, publicKey }))
}

// Local, not imported from utils.ts: this file is shared into the anchor's
// DOM-free build, and utils.ts is a DOM-touching grab-bag that would break it.
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
