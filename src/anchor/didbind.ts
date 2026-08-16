// Verifies that whoever is claiming an address actually controls the DID they
// claim it for. The client signs, with the DID's **root** key, the host-bound
// statement `bind:<did>:<username>@<relayHost>:<unixSeconds>` (src/did/
// binding.ts builds it; go-jmapserver/didbind.go checked it until the anchor
// took the job over). No secret ever leaves the client — the DID *is* its own
// public key, z-base-32 encoded.
//
// Two things stop a captured signature being reused: the host it names, and a
// freshness window. Neither is the anchor's own knowledge. **The relay reports
// the host it saw** (`r.Host` — first-hand, off the transport) and the anchor
// verifies against what it was told. That is a real step down from a relay
// checking a value it observed itself, and it is only sound because a relay and
// its anchor are one operator (ANCHOR.md: an anchor is per-operator by
// construction, never global). A relay lying about the host still cannot forge
// a signature for a host it doesn't hold one for, and it could already claim
// anything it liked on the anchor without this check at all — the anchor has
// never authenticated its relays.
import { ed25519 } from '@noble/curves/ed25519.js'
import { rootPublicKeyFromWebvhState } from '../did/webvh/document.ts'
import { resolveOwnWebvhDocument } from './webvh-resolve.ts'
import type { WebvhLogStore } from './webvh-store.ts'
import { vouchStatement } from '../did/devicebind.ts'

/** Matches go-jmapserver's didBindWindow. Both directions: a clock ahead of
 * ours is as ordinary as one behind. */
const BIND_WINDOW_SECONDS = 300

export type BindResult = { ok: true } | { ok: false; reason: string }

// Root-key resolver for verifyDIDBinding: a did:webvh identifier only names a
// verificationMethod, so the DID must be resolved — against this anchor's own
// log store, since the DID being claimed here was just PUT there by the same
// account-creation flow (server.ts's PUT /dids/*).
export function rootKeyResolver(webvh: WebvhLogStore | undefined): (did: string) => Promise<Uint8Array | null> {
  return async (did: string): Promise<Uint8Array | null> => {
    if (!did.startsWith('did:webvh:')) return null
    if (!webvh) return null
    const doc = resolveOwnWebvhDocument(webvh, did)
    return doc ? rootPublicKeyFromWebvhState(doc) : null
  }
}

export interface Binding {
  did: string
  username: string
  /** The host the *client* signed against, as the relay observed it. */
  relayHost: string
  /** Unix seconds. */
  bindTs: number
  /** base64 (standard alphabet, matching Go's base64.StdEncoding). */
  sigB64: string
}

/** True only if `sigB64` is a valid root-key signature over this exact binding
 * and the timestamp is inside the freshness window. Returns a reason rather
 * than throwing: a bad binding is a 401 for the caller, not an anchor fault.
 *
 * `resolveRootKey` gets the DID's root public key: a did:webvh identifier
 * only names a verificationMethod, so the caller must resolve the document
 * (server.ts, against its own webvh store — the DID being claimed there was
 * written by the same PUT /dids/* flow moments earlier). */
export async function verifyDIDBinding(
  b: Binding,
  resolveRootKey: (did: string) => Promise<Uint8Array | null>,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<BindResult> {
  if (!Number.isFinite(b.bindTs)) return { ok: false, reason: 'binding timestamp missing' }
  const drift = nowSeconds - b.bindTs
  if (drift > BIND_WINDOW_SECONDS || drift < -BIND_WINDOW_SECONDS) {
    return { ok: false, reason: 'binding timestamp out of window' }
  }
  const pk = await resolveRootKey(b.did)
  if (!pk) return { ok: false, reason: 'could not resolve DID root key' }

  let sig: Uint8Array
  try {
    sig = Uint8Array.from(atob(b.sigB64), c => c.charCodeAt(0))
  } catch {
    return { ok: false, reason: 'bad signature encoding' }
  }

  // Byte-identical to the statement src/did/binding.ts signs and didbind.go
  // verified. Any drift between the three and every DID account creation fails.
  const stmt = `bind:${b.did}:${b.username}@${b.relayHost}:${b.bindTs}`
  let valid: boolean
  try {
    valid = ed25519.verify(sig, new TextEncoder().encode(stmt), pk)
  } catch {
    return { ok: false, reason: 'binding signature invalid' }
  }
  return valid ? { ok: true } : { ok: false, reason: 'binding signature invalid' }
}

export interface DeviceVouch {
  did: string
  devicePubKey: string // base64url (devicebind.ts's b64urlEncode)
  label: string
  ts: number // unix seconds
  sigB64: string
}

// The per-device JMAP credential's one DID-touching step (devicebind.ts's
// file header): does `did`'s CURRENT root key actually authorize
// `devicePubKey` for JMAP login? Deliberately reuses the exact same
// resolveRootKey a provisioning claim already uses — a device vouched for
// before a later did:webvh key rotation stays valid, because the resolver
// always follows the DID to whatever key controls it NOW, never a key fixed
// at vouch time. Everything after this (ordinary session logins,
// devicebind.ts's signSessionLogin) is verified against the device pubkey
// alone and never reaches this function again.
export async function verifyDeviceVouch(
  v: DeviceVouch,
  resolveRootKey: (did: string) => Promise<Uint8Array | null>,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<BindResult> {
  if (!Number.isFinite(v.ts)) return { ok: false, reason: 'vouch timestamp missing' }
  const drift = nowSeconds - v.ts
  if (drift > BIND_WINDOW_SECONDS || drift < -BIND_WINDOW_SECONDS) {
    return { ok: false, reason: 'vouch timestamp out of window' }
  }
  const pk = await resolveRootKey(v.did)
  if (!pk) return { ok: false, reason: 'could not resolve DID root key' }

  let sig: Uint8Array
  try {
    sig = Uint8Array.from(atob(v.sigB64), c => c.charCodeAt(0))
  } catch {
    return { ok: false, reason: 'bad signature encoding' }
  }

  const stmt = vouchStatement(v.did, v.devicePubKey, v.label, v.ts)
  let valid: boolean
  try {
    valid = ed25519.verify(sig, new TextEncoder().encode(stmt), pk)
  } catch {
    return { ok: false, reason: 'vouch signature invalid' }
  }
  return valid ? { ok: true } : { ok: false, reason: 'vouch signature invalid' }
}
