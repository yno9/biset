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
import { zbase32Decode } from '../did/zbase32.ts'

/** Matches go-jmapserver's didBindWindow. Both directions: a clock ahead of
 * ours is as ordinary as one behind. */
const BIND_WINDOW_SECONDS = 300

export type BindResult = { ok: true } | { ok: false; reason: string }

/** The ed25519 public key a did:dht identifier names — the DID is the key. */
export function didPublicKey(did: string): Uint8Array | null {
  if (!did.startsWith('did:dht:')) return null
  const suffix = did.slice('did:dht:'.length)
  if (suffix === '') return null
  try {
    return zbase32Decode(suffix, 32)
  } catch {
    return null
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
 * than throwing: a bad binding is a 401 for the caller, not an anchor fault. */
export function verifyDIDBinding(b: Binding, nowSeconds = Math.floor(Date.now() / 1000)): BindResult {
  if (!Number.isFinite(b.bindTs)) return { ok: false, reason: 'binding timestamp missing' }
  const drift = nowSeconds - b.bindTs
  if (drift > BIND_WINDOW_SECONDS || drift < -BIND_WINDOW_SECONDS) {
    return { ok: false, reason: 'binding timestamp out of window' }
  }
  const pk = didPublicKey(b.did)
  if (!pk) return { ok: false, reason: 'not a did:dht identifier' }

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
