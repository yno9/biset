// Each device's DIDComm transport keys, carried inside its own MLS leaf.
//
// ## Why they belong in the tree
//
// The ratchet tree already answers "which devices does this identity have" —
// that is what made it able to replace the gossip merge, the tombstones and
// the keylist prune. But a device list is not enough to publish a DID
// document: an entry there is a kid AND the X25519 key senders encrypt to, and
// a leaf credential only carries the kid. Reading the keys back out of the
// published document would leave the very read path the switch was meant to
// delete — the tree would decide membership while the document still had to be
// consulted for what each member is.
//
// Putting the transport keys in the leaf closes that. A member can build the
// whole document from group state alone, and the document becomes strictly an
// output: written, never read, for this identity's own devices.
//
// ## What makes the binding trustworthy
//
// Two independent things, and it is worth being precise about which does what:
//
//   - **MLS signs the leaf.** A leaf node is signed by the device's own
//     signature key, so no one else can put a key in someone's leaf, and no
//     one can alter it without the group noticing.
//   - **The kid commits to the key.** A device kid is
//     `#k_<hash of the X25519 key>` (did/devicekid.ts), so the credential and
//     the extension can be checked against each other with no third party
//     involved. `deviceTransportKeys` does that check and drops a leaf that
//     fails it, which is what makes a mismatch a non-event rather than a
//     document published with someone else's key at a device's name.
//
// ## Wire format
//
// Fixed-length fields, so there is nothing to length-prefix and nothing to
// disagree about:
//
//     version(1) ‖ x25519(32) [‖ ml-kem-768(1184)]
//
// The ML-KEM key is optional because a device may predate PQ support
// (PLAN.md's did:webvh hybrid work) — absent means "not PQ-capable", which is
// exactly how the document's own `#kk…` entries already read.
import type { Extension, LeafNode } from './vendor/index.ts'
import { deviceKidFragment, fragmentOf } from '../did/devicekid.ts'
import { memberIdOf } from './identity.ts'

/** Private-use extension type (RFC 9420 registers 0xF000–0xFFFF for it), so
 * this can never collide with a standard extension. Every leaf carrying one
 * must also list it in its `capabilities.extensions`, which is what
 * `mlsCapabilities()` in group.ts is for — a leaf whose capabilities omit an
 * extension it carries is rejected by the group. */
export const TRANSPORT_KEYS_EXTENSION = 0xf001

const VERSION = 1
const X25519_LEN = 32
const MLKEM768_LEN = 1184

export interface DeviceTransportKeys {
  /** The device kid these keys belong to (`#k_…`), from the leaf credential. */
  kid: string
  x25519: Uint8Array
  mlkem?: Uint8Array
}

export function encodeTransportKeys(x25519: Uint8Array, mlkem?: Uint8Array): Extension {
  if (x25519.length !== X25519_LEN) throw new Error(`encodeTransportKeys: X25519 key must be ${X25519_LEN} bytes`)
  if (mlkem && mlkem.length !== MLKEM768_LEN) throw new Error(`encodeTransportKeys: ML-KEM-768 key must be ${MLKEM768_LEN} bytes`)
  const data = new Uint8Array(1 + X25519_LEN + (mlkem ? MLKEM768_LEN : 0))
  data[0] = VERSION
  data.set(x25519, 1)
  if (mlkem) data.set(mlkem, 1 + X25519_LEN)
  return { extensionType: TRANSPORT_KEYS_EXTENSION, extensionData: data }
}

/** Undefined for anything this build does not recognize — a future version
 * byte, a truncated payload, a leaf with no such extension at all. A device
 * whose keys cannot be read is simply not publishable yet, which is a far
 * better outcome than guessing at bytes. */
export function decodeTransportKeys(extensions: Extension[]): { x25519: Uint8Array; mlkem?: Uint8Array } | undefined {
  const ext = extensions.find(e => e.extensionType === TRANSPORT_KEYS_EXTENSION)
  if (!ext) return undefined
  const data = ext.extensionData
  if (data[0] !== VERSION) return undefined
  if (data.length === 1 + X25519_LEN) return { x25519: data.slice(1) }
  if (data.length === 1 + X25519_LEN + MLKEM768_LEN) {
    return { x25519: data.slice(1, 1 + X25519_LEN), mlkem: data.slice(1 + X25519_LEN) }
  }
  return undefined
}

/** A leaf's device identity and transport keys, or undefined when the leaf
 * does not carry them or contradicts itself.
 *
 * The contradiction check is the load-bearing part: the credential's kid is a
 * hash of the X25519 key, so a leaf claiming `did#k_A` while carrying key B is
 * either a bug or an attempt to have this identity publish B under A's name.
 * Either way it is dropped rather than trusted. */
export function deviceTransportKeys(leaf: LeafNode): DeviceTransportKeys | undefined {
  let kid: string
  try {
    ;({ kid } = memberIdOf(leaf.credential))
  } catch {
    return undefined
  }
  const keys = decodeTransportKeys(leaf.extensions)
  if (!keys) return undefined
  if (fragmentOf(kid) !== deviceKidFragment(keys.x25519)) {
    console.warn(`[mls] dropping a leaf whose kid does not match its transport key: ${kid}`)
    return undefined
  }
  return { kid, ...keys }
}
