// A device key's identifier — derived from the key, never allocated.
//
// Ported verbatim from src.bak/did/devicekid.ts.
//
// ## Why this file exists
//
// A device's DIDComm key needs a name. Four separate layers demand one and
// none of them can be talked out of it:
//
//   - **W3C DID Core** — a `verificationMethod` has an `id`, and `keyAgreement`
//     is a list of those ids.
//   - **DIDComm's JWE** — the recipient header's `kid` and authcrypt's `skid`.
//     Not merely a label: `didcomm/crypto.ts` feeds both into `apu`/`apv`, so
//     the identifier string is an input to the key derivation itself.
//   - **Routing 2.0** — a Forward names its target by kid (this rewrite does
//     not implement Forward — didcomm/crypto.ts's own header — but the kid
//     naming convention it depends on is the same one every other DIDComm
//     implementation expects).
//   - **The recipient resolver's own bookkeeping** — one keyAgreement entry
//     per kid.
//
// So the question was never whether to have one. It was whether it should
// carry STATE. The original scheme — `#k1`, `#k2`, … — made it a counter, and
// every problem followed from that: a number has to be allocated (from what
// view of the world?), must never be handed out twice (so retired ones need
// tombstones), and a mistake is unrecoverable rather than merely wrong. A
// sole device that logged out and restored got `#k1` again — a genuinely
// different key under an identifier a resolver had cached, so every
// authcrypt to it failed with "integrity check failed" until the cache
// expired.
//
// Deriving the identifier from the key removes the state. There is nothing to
// allocate, nothing to coordinate, and reuse is not prevented but IMPOSSIBLE:
// the same key always produces the same kid, and a different key cannot
// produce the same one.
//
// ## The shape
//
//     #k_<base58btc(sha256(publicKey)[0..16])>
//
// `_` after the `k` keeps a derived suffix from ever reading as some other
// `#k…` naming scheme. `_` is unreserved in a URI fragment (RFC 3986), and no
// derived suffix can begin with it.
//
// 16 bytes of SHA-256 is 128 bits. This is an identifier, not a commitment:
// the document still binds key to identity, so a collision would only mean
// two devices claiming one name, at a cost of ~2^64 work to arrange.
//
// ## Legacy
//
// `#k1`-style kids stay readable forever — an identity published before this
// change is not rewritable by anyone but its own devices, and a sender must
// keep being able to address one. `isLegacyKid` tells them apart.
import { sha256 } from '@noble/hashes/sha2.js'
import { base58 } from '@scure/base'

/** Bytes of digest kept. */
const KID_BYTES = 16

/** The fragment (`#k_…`) naming this X25519 device key. Fragment only — a
 * full DID URL is `${did}${deviceKidFragment(key)}`. */
export function deviceKidFragment(publicKey: Uint8Array): string {
  return `#k_${base58.encode(sha256(publicKey).slice(0, KID_BYTES))}`
}

/** The full DID URL for a device key of `did`. */
export function deviceKid(did: string, publicKey: Uint8Array): string {
  return `${did}${deviceKidFragment(publicKey)}`
}
