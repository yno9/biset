// The SCID<->localpart projection (jmapsmtp's ARC.md §2.9) — port of
// `crates/jmapsmtp/src/did/scid_localpart.rs`, computable identically here so
// a client can know its own resulting `scid@domain` address without a round
// trip to the relay.
//
// Why this exists: a did:webvh SCID is base58btc (scid.ts), and base58
// distinguishes case — of its 58 symbols, 46 pair up across case
// (`A`/`a`, `B`/`b`, …), so a 46-character SCID has on the order of 36-37
// case-ambiguous positions. Folding case (lowercasing it for use as a mail
// localpart, which every relay's alias/account table does pervasively)
// collapses roughly 2^36-37 distinct, independently valid SCIDs onto one
// lowercase string — a birthday collision reachable at a few hundred
// thousand registered identities, nowhere near the SHA-256-class collision
// resistance (~2^128) the SCID is actually supposed to carry.
//
// The fix is a lossless, case-insensitive-safe RE-ENCODING of the same 34
// raw bytes a SCID already is — a 2-byte SHA-256 multihash prefix plus the
// 32-byte digest (multihash.ts) — not a fold. Reversible on purpose: a
// one-way hash would have thrown away, for nothing, the ability to recover
// the SCID from `localpart@domain` with no registry lookup. Reversibility
// stops at the SCID, not the document: unlike did:key, a did:webvh SCID
// carries no location information on its own, so recovering it does not by
// itself resolve anything further — that still needs one registry step (the
// anchor's claim lookup).
import { base58 } from '@scure/base'
import { encode as zbase32Encode, decode as zbase32Decode } from './zbase32.ts'

/** did:webvh's SCID: a 2-byte SHA-256 multihash prefix plus the 32-byte
 * digest (multihash.ts). Fixed by the method itself (`did:webvh:1.0` permits
 * no other hash), not a detail of this projection. */
const SCID_BYTES = 34

/** The SCID's own base58 form, re-encoded as a case-insensitive-safe JMAP
 * localpart. `null` when `scid` does not decode to exactly `SCID_BYTES`
 * bytes. */
export function scidToLocalpart(scid: string): string | null {
  let bytes: Uint8Array
  try {
    bytes = base58.decode(scid)
  } catch {
    return null
  }
  if (bytes.length !== SCID_BYTES) return null
  return zbase32Encode(bytes)
}

/** The inverse: recovers a SCID's own base58 form from a localpart this
 * module produced. `null` for anything that isn't exactly one of those. */
export function localpartToScid(localpart: string): string | null {
  const bytes = zbase32Decode(localpart, SCID_BYTES)
  if (!bytes) return null
  return base58.encode(bytes)
}
