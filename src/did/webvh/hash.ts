// The hash construction shared by SCID generation (scid.ts) and DID Log
// entryHash generation (log.ts) — both are "hash this JSON document" with
// the same JCS + multihash + base58btc pipeline, just applied to different
// inputs (DIDWEBVHFEAT.md §3, §4).
import { base58 } from '@scure/base'
import { canonicalize } from './jcs.ts'
import { multihashSha256 } from './multihash.ts'

export function jcsMultihashBase58(value: unknown): string {
  const bytes = new TextEncoder().encode(canonicalize(value))
  return base58.encode(multihashSha256(bytes))
}

/** Pre-rotation's own hash construction (did:webvh v1.0 "Pre-Rotation Key
 * Hash Generation and Verification"): `base58btc(multihash(multikey))` over
 * the raw multikey STRING bytes directly — no JSON, no JCS canonicalization,
 * unlike jcsMultihashBase58 above. Used both to build `nextKeyHashes` entries
 * (publish.ts) and to verify a revealed key against a previous commitment
 * (resolver.ts). */
export function multikeyHashBase58(multikey: string): string {
  return base58.encode(multihashSha256(new TextEncoder().encode(multikey)))
}
