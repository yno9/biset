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
