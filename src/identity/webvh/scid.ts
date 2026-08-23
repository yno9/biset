// SCID (Self-Certifying IDentifier) verification (DIDWEBVHFEAT.md §3,
// did:webvh v1.0 spec "SCID Generation and Verification"). The SCID is the
// hash of the genesis log entry with a `{SCID}` placeholder standing in for
// itself everywhere it would otherwise appear.
import { jcsMultihashBase58 } from './hash.ts'

export const SCID_PLACEHOLDER = '{SCID}'

function generateScid(preliminaryEntry: unknown): string {
  return jcsMultihashBase58(preliminaryEntry)
}

/** Verifies the first DID Log entry's `scid` against a recomputed hash: strip
 * the proof, force `versionId` back to the placeholder, and replace every
 * literal occurrence of the claimed SCID (in `parameters.scid`, `state.id`'s
 * DID string, anywhere else it appears) with the placeholder — then the
 * recomputed hash must equal the claimed SCID. Matches reference
 * implementations' whole-document string-substitution approach rather than
 * walking each field individually, since the SCID can legitimately appear in
 * more than the two fields the spec calls out by name (e.g. `alsoKnownAs`). */
export function verifyScid(firstEntry: unknown): boolean {
  if (typeof firstEntry !== 'object' || firstEntry === null) return false
  const entry = firstEntry as Record<string, unknown>
  const parameters = entry.parameters as { scid?: unknown } | undefined
  const scid = parameters?.scid
  if (typeof scid !== 'string' || scid.length === 0) return false

  const { proof: _proof, ...rest } = entry
  const withPlaceholderVersionId = { ...rest, versionId: SCID_PLACEHOLDER }
  const json = JSON.stringify(withPlaceholderVersionId).split(scid).join(SCID_PLACEHOLDER)

  let preliminary: unknown
  try { preliminary = JSON.parse(json) } catch { return false }

  return generateScid(preliminary) === scid
}
