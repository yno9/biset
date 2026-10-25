// DID Log entry validation and JSONL decoding (didvh-spec: The VH-Log File; VH-Log: SCID and Entry Hash Generation and
// Verification). Read-only: this resolver never writes a log.
import { jcsMultihashBase58 } from './hash.ts'
import type { DataIntegrityProof } from './proof.ts'

/** @public Used by the test fixtures that build logs. */
export interface LogParameters {
  method?: string
  scid?: string
  updateKeys?: string[]
  nextKeyHashes?: string[]
  witness?: Record<string, unknown>
  watchers?: string[]
  deactivated?: boolean
  ttl?: number
}

export interface LogEntry {
  versionId: string
  versionTime: string
  parameters: LogParameters
  state: object
  proof: DataIntegrityProof[]
}

export function entryVersionNumber(versionId: string): number {
  const m = /^(\d+)-.+$/.exec(versionId)
  if (!m) throw new Error(`entryVersionNumber: malformed versionId "${versionId}"`)
  return Number(m[1])
}

function entryHashOf(versionId: string): string {
  const m = /^\d+-(.+)$/.exec(versionId)
  if (!m) throw new Error(`entryHashOf: malformed versionId "${versionId}"`)
  return m[1]!
}

/** Computes the entryHash for a new entry not yet given its final versionId.
 * `predecessorVersionId` is the SCID itself for the genesis entry, or the
 * full previous entry's versionId otherwise. @public Used by the test fixtures that build logs. */
export function generateEntryHash(predecessorVersionId: string, versionTime: string, parameters: LogParameters, state: object): string {
  return jcsMultihashBase58({ versionId: predecessorVersionId, versionTime, parameters, state })
}

/** Verifies one entry's versionId against a recomputed entryHash, given the
 * predecessor versionId (SCID for the first entry, the prior entry's full
 * versionId otherwise). */
export function verifyEntryHash(entry: Omit<LogEntry, 'proof'>, predecessorVersionId: string): boolean {
  const claimedHash = entryHashOf(entry.versionId)
  const recomputed = generateEntryHash(predecessorVersionId, entry.versionTime, entry.parameters, entry.state)
  return recomputed === claimedHash
}

const FUTURE_SKEW_MS = 5 * 60 * 1000 // reject a versionTime further ahead of "now" than this

export function isVersionTimeNotTooFarInFuture(versionTime: string, now = Date.now()): boolean {
  return Date.parse(versionTime) <= now + FUTURE_SKEW_MS
}

/** JSON Lines: one compact-JSON entry per line, matching what `.well-known/did.jsonl` serves. */
export function parseLog(jsonl: string): LogEntry[] {
  return jsonl.split('\n').map(l => l.trim()).filter(Boolean).map(l => JSON.parse(l) as LogEntry)
}

export function serializeLog(entries: LogEntry[]): string {
  return entries.map(e => JSON.stringify(e)).join('\n') + '\n'
}

/** The update keys in force right after the entry `versionId` -- the keys that were allowed to sign
 * on behalf of the DID at that generation (with pre-rotation they change with every entry, so the
 * current ones say nothing about an older generation). Undefined when the log has no such entry. */
export function updateKeysAtVersion(entries: readonly LogEntry[], versionId: string): string[] | undefined {
  let updateKeys: string[] = []
  for (const entry of entries) {
    updateKeys = entry.parameters.updateKeys ?? updateKeys
    if (entry.versionId === versionId) return updateKeys
  }
  return undefined
}
