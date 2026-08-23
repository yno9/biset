// DID Log entry validation and JSONL decoding (DIDWEBVHFEAT.md §4-5,
// did:webvh v1.0 spec "The DID Log File" / "Entry Hash Generation and
// Verification"). Read-only: this resolver never writes a log.
import { jcsMultihashBase58 } from './hash.ts'
import type { DataIntegrityProof } from './proof.ts'

export interface LogParameters {
  method?: string
  scid?: string
  updateKeys?: string[]
  nextKeyHashes?: string[]
  portable?: boolean
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
 * full previous entry's versionId otherwise. */
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

/** did:webvh's parameter-inheritance rule (DIDWEBVHFEAT.md §5): a field
 * absent from a non-genesis entry's `parameters` keeps the previous entry's
 * resolved value. `scid`/`method` are deliberately NOT defaulted here —
 * `scid` is first-entry-only (never inherited) and `method` downgrade
 * checking is the resolver's job, not this mechanical fill-in. */
export function resolveParameters(previous: LogParameters, current: LogParameters): LogParameters {
  return {
    method: current.method ?? previous.method,
    updateKeys: current.updateKeys ?? previous.updateKeys,
    nextKeyHashes: current.nextKeyHashes ?? previous.nextKeyHashes ?? [],
    portable: current.portable ?? previous.portable ?? false,
    witness: current.witness ?? previous.witness ?? {},
    watchers: current.watchers ?? previous.watchers ?? [],
    deactivated: current.deactivated ?? previous.deactivated ?? false,
    ttl: current.ttl ?? previous.ttl ?? 3600,
  }
}

const FUTURE_SKEW_MS = 5 * 60 * 1000 // spec: reject a versionTime further ahead of "now" than this

export function isVersionTimeMonotonic(previousVersionTime: string, currentVersionTime: string): boolean {
  return Date.parse(currentVersionTime) > Date.parse(previousVersionTime)
}

export function isVersionTimeNotTooFarInFuture(versionTime: string, now = Date.now()): boolean {
  return Date.parse(versionTime) <= now + FUTURE_SKEW_MS
}

/** JSON Lines: one compact-JSON entry per line, matching what `.well-known/did.jsonl` / anchor's `.../dids/{username}/did.jsonl` serve. */
export function parseLog(jsonl: string): LogEntry[] {
  return jsonl.split('\n').map(l => l.trim()).filter(Boolean).map(l => JSON.parse(l) as LogEntry)
}

export function serializeLog(entries: LogEntry[]): string {
  return entries.map(e => JSON.stringify(e)).join('\n') + '\n'
}
