// Shared log I/O — the GET/append-or-PUT primitives every write operation
// (device key registration, key rotation, deactivate...) builds on.
import { didToHttpsUrl } from './identifier.ts'
import { parseLog, resolveParameters, serializeLog, type LogEntry, type LogParameters } from './log.ts'

// Strictly increasing even across back-to-back calls within the same
// process — two writes issued within the same second would otherwise
// produce an identical versionTime, which resolver.ts's monotonicity check
// rejects outright. Whole-seconds precision, NOT milliseconds: interop
// verifiers following did:webvh v1.0's reference behavior re-serialize
// versionTime at second precision before re-hashing it as part of proof
// verification, so a proof signed over millisecond precision can fail to
// re-hash to the same bytes a spec-compliant verifier computes.
let lastIssuedSec = 0
export function nowVersionTime(): string {
  const sec = Math.max(Math.floor(Date.now() / 1000), lastIssuedSec + 1)
  lastIssuedSec = sec
  return new Date(sec * 1000).toISOString().replace('.000Z', 'Z')
}

/** Fetches the current log — the shared first half of every update.
 *
 * `last.parameters` is the FULLY RESOLVED value (chained through every entry
 * via `resolveParameters`), not the raw last entry's own `parameters` — a
 * non-genesis entry legitimately omits any field unchanged from before, so
 * the raw entry alone can't answer "what are the CURRENT updateKeys" once
 * any update has gone through. `entries` stays the raw array (what `putLog`
 * re-serializes); only the `last` handed back for callers to READ from is
 * resolved. */
export async function fetchCurrentLog(did: string, fetchImpl: typeof fetch = fetch): Promise<{ url: string; entries: LogEntry[]; last: LogEntry }> {
  const url = didToHttpsUrl(did)
  const response = await fetchImpl(url)
  if (!response.ok) throw new Error(`fetchCurrentLog: GET failed with HTTP ${response.status}`)
  const entries = parseLog(await response.text())
  const rawLast = entries[entries.length - 1]
  if (!rawLast) throw new Error('fetchCurrentLog: log is empty')
  let resolved: LogParameters = {}
  for (const entry of entries) resolved = resolveParameters(resolved, entry.parameters)
  const last: LogEntry = { ...rawLast, parameters: resolved }
  return { url, entries, last }
}

/** Write the log, sending only what is NEW: `newEntries` alone goes up as a
 * POST for an anchor that supports appending, falling back to the whole-log
 * PUT when it does not (404/405). Re-uploading the entire history on every
 * update would make each request grow with it — append lets it stay one
 * entry's worth regardless of how long the log has gotten. */
export async function putLog(url: string, entries: LogEntry[], newEntries?: LogEntry[], fetchImpl: typeof fetch = fetch): Promise<void> {
  const appended = newEntries ?? entries
  const response = await fetchImpl(url, { method: 'POST', headers: { 'Content-Type': 'text/jsonl' }, body: serializeLog(appended) })
  if (response.ok) return
  if (response.status !== 404 && response.status !== 405) {
    throw new Error(`putLog: POST failed with HTTP ${response.status} ${await response.text().catch(() => '')}`)
  }
  const full = await fetchImpl(url, { method: 'PUT', headers: { 'Content-Type': 'text/jsonl' }, body: serializeLog(entries) })
  if (!full.ok) throw new Error(`putLog: PUT failed with HTTP ${full.status} ${await full.text().catch(() => '')}`)
}
