// Shared log I/O — the GET/append-or-PUT primitives every write operation
// (content update, key rotation, deactivate, location migration) builds on.
// Split out of publish.ts so migrate.ts can use them without a circular
// import (publish.ts's moveDidToNewDomain now itself calls into migrate.ts).
import { didToHttpsUrl } from './identifier.ts'
import { parseLog, resolveParameters, serializeLog, type LogEntry, type LogParameters } from './log.ts'

// Strictly increasing even across back-to-back calls within the same
// process (found live in testing: two updates issued within the same
// second produced an identical versionTime, which resolver.ts's
// monotonicity check then rejects outright — same failure shape
// dht/resolver.ts's nextSafeSeq exists to prevent for BEP44 seq). The +1s
// bump (not wall-clock waiting) covers back-to-back calls without slowing
// anything down — this is a monotonic counter, not a claim about real
// elapsed time, same reasoning dht's seq numbers already lean on.
//
// Whole-seconds precision, NOT milliseconds (2026-07-28, corrected after an
// interop check against didwebvh-rs, the DIF reference implementation, via
// its resolve_file() test entrypoint): didwebvh-rs re-serializes versionTime
// through `DateTime<FixedOffset>` + `to_rfc3339_opts(SecondsFormat::Secs, true)`
// before re-hashing it as part of proof verification (log_entry/mod.rs's
// format_version_time) — millisecond precision survives parsing but is
// always DROPPED on that re-serialize, so a proof signed over a
// millisecond-precision versionTime can never re-hash to the same bytes a
// spec-compliant verifier computes. did:webvh v1.0 itself only requires
// ISO8601 and doesn't forbid fractional seconds, but this asymmetry (kept
// by the signer, discarded by at least this verifier) makes millisecond
// precision a real interop trap in practice, not just a style choice.
let lastIssuedSec = 0
export function nowVersionTime(): string {
  const sec = Math.max(Math.floor(Date.now() / 1000), lastIssuedSec + 1)
  lastIssuedSec = sec
  return new Date(sec * 1000).toISOString().replace('.000Z', 'Z')
}

/** Fetches the current log — the shared first half of every update
 * (content-only, key rotation, deactivate, migrate...).
 *
 * `last.parameters` is the FULLY RESOLVED value (chained through every entry
 * via resolveParameters), not the raw last entry's own `parameters` — a
 * non-genesis entry legitimately omits any field unchanged from before
 * (log.ts's parametersToWrite, the did:webvh v1.0 inheritance rule), so the
 * raw entry alone can't answer "what are the CURRENT updateKeys" the moment
 * any update has ever gone through. `entries` stays the raw array (what
 * putLog re-serializes) — only the `last` handed back for callers to READ
 * from is resolved. */
export async function fetchCurrentLog(did: string): Promise<{ url: string; entries: LogEntry[]; last: LogEntry }> {
  const url = didToHttpsUrl(did)
  const resp = await fetch(url)
  if (!resp.ok) throw new Error(`fetchCurrentLog: GET failed with HTTP ${resp.status}`)
  const entries = parseLog(await resp.text())
  const rawLast = entries[entries.length - 1]
  if (!rawLast) throw new Error('fetchCurrentLog: log is empty')
  let resolved: LogParameters = {}
  for (const entry of entries) resolved = resolveParameters(resolved, entry.parameters)
  const last: LogEntry = { ...rawLast, parameters: resolved }
  return { url, entries, last }
}

/** Write the log, sending only what is NEW.
 *
 * A did:webvh log is append-only and every entry embeds the whole document, so
 * it grows without bound — and re-uploading all of it on every update makes
 * the request grow with the history. That is not merely wasteful, it deadlocks:
 * y@biset.md (2026-08-13) crossed the server's 1MiB body limit and could no
 * longer publish ANYTHING, including the update that would have shrunk the
 * document. Every route out required an append, and the append was the thing
 * that no longer fit.
 *
 * `newEntries` alone goes up as a POST, which the store splices onto what it
 * holds — it already required an update to extend the existing log verbatim,
 * so it was always the one that knew the prefix. The body is then one entry's
 * worth regardless of how long the history is.
 *
 * Falls back to the whole-log PUT when the store does not answer POST (405/404
 * from an anchor that predates this), so a client can talk to either. */
export async function putLog(url: string, entries: LogEntry[], newEntries?: LogEntry[]): Promise<void> {
  const appended = newEntries ?? entries
  const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'text/jsonl' }, body: serializeLog(appended) })
  if (resp.ok) return
  if (resp.status !== 404 && resp.status !== 405) {
    throw new Error(`putLog: POST failed with HTTP ${resp.status} ${await resp.text().catch(() => '')}`)
  }
  const full = await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'text/jsonl' }, body: serializeLog(entries) })
  if (!full.ok) throw new Error(`putLog: PUT failed with HTTP ${full.status} ${await full.text().catch(() => '')}`)
}
