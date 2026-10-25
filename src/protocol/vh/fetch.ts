// Finding a did:vh log. A did:vh names no host, so the DID does not say where its log is: the caller is handed places to ask.
// Two kinds, both only *where to look* (the log proves itself by its SCID and signatures, never by who served it):
//   - locations: the web hosts the contact is known by (`alice.did.md`, from an address or from `alsoKnownAs`), whose log is at
//     `https://<host>/.well-known/did.jsonl`;
//   - watchers: services that hold logs by SCID (`GET <watcher>/log?scid=`), the operator's or the identity's own (`watchers`).
// The first copy that verifies for this DID wins; one that does not (another identity's, damaged) is passed over.
import { parseLog, type LogEntry } from './log.ts'
import { resolveVhEntries, type VhResolution } from './resolver.ts'
import { isDomainHost, isVhDid, parseVhDid } from './identifier.ts'
import { logUrlOf } from './src.ts'
import type { DidDocument } from './document.ts'
import { checkAndRemember, type VersionMemory } from '../freshness.ts'
import { checkCopies, LogForkedError, type Copy } from './copies.ts'

export interface VhLogSources {
  /** Places to ask for a log: a web location (`https://example.com/dids/issuer`, the `src` of didvh-spec) or a bare host (`alice.did.md`, from
   * an address), which is the web location `https://alice.did.md`. Each is read at its `did.jsonl` (src.ts). */
  locations?: readonly string[]
  /** Watcher base URLs, asked `GET /log?scid=<SCID>`. */
  watchers?: readonly string[]
  fetch?: typeof fetch
  /** Ask the watchers (the owner's, from the log, and these) for their copies and compare: a newer copy replaces this one, a fork is refused. */
  compareCopies?: boolean
}

async function textOf(url: string, fetchImpl: typeof fetch): Promise<string | undefined> {
  try {
    const response = await fetchImpl(url)
    return response.ok ? await response.text() : undefined
  } catch {
    return undefined
  }
}

/** The urls to ask, in order: the hosts the contact is known by, then the watchers. */
function candidateUrls(scid: string, sources: VhLogSources): string[] {
  const urls: string[] = []
  for (const place of sources.locations ?? []) {
    try { urls.push(logUrlOf(place.includes('://') ? place : `https://${place}`)) } catch { /* not a web location: never asked */ }
  }
  for (const watcher of sources.watchers ?? []) {
    try { urls.push(new URL(`/log?scid=${scid}`, watcher).href) } catch { /* not a URL */ }
  }
  return urls
}

/** Fetches and fully verifies the log of `did`; null when nobody asked has a log that verifies for it. A memory refuses a
 * stale or forked copy (freshness.ts) and remembers the newest one it accepts. */
export async function fetchVhResolution(did: string, sources: VhLogSources, memory?: VersionMemory): Promise<{ resolution: VhResolution; log: LogEntry[] } | null> {
  const { scid } = parseVhDid(did)
  const fetchImpl = sources.fetch ?? fetch
  for (const url of candidateUrls(scid, sources)) {
    const text = await textOf(url, fetchImpl)
    if (text === undefined) continue
    let log: LogEntry[]
    let resolution: VhResolution
    try {
      log = parseLog(text)
      resolution = resolveVhEntries(did, log)
    } catch {
      continue
    }
    if (sources.compareCopies) {
      // The owner's own list first, then the ones this client adds; the place this copy came from is not asked again.
      const skip = [new URL(url).origin]
      const ours = [...resolution.watchers, ...(sources.watchers ?? [])]
      const { copies, newest } = await cachedCheck(did, log, { watchers: ours, skip, fetch: fetchImpl })
      if (copies.some(copy => copy.status === 'forked')) throw new LogForkedError(did, copies)
      if (newest !== log) { log = [...newest]; resolution = resolveVhEntries(did, log) }
    }
    if (memory) await checkAndRemember(memory, did, log)
    return { resolution, log }
  }
  return null
}

// A check asks several servers, and a DID is resolved for every message: the result of a check is reused for a few minutes
// (the owner's `ttl` is guidance for how long a resolution may be cached, and is only an upper bound here).
const CHECK_TTL_MS = 5 * 60 * 1000
const checked = new Map<string, { at: number; versionId: string; result: { copies: Copy[]; newest: readonly LogEntry[] } }>()
async function cachedCheck(did: string, log: LogEntry[], sources: Parameters<typeof checkCopies>[2]) {
  const versionId = log[log.length - 1]!.versionId
  const known = checked.get(did)
  if (known && known.versionId === versionId && Date.now() - known.at < CHECK_TTL_MS) return known.result
  const result = await checkCopies(did, log, sources)
  checked.set(did, { at: Date.now(), versionId, result })
  return result
}
/** Forgets what was checked (tests, and a client that wants to look again). */
export function forgetCopyChecks(): void { checked.clear() }

/**
 * The did:vh published at a host (`alice.did.md`) when only the host is known (a typed alias, a login hint): the log is at
 * `https://<host>/.well-known/did.jsonl` and its first entry says which DID it is. It counts only if it verifies in full and its
 * current document names `did:web:<host>` as its place (the location rule a host enforces when it takes a log), so a host
 * cannot make another identity's log pass for the name it serves. null when there is no such log.
 */
export async function resolveVhByHost(host: string, options: { fetch?: typeof fetch; memory?: VersionMemory } = {}): Promise<{ did: string; document: DidDocument; entries: LogEntry[] } | null> {
  if (!isDomainHost(host.toLowerCase())) return null
  const text = await textOf(`https://${host.toLowerCase()}/.well-known/did.jsonl`, options.fetch ?? fetch)
  if (text === undefined) return null
  let entries: LogEntry[]
  let did: unknown
  try {
    entries = parseLog(text)
    did = (entries[0]?.state as { id?: unknown } | undefined)?.id
  } catch { return null }
  if (typeof did !== 'string' || !isVhDid(did)) return null
  let resolution: VhResolution
  try { resolution = resolveVhEntries(did, entries) } catch { return null }
  const document = resolution.doc
  if (!document || !document.alsoKnownAs.includes(`did:web:${host.toLowerCase()}`)) return null
  if (options.memory) await checkAndRemember(options.memory, did, entries)
  return { did, document, entries }
}
