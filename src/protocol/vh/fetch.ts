// Finding a did:vh log. A did:vh names no host, so the DID does not say where its log is: the caller is handed places to ask.
// Two kinds, both only *where to look* (the log proves itself by its SCID and signatures, never by who served it):
//   - locations: the web hosts the contact is known by (`alice.did.md`, from an address or from `alsoKnownAs`), whose log is at
//     `https://<host>/.well-known/did.jsonl`;
//   - watchers: services that hold logs by SCID (`GET <watcher>/log?scid=`), the operator's or the identity's own (`watchers`).
// The first copy that verifies for this DID wins; one that does not (another identity's, damaged) is passed over.
import { parseLog, type LogEntry } from '../webvh/log.ts'
import { resolveVhEntries, type VhResolution } from './resolver.ts'
import { parseVhDid } from './identifier.ts'
import { checkAndRemember, type VersionMemory } from '../freshness.ts'

export interface VhLogSources {
  /** Web hosts to ask for `https://<host>/.well-known/did.jsonl`, e.g. `alice.did.md`. */
  locations?: readonly string[]
  /** Watcher base URLs, asked `GET /log?scid=<SCID>`. */
  watchers?: readonly string[]
  fetch?: typeof fetch
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
  for (const host of sources.locations ?? []) urls.push(`https://${host}/.well-known/did.jsonl`)
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
    if (memory) await checkAndRemember(memory, did, log)
    return { resolution, log }
  }
  return null
}
