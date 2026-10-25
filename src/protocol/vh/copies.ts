// Comparing a log with other copies of it (didvh-spec: Log Freshness and Duplicity; the resolution options checkWatchers and
// extraWatchers). A log verifies by its SCID, hash chain and signatures, and none of that says it is the *newest* log, or the
// only continuation of its history: a host can serve a copy from before a key rotation, and an owner can show two parties two
// different continuations. Both verify. A watcher that holds the log is another place to ask.
//
// Log B extends log A when it holds every entry of A at the same position with the same versionId (each versionId carries a
// hash chained to its predecessor, so one position is enough). If neither extends the other, the owner is duplicitous.
import { parseLog, type LogEntry } from './log.ts'
import { resolveVhEntries } from './resolver.ts'
import { parseVhDid } from './identifier.ts'

type CopyStatus = 'same' | 'ahead' | 'behind' | 'forked' | 'notFound' | 'unavailable' | 'invalid'

export interface Copy {
  source: string
  status: CopyStatus
  versionNumber?: number
  /** For a fork: the first version at which the two histories differ, and the versionId each has there (the report the specification asks for). */
  forkedAt?: number
  versionId?: string
  ownVersionId?: string
}

/** The owner showed two continuations of one history: nothing after the last entry they share can be relied on. */
export class LogForkedError extends Error {
  readonly copies: Copy[]
  constructor(did: string, copies: Copy[]) {
    const fork = copies.find(copy => copy.status === 'forked')
    super(`${did} has two continuations of one history${fork?.forkedAt ? ` (they differ at version ${fork.forkedAt}: ${fork.ownVersionId} here, ${fork.versionId} at ${fork.source})` : ''}.`)
    this.name = 'LogForkedError'
    this.copies = copies
  }
}

/** Where `other` stands against `own`, by versionId alone (both must already be verified). */
export function compareLogs(own: readonly { versionId: string }[], other: readonly { versionId: string }[]): { status: 'same' | 'ahead' | 'behind' | 'forked'; forkedAt?: number } {
  const common = Math.min(own.length, other.length)
  for (let index = 0; index < common; index += 1) if (own[index]!.versionId !== other[index]!.versionId) return { status: 'forked', forkedAt: index + 1 }
  if (other.length === own.length) return { status: 'same' }
  return { status: other.length > own.length ? 'ahead' : 'behind' }
}

export interface CopySources {
  /** Watcher base URLs: the ones the owner lists in the log, and the ones this client adds. Only https is asked. */
  watchers: readonly string[]
  fetch?: typeof fetch
  /** Where `own` came from, so it is not asked again. */
  skip?: readonly string[]
  timeoutMs?: number
  maxBytes?: number
}

/** Asks each watcher for its copy of `did` (`GET <watcher>/log?scid=`), verifies it, and compares it with `own`. */
export async function checkCopies(did: string, own: readonly LogEntry[], sources: CopySources): Promise<{ copies: Copy[]; newest: readonly LogEntry[] }> {
  const { scid } = parseVhDid(did)
  const fetchImpl = sources.fetch ?? fetch
  const maxBytes = sources.maxBytes ?? 4 * 1024 * 1024
  const asked = new Set<string>()
  const copies: Copy[] = []
  let newest: readonly LogEntry[] = own
  for (const watcher of sources.watchers) {
    let url: URL
    try { url = new URL(`/log?scid=${scid}`, watcher) } catch { continue }
    if (url.protocol !== 'https:' || asked.has(url.origin) || sources.skip?.includes(url.origin)) continue
    asked.add(url.origin)
    const source = url.origin
    let text: string
    try {
      const response = await fetchImpl(url.href, { cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(sources.timeoutMs ?? 5000) })
      if (response.status === 404) { copies.push({ source, status: 'notFound' }); continue }
      if (!response.ok) { copies.push({ source, status: 'unavailable' }); continue }
      text = await response.text()
      if (text.length > maxBytes) { copies.push({ source, status: 'invalid' }); continue }
    } catch { copies.push({ source, status: 'unavailable' }); continue }
    let log: LogEntry[]
    try { log = parseLog(text); resolveVhEntries(did, log) } catch { copies.push({ source, status: 'invalid' }); continue }
    const standing = compareLogs(own, log)
    copies.push({
      source, status: standing.status, versionNumber: log.length,
      ...(standing.forkedAt ? { forkedAt: standing.forkedAt, versionId: log[standing.forkedAt - 1]!.versionId, ownVersionId: own[standing.forkedAt - 1]!.versionId } : {}),
    })
    if (standing.status === 'ahead' && log.length > newest.length) newest = log
  }
  return { copies, newest }
}
