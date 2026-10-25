// Reading a DID's log fresh: past the host's CDN.
import { fetchDidLog } from '../../protocol/did-resolve.ts'
import type { LogEntry } from '../../protocol/vh/log.ts'

/** A `fetch` that cannot be answered from a cache: a unique query string makes the URL a different
 * cache key for the host's CDN as well (the host serves public reads with `s-maxage=30` and does not
 * purge on write), and `no-store` skips the browser's. */
export function freshFetch(fetchImpl: typeof fetch = fetch): typeof fetch {
  return ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
    url.searchParams.set('_', `${Date.now()}${Math.random().toString(36).slice(2, 8)}`)
    return fetchImpl(url.toString(), { ...init, cache: 'no-store' })
  }) as typeof fetch
}

/** The whole verified log of `did` and its latest entry, read fresh. Throws when nobody the app asks has it. */
export async function fetchCurrentLog(did: string, fetchImpl: typeof fetch = fetch): Promise<{ entries: LogEntry[]; last: LogEntry }> {
  const found = await fetchDidLog(did, { fetch: freshFetch(fetchImpl) })
  const last = found?.entries.at(-1)
  if (!found || !last) throw new Error(`fetchCurrentLog: no log was found for ${did}`)
  return { entries: found.entries, last }
}
