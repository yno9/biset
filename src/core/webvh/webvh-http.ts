// GET/PUT/POST .well-known/did.jsonl -- did:webvh v1.0 log hosting for the
// subdomain-per-identity scheme (identity/webvh/identifier.ts:
// did:webvh:{scid}:{domain}, no pathSegments -- one identity per subdomain,
// so `domain` alone is the storage key, unlike the pre-Vault-Core anchor's
// path-segment-per-username scheme this is ported from
// (.claude/worktrees/loving-pike-d5f3df/src/webvh-server/core.ts). Same
// verification and append/reclaim rules; only the URL shape and DID
// construction changed.
import { buildWebvhDid } from '../../identity/webvh/identifier.ts'
import { parseLog, serializeLog, type LogEntry } from '../../identity/webvh/log.ts'
import { resolveEntries } from '../../identity/webvh/resolver.ts'
import type { WebvhLogStore } from './webvh-store.ts'

export const WEBVH_CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
}

const text = (body: string, status: number) =>
  new Response(body + '\n', { status, headers: { ...WEBVH_CORS, 'Content-Type': 'text/plain; charset=utf-8' } })
const notFound = () => text('404 page not found', 404)

const DEFAULT_MAX_LOG_BODY = 1 << 20 // 1MiB -- one request's worth; POST sends only new entries
const DEFAULT_MAX_LOG_ENTRIES = 10_000
const DEFAULT_MAX_LOG_BYTES = 16 << 20 // 16MiB -- total stored per identity

export interface WebvhHttpOptions {
  /** Header carrying the intended domain when a reverse-proxy hop in front
   * of this process rewrites Host (Caddy's biset.md/*.biset.md blocks set
   * `header_up X-Biset-Domain {host}`). Falls back to Host when unset or
   * absent. */
  domainHeader?: string
  maxLogBodyBytes?: number
  maxLogEntries?: number
  maxLogBytes?: number
}

const WELL_KNOWN_PATH = '/.well-known/did.jsonl'

/** Builds the GET/PUT/POST /.well-known/did.jsonl handler. Both GET and
 * write are open to anyone -- no auth gate, the "gateway holds zero
 * authority" stance: a did:webvh log is self-certifying (SCID + per-entry
 * Data Integrity proofs), so this store cannot forge one, only withhold it.
 * An update to an EXISTING domain must extend its current log verbatim
 * (append-only) and the log itself must resolve before being accepted --
 * same checks resolve() runs, so a wrongly-signed entry never lands. A
 * first-ever write for a domain is unrestricted, first-come.
 *
 * One exception to append-only: a RECLAIM, when the incoming log's OWN scid
 * (only ever present on a full log's first entry) matches the scid the
 * stored log's first entry already carries -- the same portable identity
 * moving back to a subdomain it held before. See the ported original
 * (webvh-server/core.ts) for the full incident history behind this rule. */
export function createWebvhHttpHandler(store: WebvhLogStore, opts: WebvhHttpOptions = {}): (request: Request) => Promise<Response> {
  const maxBody = opts.maxLogBodyBytes ?? DEFAULT_MAX_LOG_BODY
  const maxEntries = opts.maxLogEntries ?? DEFAULT_MAX_LOG_ENTRIES
  const maxBytes = opts.maxLogBytes ?? DEFAULT_MAX_LOG_BYTES

  return async function handleWebvh(request: Request): Promise<Response> {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: WEBVH_CORS })
    const url = new URL(request.url)
    if (url.pathname !== WELL_KNOWN_PATH) return notFound()
    const domain = ((opts.domainHeader && request.headers.get(opts.domainHeader)) ?? request.headers.get('host') ?? '').split(':')[0]
    if (!domain) return text('missing host', 400)

    switch (request.method) {
      case 'GET': {
        const jsonl = store.read(domain)
        if (!jsonl) return notFound()
        return new Response(jsonl, { status: 200, headers: { ...WEBVH_CORS, 'Content-Type': 'text/jsonl' } })
      }
      case 'POST':
      case 'PUT': {
        const body = await request.text()
        if (body.length > maxBody) return text('log too large', 400)
        let entries: LogEntry[]
        try {
          entries = parseLog(body)
        } catch {
          return text('invalid JSONL', 400)
        }
        if (entries.length === 0) return text('empty log', 400)

        const existing = store.read(domain)
        let existingEntries: LogEntry[] = []
        try {
          existingEntries = existing ? parseLog(existing) : []
        } catch {
          existingEntries = []
        }
        const existingScid = existingEntries[0]?.parameters?.scid
        // Only ever set on a full log's own genesis entry.
        const incomingScid = entries[0]?.parameters?.scid
        const isReclaim = existingEntries.length > 0 && incomingScid !== undefined && incomingScid === existingScid
        if (existingEntries.length > 0 && incomingScid !== undefined && !isReclaim) {
          return text('location already in use by a different identity', 409)
        }
        const isAppend = !isReclaim && request.method === 'POST' && existingEntries.length > 0
        const allEntries = isAppend ? [...existingEntries, ...entries] : entries
        if (!isReclaim && !isAppend && existing) {
          const serializedIncoming = entries.map(e => JSON.stringify(e))
          const serializedExisting = existingEntries.map(e => JSON.stringify(e))
          const extendsExisting = serializedIncoming.length >= serializedExisting.length
            && serializedExisting.every((l, i) => l === serializedIncoming[i])
          if (!extendsExisting) return text('update must extend the existing log, not replace it', 409)
        }
        if (allEntries.length > maxEntries) {
          return text(`log would exceed ${maxEntries} entries for this domain`, 507)
        }
        const totalBytes = allEntries.reduce((n, e) => n + JSON.stringify(e).length + 1, 0)
        if (totalBytes > maxBytes) {
          return text(`log would exceed ${maxBytes} bytes for this domain`, 507)
        }

        // Verified against the DID of the LOCATION being written to (this
        // domain, the log's own SCID) -- not against whatever state.id the
        // genesis entry happens to carry, so a migrateWebvhLocation move
        // (same log, new location) lands correctly while an unrelated valid
        // log still can't be parked under a domain it doesn't belong to.
        const scid = allEntries[0]?.parameters?.scid
        if (!scid) return text('first entry parameters.scid missing', 400)
        const locationDid = buildWebvhDid({ scid, domain })
        try {
          resolveEntries(locationDid, allEntries)
        } catch (e) {
          return text(`invalid did:webvh log: ${e instanceof Error ? e.message : String(e)}`, 400)
        }
        store.write(domain, serializeLog(allEntries))
        return new Response(null, { status: 204, headers: WEBVH_CORS })
      }
      default:
        return text('method not allowed', 405)
    }
  }
}
