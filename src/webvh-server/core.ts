// A minimal, standalone did:webvh v1.0 hosting server: the GET/PUT/POST
// did.jsonl contract and nothing else — no accounts, no authentication, no
// mediator, no relay. A did:webvh log is self-certifying (SCID + per-entry
// Data Integrity proofs), so this store cannot forge one, only withhold it —
// anyone can host any did:webvh identity that chooses to publish here,
// including a migrateWebvhLocation move (did/webvh/migrate.ts) landing from
// biset or from any other implementation.
//
// Deliberately independent of biset's account/relay/mediator concerns: this
// is what makes a server hosting THIS handler a valid did:webvh migration
// target without being biset at all — see PLAN.md's did:webvh migration
// section, 2026-08-16 addendum. biset's own anchor (anchor/server.ts) wraps
// this exact handler alongside its other routes (mediator, claim registry)
// rather than duplicating the log-storage logic.
import type { WebvhLogStore } from '../anchor/webvh-store.ts'
import { resolveEntries } from '../did/webvh/resolver.ts'
import { buildWebvhDid } from '../did/webvh/identifier.ts'
import type { LogEntry } from '../did/webvh/log.ts'

export const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
}

const text = (body: string, status: number) =>
  new Response(body + '\n', { status, headers: { ...CORS, 'Content-Type': 'text/plain; charset=utf-8' } })
const notFound = () => text('404 page not found', 404)
const serializeLines = (lines: string[]): string => lines.join('\n') + '\n'

const DEFAULT_MAX_LOG_BODY = 1 << 20 // 1MiB — one request's worth; POST sends only new entries
const DEFAULT_MAX_LOG_ENTRIES = 10_000
const DEFAULT_MAX_LOG_BYTES = 16 << 20 // 16MiB — total stored per identity

export interface WebvhHandlerOptions {
  /** First-path-segment names this handler refuses to serve/accept a
   * did.jsonl at — for a server that ALSO answers other routes on the same
   * origin (biset's anchor: everything under `/_anchor/*`), so a did:webvh
   * path can never collide with one of them. A standalone server with no
   * other routes on the same origin can leave this empty. */
  reservedFirstSegments?: readonly string[]
  /** Header carrying the intended domain when a reverse-proxy hop in front
   * of this process rewrites Host (biset's own anchor does — see
   * anchor/server.ts's note on why: a two-hop Caddy chain that needs a
   * fixed vhost-match Host along the way). Falls back to the Host header
   * when this option is unset or the header is absent, which is the right
   * default for a server sitting behind a normal TLS-terminating proxy
   * (Caddy/nginx) that passes Host straight through. */
  domainHeader?: string
  maxLogBodyBytes?: number
  maxLogEntries?: number
  maxLogBytes?: number
}

/** Builds the GET/PUT/POST /<name>/did.jsonl handler. Both GET and
 * write are open to anyone — no auth gate — the "gateway holds zero
 * authority" stance: this store enforces only that an update to an EXISTING
 * name extends its current log verbatim (append-only), and that the log
 * itself resolves (SCID/entryHash chain/versionTime monotonicity/every
 * entry's Data Integrity proof) before accepting a write — same checks
 * resolve() runs, so a wrongly-signed entry never lands in the first place
 * (once landed it can never be retracted — the log is append-only). A
 * first-ever write for a name is unrestricted: first-come, same as claiming
 * any name anywhere.
 *
 * One exception to append-only: a RECLAIM. A name that was moved away from
 * keeps its did.jsonl forever (this store never deletes on move — see
 * webvh-store.ts and the sweep in anchor/webvh-sweep.ts for the only thing
 * that ever does), so the same portable identity moving back to a name it
 * held before finds a stale, forked log already sitting there — appending
 * onto it produces a corrupt chain (a genesis entry landing where entry N+1
 * is expected), and it isn't a byte-prefix of the incoming log either, so
 * the ordinary extend-verbatim rule can't accept it. Found live 2026-08-18:
 * did:webvh:t.biset.md:5534testaa moving 5534 -> 5534testaa -> 5534test hit
 * exactly this, "versionId gap at entry 4". Detected by comparing the
 * incoming log's OWN scid (only ever present on a full log's first entry)
 * against the scid the stored log's first entry already carries: a match
 * requires having produced a validly-chained, validly-signed log from that
 * exact genesis (verified below by resolveEntries same as any other write),
 * which nobody but the true holder of that SCID's key material can do — so
 * treating a scid match as authorization to replace the stale log outright
 * costs no security the append-only rule was providing in the first place.
 * A scid MISMATCH against an existing log, conversely, now gets a clear
 * conflict response instead of silently falling into the append path and
 * failing with a confusing versionId-gap error. */
export function createWebvhHandler(store: WebvhLogStore, opts: WebvhHandlerOptions = {}): (req: Request, url: URL) => Promise<Response> {
  const reserved = new Set(opts.reservedFirstSegments ?? [])
  const maxBody = opts.maxLogBodyBytes ?? DEFAULT_MAX_LOG_BODY
  const maxEntries = opts.maxLogEntries ?? DEFAULT_MAX_LOG_ENTRIES
  const maxBytes = opts.maxLogBytes ?? DEFAULT_MAX_LOG_BYTES

  return async function handleWebvh(req: Request, url: URL): Promise<Response> {
    const m = /^\/([^/]+)\/did\.jsonl$/.exec(url.pathname)
    if (!m) return notFound()
    const name = m[1]!
    if (reserved.has(name)) return notFound()
    const domain = ((opts.domainHeader && req.headers.get(opts.domainHeader)) ?? req.headers.get('host') ?? '').split(':')[0]
    if (!domain) return text('missing host', 400)

    switch (req.method) {
      case 'GET': {
        const jsonl = store.read(domain, name)
        if (!jsonl) return notFound()
        return new Response(jsonl, { status: 200, headers: { ...CORS, 'Content-Type': 'text/jsonl' } })
      }
      case 'POST':
      case 'PUT': {
        const body = await req.text()
        if (body.length > maxBody) return text('log too large', 400)
        const lines = body.split('\n').map(l => l.trim()).filter(Boolean)
        if (lines.length === 0) return text('empty log', 400)
        let entries: LogEntry[]
        try {
          entries = lines.map(l => JSON.parse(l) as LogEntry)
        } catch {
          return text('invalid JSONL', 400)
        }
        // POST carries ONLY the new entries; the stored log is the prefix.
        // PUT carries the whole thing. Distinguishing matters past
        // convenience: with PUT alone, a request grows with the log's whole
        // history, so a long-lived identity eventually cannot write at all —
        // and the write it would need in order to shrink is itself blocked
        // by the same limit (found live on biset's own anchor, PLAN.md /
        // publish.ts's putLog note).
        const existing = store.read(domain, name)
        const existingLines = existing ? existing.split('\n').map(l => l.trim()).filter(Boolean) : []
        let existingScid: string | undefined
        if (existingLines[0]) {
          try { existingScid = (JSON.parse(existingLines[0]) as LogEntry).parameters?.scid } catch { /* corrupt — treated as no readable scid below */ }
        }
        const incomingScid = entries[0]?.parameters?.scid // only ever set when this request carries a full log from its own genesis
        const isReclaim = existingLines.length > 0 && incomingScid !== undefined && incomingScid === existingScid
        if (existingLines.length > 0 && incomingScid !== undefined && !isReclaim) {
          return text('location already in use by a different identity', 409)
        }
        const isAppend = !isReclaim && req.method === 'POST' && existingLines.length > 0
        const allLines = isAppend ? [...existingLines, ...lines] : lines
        if (!isReclaim && !isAppend && existing) {
          const extendsExisting = lines.length >= existingLines.length && existingLines.every((l, i) => l === lines[i])
          if (!extendsExisting) return text('update must extend the existing log, not replace it', 409)
        }
        if (allLines.length > maxEntries) {
          return text(`log would exceed ${maxEntries} entries for this name`, 507)
        }
        const totalBytes = allLines.reduce((n, l) => n + l.length + 1, 0)
        if (totalBytes > maxBytes) {
          return text(`log would exceed ${maxBytes} bytes for this name`, 507)
        }
        let allEntries: LogEntry[]
        try {
          allEntries = isAppend ? [...existingLines.map(l => JSON.parse(l) as LogEntry), ...entries] : entries
        } catch {
          return text('stored log is not valid JSONL', 500)
        }
        // Verified against the DID of the LOCATION being written to (this
        // domain, this name, the log's own SCID) — not against whatever
        // `state.id` the genesis entry happens to carry. That distinction is
        // what makes a migrateWebvhLocation move (which writes the SAME log
        // to a NEW location, whose genesis names the OLD one) land correctly
        // here while still rejecting an attempt to park an unrelated valid
        // log under a name it doesn't belong to.
        const scid = allEntries[0]?.parameters?.scid
        if (!scid) return text('first entry parameters.scid missing', 400)
        const locationDid = buildWebvhDid({ scid, domain, pathSegments: [name] })
        try {
          resolveEntries(locationDid, allEntries)
        } catch (e) {
          return text(`invalid did:webvh log: ${e instanceof Error ? e.message : String(e)}`, 400)
        }
        store.write(domain, name, serializeLines(allLines))
        return new Response(null, { status: 204, headers: CORS })
      }
      default:
        return text('method not allowed', 405)
    }
  }
}
