// GET/PUT .well-known/did.json -- did:web mirror hosting (identity/web/
// mirror.ts). No PUT auth gate of its own: instead of verifying a signature
// (buildDidWebMirrorDocument's output carries none -- it is a plain string
// substitution of an already-resolved did:webvh state, not a fresh signed
// document), this validates that the PUT body is EXACTLY what
// buildDidWebMirrorDocument produces from the domain's own current
// did:webvh state (read from the same-process WebvhLogStore, already
// resolved+verified by resolveEntries) -- so a write can only ever mirror
// what the domain's real did:webvh log already says, never anything else.
import { buildDidWebMirrorDocument } from '../../identity/web/mirror.ts'
import type { SignedWebvhState } from '../../identity/webvh/document.ts'
import { buildWebvhDid } from '../../identity/webvh/identifier.ts'
import { parseLog } from '../../identity/webvh/log.ts'
import { resolveEntries } from '../../identity/webvh/resolver.ts'
import { canonicalJson, type CanonicalValue } from '../../protocol/canonical.ts'
import type { DidWebStore } from './did-web-store.ts'
import type { WebvhLogStore } from './webvh-store.ts'
import { WEBVH_CORS } from './webvh-http.ts'

const text = (body: string, status: number) =>
  new Response(body + '\n', { status, headers: { ...WEBVH_CORS, 'Content-Type': 'text/plain; charset=utf-8' } })
const notFound = () => text('404 page not found', 404)

const MAX_BODY = 1 << 16 // 64KiB -- generous for a did document with a handful of keys
const WELL_KNOWN_PATH = '/.well-known/did.json'

export interface DidWebHttpOptions {
  domainHeader?: string
}

export function createDidWebHttpHandler(webStore: DidWebStore, webvhStore: WebvhLogStore, opts: DidWebHttpOptions = {}): (request: Request) => Promise<Response> {
  return async function handleDidWeb(request: Request): Promise<Response> {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: WEBVH_CORS })
    const url = new URL(request.url)
    if (url.pathname !== WELL_KNOWN_PATH) return notFound()
    const domain = ((opts.domainHeader && request.headers.get(opts.domainHeader)) ?? request.headers.get('host') ?? '').split(':')[0]
    if (!domain) return text('missing host', 400)

    switch (request.method) {
      case 'GET': {
        const stored = webStore.read(domain)
        if (!stored) return notFound()
        return new Response(stored, { status: 200, headers: { ...WEBVH_CORS, 'Content-Type': 'application/json' } })
      }
      case 'PUT': {
        const body = await request.text()
        if (body.length > MAX_BODY) return text('document too large', 400)
        let parsedBody: unknown
        try {
          parsedBody = JSON.parse(body)
        } catch {
          return text('invalid JSON', 400)
        }
        const webvhLog = webvhStore.read(domain)
        if (!webvhLog) return text('no did:webvh identity at this domain', 404)
        let entries
        try {
          entries = parseLog(webvhLog)
        } catch {
          return text('stored did:webvh log is not valid JSONL', 500)
        }
        const scid = entries[0]?.parameters?.scid
        if (!scid) return text('stored did:webvh log has no scid', 500)
        const webvhDid = buildWebvhDid({ scid, domain })
        let currentState
        try {
          currentState = resolveEntries(webvhDid, entries)
        } catch (e) {
          return text(`stored did:webvh log does not resolve: ${e instanceof Error ? e.message : String(e)}`, 500)
        }
        if (!currentState) return text('did:webvh identity at this domain is deactivated', 404)
        // resolveEntries's return value is a NORMALIZED WebvhDidDocument (it
        // always adds alsoKnownAs, for one) -- what a real client actually
        // mirrors is the log's last entry's raw, unnormalized state
        // (create-genesis.ts passes `real.state` straight to
        // syncDidWebMirror, never resolveEntries's reconstruction), so that
        // raw state is what the comparison below has to match against.
        const rawState = entries[entries.length - 1]!.state as SignedWebvhState
        const expected = buildDidWebMirrorDocument(webvhDid, domain, rawState)
        // Canonical (key-order-independent) comparison: buildDidWebMirrorDocument
        // preserves whatever property order the log's stored state happens to
        // have, which need not match resolveEntries's own reconstructed order.
        const expectedCanonical = canonicalJson(expected as unknown as CanonicalValue)
        let bodyCanonical: string
        try {
          bodyCanonical = canonicalJson(parsedBody as CanonicalValue)
        } catch {
          return text('invalid document', 400)
        }
        if (bodyCanonical !== expectedCanonical) {
          return text('did:web mirror must exactly match the domain\'s current did:webvh state', 403)
        }
        webStore.write(domain, expectedCanonical)
        return new Response(null, { status: 204, headers: WEBVH_CORS })
      }
      default:
        return text('method not allowed', 405)
    }
  }
}
