// GET/PUT .well-known/routing.json -- routing.json hosting for the
// subdomain-per-identity scheme, alongside webvh-http.ts's did.jsonl.
//
// Unlike did.jsonl (self-certifying: SCID + per-entry Data Integrity
// proofs, so the "gateway holds zero authority" GET/write-both-open stance
// applies), routing.json's own content carries no hash chain -- without
// SOME check here, an open PUT would let any third party redirect another
// identity's DIDComm delivery or plant a fake device key. The check is a
// DataIntegrityProof (identity/webvh/proof.ts, same cryptosuite a did:webvh
// log entry signs with) over the whole document, verified against the
// domain's did:webvh log's CURRENT updateKeys -- read directly from the
// same-process WebvhLogStore (already verified by resolveEntries), no HTTP
// round trip, same pattern did-web-http.ts uses for its own PUT check.
import { decodeMultikey } from '../../identity/webvh/multikey.ts'
import { parseLog, resolveParameters, type LogParameters } from '../../identity/webvh/log.ts'
import { verifyProof, type DataIntegrityProof } from '../../identity/webvh/proof.ts'
import type { RoutingDocStore } from './routing-store.ts'
import type { WebvhLogStore } from './webvh-store.ts'
import { WEBVH_CORS } from './webvh-http.ts'

const text = (body: string, status: number) =>
  new Response(body + '\n', { status, headers: { ...WEBVH_CORS, 'Content-Type': 'text/plain; charset=utf-8' } })
const notFound = () => text('404 page not found', 404)

const MAX_BODY = 1 << 20 // 1MiB -- generous for a handful of keyAgreement entries + one service entry
const WELL_KNOWN_PATH = '/.well-known/routing.json'

export interface RoutingHttpOptions {
  domainHeader?: string
}

function currentUpdateKeys(webvhLog: string): string[] {
  const entries = parseLog(webvhLog)
  let resolved: LogParameters = {}
  for (const entry of entries) resolved = resolveParameters(resolved, entry.parameters)
  return resolved.updateKeys ?? []
}

export function createRoutingHttpHandler(routingStore: RoutingDocStore, webvhStore: WebvhLogStore, opts: RoutingHttpOptions = {}): (request: Request) => Promise<Response> {
  return async function handleRouting(request: Request): Promise<Response> {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: WEBVH_CORS })
    const url = new URL(request.url)
    if (url.pathname !== WELL_KNOWN_PATH) return notFound()
    const domain = ((opts.domainHeader && request.headers.get(opts.domainHeader)) ?? request.headers.get('host') ?? '').split(':')[0]
    if (!domain) return text('missing host', 400)

    switch (request.method) {
      case 'GET': {
        const stored = routingStore.read(domain)
        if (!stored) return notFound()
        return new Response(stored, { status: 200, headers: { ...WEBVH_CORS, 'Content-Type': 'application/json' } })
      }
      case 'PUT': {
        const body = await request.text()
        if (body.length > MAX_BODY) return text('document too large', 400)
        let parsed: unknown
        try {
          parsed = JSON.parse(body)
        } catch {
          return text('invalid JSON', 400)
        }
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return text('invalid document', 400)
        const { proof, ...doc } = parsed as Record<string, unknown> & { proof?: DataIntegrityProof }
        if (!proof || typeof proof !== 'object') return text('missing proof', 400)

        const webvhLog = webvhStore.read(domain)
        if (!webvhLog) return text('no did:webvh identity at this domain', 404)
        let updateKeys: string[]
        try {
          updateKeys = currentUpdateKeys(webvhLog)
        } catch {
          return text('stored did:webvh log is not valid JSONL', 500)
        }
        if (updateKeys.length === 0) return text('did:webvh identity at this domain has no updateKeys', 500)

        const authorized = updateKeys.some(updateKey => {
          if (proof.verificationMethod !== `did:key:${updateKey}#${updateKey}`) return false
          try {
            return verifyProof(doc, proof, decodeMultikey(updateKey))
          } catch {
            return false
          }
        })
        if (!authorized) return text('proof does not verify against this identity\'s current updateKeys', 403)

        routingStore.write(domain, JSON.stringify(doc))
        return new Response(null, { status: 204, headers: WEBVH_CORS })
      }
      default:
        return text('method not allowed', 405)
    }
  }
}
