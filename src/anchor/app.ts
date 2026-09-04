import { createDidWebHttpHandler } from './webvh/did-web-http.ts'
import type { DidWebStore } from './webvh/did-web-store.ts'
import { createRoutingHttpHandler } from './webvh/routing-http.ts'
import type { RoutingDocStore } from './webvh/routing-store.ts'
import { createWebvhHttpHandler, WEBVH_CORS } from './webvh/webvh-http.ts'
import type { WebvhLogStore } from './webvh/webvh-store.ts'

export interface BisetAnchorApplicationOptions {
  webvh: WebvhLogStore
  didWeb: DidWebStore
  routing: RoutingDocStore
  /** Reverse proxy header containing the original identity domain. */
  domainHeader?: string
}

/** Public identity-document plane. It deliberately has no mailbox, relay,
 * DIDComm listener, MLS state, device roster, or private-key dependency. */
export function createBisetAnchorFetchHandler(options: BisetAnchorApplicationOptions): (request: Request) => Promise<Response> {
  const handlerOptions = { domainHeader: options.domainHeader ?? 'x-biset-domain' }
  const webvh = createWebvhHttpHandler(options.webvh, handlerOptions)
  const didWeb = createDidWebHttpHandler(options.didWeb, options.webvh, handlerOptions)
  const routing = createRoutingHttpHandler(options.routing, options.webvh, handlerOptions)

  return async (request: Request): Promise<Response> => {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: WEBVH_CORS })
    const path = new URL(request.url).pathname
    if (path === '/healthz') {
      return Response.json(
        {
          ok: true,
          service: 'biset-anchor',
          storage: 'public-identity-only',
        },
        { headers: WEBVH_CORS },
      )
    }
    if (path === '/.well-known/did.jsonl') return webvh(request)
    if (path === '/.well-known/did.json') return didWeb(request)
    if (path === '/.well-known/routing.json') return routing(request)
    return new Response('Not found', { status: 404, headers: WEBVH_CORS })
  }
}

function withCors(response: Response): Response {
  const headers = new Headers(response.headers)
  for (const [name, value] of Object.entries(WEBVH_CORS)) headers.set(name, value)
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
}
