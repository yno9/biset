import { createDidWebHttpHandler } from './webvh/did-web-http.ts'
import type { DidWebStore } from './webvh/did-web-store.ts'
import { createRoutingHttpHandler } from './webvh/routing-http.ts'
import type { RoutingDocStore } from './webvh/routing-store.ts'
import { createWebvhHttpHandler, WEBVH_CORS } from './webvh/webvh-http.ts'
import type { WebvhLogStore } from './webvh/webvh-store.ts'
import type { AnchorOidcProvider } from './oidc.ts'
import type { AnchorOid4vpProvider } from './oid4vp.ts'
import { oidcClientCallback, oidcClientCallbackScript } from './oidc-client-callback.ts'

export interface BisetAnchorApplicationOptions {
  webvh: WebvhLogStore
  didWeb: DidWebStore
  routing: RoutingDocStore
  /** Reverse proxy header containing the original identity domain. */
  domainHeader?: string
  oidc?: AnchorOidcProvider
  oid4vp?: AnchorOid4vpProvider
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
          storage: options.oidc ? 'identity-and-oidc-control-plane' : 'public-identity-only',
          oidc: options.oidc ? 'enabled' : 'disabled',
          oid4vp: options.oid4vp ? 'enabled' : 'disabled',
        },
        { headers: WEBVH_CORS },
      )
    }
    if (options.oidc && path === '/.well-known/openid-configuration' && request.method === 'GET') return Response.json(options.oidc.metadata(), { headers: WEBVH_CORS })
    if (options.oidc && path === '/oauth/jwks' && request.method === 'GET') return Response.json(options.oidc.jwks(), { headers: WEBVH_CORS })
    if (options.oidc && path === '/oauth/authorize' && request.method === 'GET') return withCors(await options.oidc.authorize(request))
    if (options.oidc && path === '/oauth/token' && request.method === 'POST') return withCors(await options.oidc.token(request))
    if (options.oidc && path === '/oauth/client-callback' && request.method === 'GET') return oidcClientCallback()
    if (options.oidc && path === '/oauth/client-callback.js' && request.method === 'GET') return oidcClientCallbackScript()
    if (options.oid4vp && path === '/oid4vp/jwks' && request.method === 'GET') return Response.json(options.oid4vp.jwks(), { headers: WEBVH_CORS })
    if (options.oid4vp && path.startsWith('/oid4vp/request/') && request.method === 'GET') return withCors(await options.oid4vp.requestObject(path.slice('/oid4vp/request/'.length)))
    if (options.oid4vp && path === '/oid4vp/response' && request.method === 'POST') return withCors(await options.oid4vp.directPost(request))
    if (options.oid4vp && path === '/oid4vp/complete' && request.method === 'GET') return withCors(await options.oid4vp.complete(request))
    if (options.oid4vp && path === '/oid4vp/wallet-bridge' && request.method === 'GET') return options.oid4vp.walletBridge()
    if (options.oid4vp && path === '/oid4vp/wallet-bridge.js' && request.method === 'GET') return options.oid4vp.walletBridgeScript()
    if (options.oid4vp && path === '/oid4vp/enrollment/challenge' && request.method === 'POST') return withCors(await options.oid4vp.beginEnrollment(request, options.webvh))
    if (options.oid4vp && path === '/oid4vp/enrollment/complete' && request.method === 'POST') return withCors(await options.oid4vp.completeEnrollment(request, options.webvh))
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
