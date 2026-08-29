import { createBisetAnchorFetchHandler } from './app.ts'
import { DidWebStore } from './webvh/did-web-store.ts'
import { RoutingDocStore } from './webvh/routing-store.ts'
import { ensureWebvhDataDir, WebvhLogStore } from './webvh/webvh-store.ts'
import type { AnchorOidcProvider } from './oidc.ts'
import type { AnchorOid4vpProvider } from './oid4vp.ts'

export interface BisetAnchorDeploymentOptions {
  dataDir: string
  domainHeader?: string
  oidc?: AnchorOidcProvider
  oid4vp?: AnchorOid4vpProvider
  apexDomain?: string
}

export interface BisetAnchorDeployment {
  readonly webvh: WebvhLogStore
  readonly didWeb: DidWebStore
  readonly routing: RoutingDocStore
  readonly fetch: (request: Request) => Promise<Response>
}

/** Filesystem-backed deployment for public identity and routing documents. */
export function createBisetAnchorDeployment(options: BisetAnchorDeploymentOptions): BisetAnchorDeployment {
  if (!options.dataDir) throw new TypeError('anchor deployment data directory is required')
  ensureWebvhDataDir(options.dataDir)
  const webvh = new WebvhLogStore(options.dataDir)
  const didWeb = new DidWebStore(options.dataDir)
  const routing = new RoutingDocStore(options.dataDir)
  return {
    webvh,
    didWeb,
    routing,
    fetch: createBisetAnchorFetchHandler({
      webvh,
      didWeb,
      routing,
      domainHeader: options.domainHeader,
      oidc: options.oidc,
      oid4vp: options.oid4vp,
      apexDomain: options.apexDomain,
    }),
  }
}
