import { createVaultDeliveryHttpHandler } from './mediation/vault-delivery-http.ts'
import type { VaultDeliveryStore } from './mediation/vault-delivery-store.ts'

export interface BisetCoreApplicationOptions {
  /**
   * Constructed by the deployment's identity/MLS composition. Omitting it is
   * intentionally safe: the process remains a health endpoint, not an open
   * relay whose caller can invent devices or authorisation.
   */
  vaultDeliveryStore?: VaultDeliveryStore
}

/** Narrow composition root: identity decides authorisation; mediation stores bounded ciphertext. */
export function createBisetCoreFetchHandler(options: BisetCoreApplicationOptions): (request: Request) => Promise<Response> {
  const vaultDelivery = options.vaultDeliveryStore && createVaultDeliveryHttpHandler(options.vaultDeliveryStore)
  return async (request) => {
    const path = new URL(request.url).pathname
    if (path === '/healthz') return Response.json({ ok: true, service: 'biset-core', storage: 'bounded-only' })
    if (path.startsWith('/v1/vault-delivery/') && vaultDelivery) return vaultDelivery(request)
    return new Response('Not found', { status: 404 })
  }
}
