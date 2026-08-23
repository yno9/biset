import { createVaultDeliveryHttpHandler } from './mediation/vault-delivery-http.ts'
import type { VaultDeliveryStore } from './mediation/vault-delivery-store.ts'
import { createRestoreControlHttpHandler } from './mediation/restore-control-http.ts'
import type { RestoreControlStore } from './mediation/restore-control-store.ts'
import { createIngressHttpHandler } from './mediation/ingress-http.ts'
import type { IngressStore } from './mediation/ingress-store.ts'
import { createRosterInstallHttpHandler } from './identity/roster-http.ts'
import type { DeviceControlSignatureVerifier } from './identity/authorizers.ts'
import type { TrustedDeviceRoster } from './identity/device-roster.ts'

export interface BisetCoreApplicationOptions {
  /**
   * Constructed by the deployment's identity/MLS composition. Omitting it is
   * intentionally safe: the process remains a health endpoint, not an open
   * relay whose caller can invent devices or authorisation.
   */
  vaultDeliveryStore?: VaultDeliveryStore
  /** Optional, separately authorised short-lived restore signalling plane. */
  restoreControlStore?: RestoreControlStore
  /** Endpoint-signed ingress pull/ACK plane; never an external adapter offer API. */
  ingressStore?: IngressStore
  /** Roster install plane; requires both the store and its signature verifier. */
  roster?: { store: TrustedDeviceRoster; verifier: Pick<DeviceControlSignatureVerifier, 'verifyRosterInstall'> }
}

/** Narrow composition root: identity decides authorisation; mediation stores bounded ciphertext. */
export function createBisetCoreFetchHandler(options: BisetCoreApplicationOptions): (request: Request) => Promise<Response> {
  const vaultDelivery = options.vaultDeliveryStore && createVaultDeliveryHttpHandler(options.vaultDeliveryStore)
  const restoreControl = options.restoreControlStore && createRestoreControlHttpHandler(options.restoreControlStore)
  const ingress = options.ingressStore && createIngressHttpHandler(options.ingressStore)
  const roster = options.roster && createRosterInstallHttpHandler(options.roster.store, options.roster.verifier)
  return async (request) => {
    const path = new URL(request.url).pathname
    if (path === '/healthz') return Response.json({ ok: true, service: 'biset-core', storage: 'bounded-only' })
    if (path.startsWith('/v1/vault-delivery/') && vaultDelivery) return vaultDelivery(request)
    if (path.startsWith('/v1/restore/') && restoreControl) return restoreControl(request)
    if (path.startsWith('/v1/ingress/') && ingress) return ingress(request)
    if (path.startsWith('/v1/roster/') && roster) return roster(request)
    return new Response('Not found', { status: 404 })
  }
}
