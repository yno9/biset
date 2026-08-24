import { createVaultDeliveryHttpHandler } from './mediation/vault-delivery-http.ts'
import type { VaultDeliveryStore } from './mediation/vault-delivery-store.ts'
import { createRestoreControlHttpHandler } from './mediation/restore-control-http.ts'
import type { RestoreControlStore } from './mediation/restore-control-store.ts'
import { createIngressHttpHandler } from './mediation/ingress-http.ts'
import type { IngressStore } from './mediation/ingress-store.ts'
import { createRosterInstallHttpHandler } from './identity/roster-http.ts'
import type { DeviceControlSignatureVerifier } from './identity/authorizers.ts'
import type { TrustedDeviceRoster } from './identity/device-roster.ts'
import { createMlsDeliveryHttpHandler } from './mediation/mls-delivery-http.ts'
import type { MlsDsSignatureVerifier } from './mediation/mls-delivery-authorizer.ts'
import type { SqliteMlsDeliveryService } from './mediation/mls-delivery-store.ts'
import { createMailSubmissionHttpHandler } from './mediation/mail-submission-http.ts'
import type { CoreMailSubmissionAdapter } from './adapters/mail-submission-adapter.ts'
import { createWebvhHttpHandler } from './webvh/webvh-http.ts'
import type { WebvhLogStore } from './webvh/webvh-store.ts'
import { createDidWebHttpHandler } from './webvh/did-web-http.ts'
import type { DidWebStore } from './webvh/did-web-store.ts'

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
  /** MLS self-group DS plane (RFC 9750 §5): commit ordering, GroupInfo, KeyPackage directory. */
  mlsDelivery?: { store: SqliteMlsDeliveryService; verifier: MlsDsSignatureVerifier; isLiveDevice: (identityId: string, kid: string) => Promise<boolean> }
  /** Authenticated device -> core outbound mail submission (PLAN.md §6.2). */
  mailSubmission?: CoreMailSubmissionAdapter
  /** did:webvh log hosting (GET/PUT/POST .well-known/did.jsonl) for the
   * subdomain-per-identity scheme. Ported from the pre-Vault-Core anchor,
   * which this deployment otherwise has no dependency on -- see
   * src/core/webvh/webvh-http.ts's header. */
  webvh?: WebvhLogStore
  /** did:web mirror hosting (GET/PUT .well-known/did.json), identity/web/
   * mirror.ts's server side. Requires `webvh` too -- a mirror write is
   * validated against the domain's current did:webvh state. */
  didWeb?: DidWebStore
}

// Every narrow-API handler (roster/mls/vault-delivery/restore/ingress/mail)
// was built assuming a same-process test fetch or a signed server-to-server
// caller, never CORS -- found live testing the compose/reply slice: a
// browser at file:// (or t.biset.md) preflights every POST here and none of
// them answered with Access-Control-Allow-Origin, so the actual request
// never even went out. webvh/did-web already set their own CORS headers
// (webvh-http.ts's WEBVH_CORS predates this), so applying the same set here
// too is redundant for those two paths but harmless (Headers.set overwrites,
// not appends).
const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
}

/** Narrow composition root: identity decides authorisation; mediation stores bounded ciphertext. */
export function createBisetCoreFetchHandler(options: BisetCoreApplicationOptions): (request: Request) => Promise<Response> {
  const vaultDelivery = options.vaultDeliveryStore && createVaultDeliveryHttpHandler(options.vaultDeliveryStore)
  const restoreControl = options.restoreControlStore && createRestoreControlHttpHandler(options.restoreControlStore)
  const ingress = options.ingressStore && createIngressHttpHandler(options.ingressStore)
  const roster = options.roster && createRosterInstallHttpHandler(options.roster.store, options.roster.verifier)
  const mlsDelivery = options.mlsDelivery && createMlsDeliveryHttpHandler(options.mlsDelivery.store, options.mlsDelivery.verifier, options.mlsDelivery.isLiveDevice)
  const mailSubmission = options.mailSubmission && createMailSubmissionHttpHandler(options.mailSubmission)
  const webvh = options.webvh && createWebvhHttpHandler(options.webvh, { domainHeader: 'x-biset-domain' })
  const didWeb = options.webvh && options.didWeb && createDidWebHttpHandler(options.didWeb, options.webvh, { domainHeader: 'x-biset-domain' })
  const inner = async (request: Request): Promise<Response> => {
    const path = new URL(request.url).pathname
    if (path === '/healthz') return Response.json({ ok: true, service: 'biset-core', storage: 'bounded-only' })
    if (path === '/.well-known/did.jsonl' && webvh) return webvh(request)
    if (path === '/.well-known/did.json' && didWeb) return didWeb(request)
    if (path.startsWith('/v1/vault-delivery/') && vaultDelivery) return vaultDelivery(request)
    if (path.startsWith('/v1/restore/') && restoreControl) return restoreControl(request)
    if (path.startsWith('/v1/ingress/') && ingress) return ingress(request)
    if (path.startsWith('/v1/roster/') && roster) return roster(request)
    if (path.startsWith('/v1/mls/') && mlsDelivery) return mlsDelivery(request)
    if (path.startsWith('/v1/mail/') && mailSubmission) return mailSubmission(request)
    return new Response('Not found', { status: 404 })
  }
  return async (request) => {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS })
    const response = await inner(request)
    const headers = new Headers(response.headers)
    for (const [key, value] of Object.entries(CORS)) headers.set(key, value)
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
  }
}
