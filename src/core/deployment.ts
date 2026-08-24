import { Database } from 'bun:sqlite'
import { createBisetCoreFetchHandler } from './app.ts'
import { rosterBackedIngressAuthorizer, rosterBackedRestoreControlAuthorizer, rosterBackedVaultDeliveryAuthorizer } from './identity/authorizers.ts'
import { Ed25519DeviceControlSignatureVerifier, type DeviceSigningPublicKeyResolver } from './identity/ed25519-device-control-verifier.ts'
import { SqliteTrustedDeviceRoster } from './identity/sqlite-device-roster.ts'
import { SqliteVaultDeliveryStore } from './mediation/sqlite-vault-delivery-store.ts'
import type { VaultDeliveryStoreLimits } from './mediation/vault-delivery-store.ts'
import { SqliteRestoreControlStore, type RestoreControlStoreLimits } from './mediation/sqlite-restore-control-store.ts'
import { SqliteIngressStore } from './mediation/sqlite-ingress-store.ts'
import type { IngressStoreLimits } from './mediation/ingress-store.ts'
import { CoreIngressAdapter } from './adapters/ingress.ts'
import { SqliteMlsDeliveryService } from './mediation/mls-delivery-store.ts'
import { Ed25519MlsDsSignatureVerifier } from './mediation/mls-delivery-authorizer.ts'
import { rosterBackedMailSubmissionAuthorizer } from './identity/authorizers.ts'
import { CoreMailSubmissionAdapter } from './adapters/mail-submission-adapter.ts'
import { WebvhLogStore } from './webvh/webvh-store.ts'
import { DidWebStore } from './webvh/did-web-store.ts'
import { RoutingDocStore } from './webvh/routing-store.ts'

export interface BisetCoreDeploymentOptions {
  databasePath: string
  /** Backed by DID/webvh resolution and its deployment-specific cache policy. */
  signingKeys: DeviceSigningPublicKeyResolver
  deliveryLimits?: VaultDeliveryStoreLimits
  restoreControlLimits?: RestoreControlStoreLimits
  ingressLimits?: IngressStoreLimits
  /** EHLO name for outbound mail submission (PLAN.md §6.2). Omitting it is
   * intentionally safe, the same way every other optional plane here is:
   * the deployment simply doesn't expose /v1/mail/submit rather than
   * guessing a hostname to announce on this identity's behalf. */
  mailHelloName?: string
  /** Directory for did:webvh log storage (GET/PUT/POST .well-known/did.jsonl,
   * subdomain-per-identity scheme). Omitting it is intentionally safe: the
   * deployment simply doesn't expose the endpoint, matching every other
   * optional plane here. */
  webvhDataDir?: string
}

export interface BisetCoreDeployment {
  readonly roster: SqliteTrustedDeviceRoster
  readonly delivery: SqliteVaultDeliveryStore
  readonly restoreControl: SqliteRestoreControlStore
  /** First-party adapter boundary only; the public core fetch handler does not expose it. */
  readonly ingress: SqliteIngressStore
  readonly ingressAdapter: CoreIngressAdapter
  readonly mlsDelivery: SqliteMlsDeliveryService
  readonly mailSubmissionAdapter?: CoreMailSubmissionAdapter
  readonly webvh?: WebvhLogStore
  readonly didWeb?: DidWebStore
  readonly routing?: RoutingDocStore
  readonly fetch: (request: Request) => Promise<Response>
  close(): void
}

/**
 * Production-shaped core composition. The shared SQLite database contains
 * public roster metadata and bounded ciphertext relay state, but no mailbox
 * projection, no plaintext, no user private key, and no MLS exporter secret.
 */
export function createBisetCoreDeployment(options: BisetCoreDeploymentOptions): BisetCoreDeployment {
  if (!options.databasePath) throw new TypeError('core deployment database path is required')
  const database = new Database(options.databasePath)
  const roster = new SqliteTrustedDeviceRoster(database)
  const verifier = new Ed25519DeviceControlSignatureVerifier(options.signingKeys)
  const delivery = new SqliteVaultDeliveryStore(database, rosterBackedVaultDeliveryAuthorizer(roster, verifier), options.deliveryLimits)
  const restoreControl = new SqliteRestoreControlStore(database, rosterBackedRestoreControlAuthorizer(roster, verifier), options.restoreControlLimits)
  const ingress = new SqliteIngressStore(database, rosterBackedIngressAuthorizer(roster, verifier), options.ingressLimits)
  const ingressAdapter = new CoreIngressAdapter(roster, ingress)
  const mlsDelivery = new SqliteMlsDeliveryService(database)
  const mlsDeliveryVerifier = new Ed25519MlsDsSignatureVerifier(options.signingKeys)
  const mailSubmissionAdapter = options.mailHelloName
    ? new CoreMailSubmissionAdapter(rosterBackedMailSubmissionAuthorizer(roster, verifier), options.mailHelloName)
    : undefined
  const webvh = options.webvhDataDir ? new WebvhLogStore(options.webvhDataDir) : undefined
  const didWeb = options.webvhDataDir ? new DidWebStore(options.webvhDataDir) : undefined
  const routing = options.webvhDataDir ? new RoutingDocStore(options.webvhDataDir) : undefined
  return {
    roster,
    delivery,
    restoreControl,
    ingress,
    ingressAdapter,
    mlsDelivery,
    mailSubmissionAdapter,
    webvh,
    didWeb,
    routing,
    fetch: createBisetCoreFetchHandler({
      vaultDeliveryStore: delivery,
      restoreControlStore: restoreControl,
      ingressStore: ingress,
      roster: { store: roster, verifier },
      mlsDelivery: { store: mlsDelivery, verifier: mlsDeliveryVerifier, isLiveDevice: (identityId, kid) => roster.isTrustedDevice(identityId, kid) },
      mailSubmission: mailSubmissionAdapter,
      webvh,
      didWeb,
      routing,
    }),
    close() { database.close() },
  }
}
