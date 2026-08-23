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

export interface BisetCoreDeploymentOptions {
  databasePath: string
  /** Backed by DID/webvh resolution and its deployment-specific cache policy. */
  signingKeys: DeviceSigningPublicKeyResolver
  deliveryLimits?: VaultDeliveryStoreLimits
  restoreControlLimits?: RestoreControlStoreLimits
  ingressLimits?: IngressStoreLimits
}

export interface BisetCoreDeployment {
  readonly roster: SqliteTrustedDeviceRoster
  readonly delivery: SqliteVaultDeliveryStore
  readonly restoreControl: SqliteRestoreControlStore
  /** First-party adapter boundary only; the public core fetch handler does not expose it. */
  readonly ingress: SqliteIngressStore
  readonly ingressAdapter: CoreIngressAdapter
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
  return {
    roster,
    delivery,
    restoreControl,
    ingress,
    ingressAdapter,
    fetch: createBisetCoreFetchHandler({ vaultDeliveryStore: delivery, restoreControlStore: restoreControl, ingressStore: ingress, roster: { store: roster, verifier } }),
    close() { database.close() },
  }
}
