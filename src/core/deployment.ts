import { Database } from 'bun:sqlite'
import { createBisetCoreFetchHandler } from './app.ts'
import { rosterBackedRestoreControlAuthorizer, rosterBackedVaultDeliveryAuthorizer } from './identity/authorizers.ts'
import { Ed25519DeviceControlSignatureVerifier, type DeviceSigningPublicKeyResolver } from './identity/ed25519-device-control-verifier.ts'
import { SqliteTrustedDeviceRoster } from './identity/sqlite-device-roster.ts'
import { SqliteVaultDeliveryStore } from './mediation/sqlite-vault-delivery-store.ts'
import type { VaultDeliveryStoreLimits } from './mediation/vault-delivery-store.ts'
import { SqliteRestoreControlStore, type RestoreControlStoreLimits } from './mediation/sqlite-restore-control-store.ts'

export interface BisetCoreDeploymentOptions {
  databasePath: string
  /** Backed by DID/webvh resolution and its deployment-specific cache policy. */
  signingKeys: DeviceSigningPublicKeyResolver
  deliveryLimits?: VaultDeliveryStoreLimits
  restoreControlLimits?: RestoreControlStoreLimits
}

export interface BisetCoreDeployment {
  readonly roster: SqliteTrustedDeviceRoster
  readonly delivery: SqliteVaultDeliveryStore
  readonly restoreControl: SqliteRestoreControlStore
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
  return {
    roster,
    delivery,
    restoreControl,
    fetch: createBisetCoreFetchHandler({ vaultDeliveryStore: delivery, restoreControlStore: restoreControl }),
    close() { database.close() },
  }
}
