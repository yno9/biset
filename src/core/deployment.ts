import { Database } from 'bun:sqlite'
import { createBisetCoreFetchHandler } from './app.ts'
import { rosterBackedVaultDeliveryAuthorizer } from './identity/authorizers.ts'
import { Ed25519DeviceControlSignatureVerifier, type DeviceSigningPublicKeyResolver } from './identity/ed25519-device-control-verifier.ts'
import { SqliteTrustedDeviceRoster } from './identity/sqlite-device-roster.ts'
import { SqliteVaultDeliveryStore } from './mediation/sqlite-vault-delivery-store.ts'
import type { VaultDeliveryStoreLimits } from './mediation/vault-delivery-store.ts'

export interface BisetCoreDeploymentOptions {
  databasePath: string
  /** Backed by DID/webvh resolution and its deployment-specific cache policy. */
  signingKeys: DeviceSigningPublicKeyResolver
  deliveryLimits?: VaultDeliveryStoreLimits
}

export interface BisetCoreDeployment {
  readonly roster: SqliteTrustedDeviceRoster
  readonly delivery: SqliteVaultDeliveryStore
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
  return {
    roster,
    delivery,
    fetch: createBisetCoreFetchHandler({ vaultDeliveryStore: delivery }),
    close() { database.close() },
  }
}
