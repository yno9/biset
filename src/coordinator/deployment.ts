import type { VaultCoordinatorStoreLimits } from './store.ts'
import { SqliteVaultCoordinatorStore } from './store.ts'
import { OidcJwtAccessTokenVerifier, type OidcJwtAccessTokenVerifierOptions, type VaultAccessTokenVerifier } from './auth.ts'
import { createVaultCoordinatorFetchHandler } from './app.ts'
import { createMlsDeliveryHttpHandler } from './mls-delivery-http.ts'
import { Ed25519MlsDsSignatureVerifier, type DeviceSigningPublicKeyResolver } from './mls-delivery-authorizer.ts'
import { SqliteMlsDeliveryService } from './mls-delivery-store.ts'
import { CoordinatorWebvhSigningKeyResolver } from './webvh-signing-key-resolver.ts'

export interface VaultCoordinatorDeploymentOptions {
  databasePath: string
  accessTokens: VaultAccessTokenVerifier
  limits?: VaultCoordinatorStoreLimits
  mlsSigningKeys?: DeviceSigningPublicKeyResolver
}

export interface OidcVaultCoordinatorDeploymentOptions extends Omit<VaultCoordinatorDeploymentOptions, 'accessTokens'> {
  oidc: OidcJwtAccessTokenVerifierOptions
}

export function createVaultCoordinatorDeployment(options: VaultCoordinatorDeploymentOptions) {
  const store = SqliteVaultCoordinatorStore.open(options.databasePath, options.limits)
  const mlsDelivery = SqliteMlsDeliveryService.open(options.databasePath)
  const signingKeys = options.mlsSigningKeys ?? new CoordinatorWebvhSigningKeyResolver()
  const mlsHandler = createMlsDeliveryHttpHandler(
    mlsDelivery,
    new Ed25519MlsDsSignatureVerifier(signingKeys),
    async kid => mlsDelivery.groupsFor(kid).length > 0,
  )
  return {
    store,
    mlsDelivery,
    fetch: createVaultCoordinatorFetchHandler({ store, accessTokens: options.accessTokens, mlsDelivery: mlsHandler }),
    close(): void { mlsDelivery.close(); store.close() },
  }
}

export function createOidcVaultCoordinatorDeployment(options: OidcVaultCoordinatorDeploymentOptions) {
  return createVaultCoordinatorDeployment({ ...options, accessTokens: new OidcJwtAccessTokenVerifier(options.oidc) })
}
