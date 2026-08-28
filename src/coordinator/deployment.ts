import type { VaultCoordinatorStoreLimits } from './store.ts'
import { SqliteVaultCoordinatorStore } from './store.ts'
import { OidcJwtAccessTokenVerifier, type OidcJwtAccessTokenVerifierOptions, type VaultAccessTokenVerifier } from './auth.ts'
import { createVaultCoordinatorFetchHandler } from './app.ts'

export interface VaultCoordinatorDeploymentOptions {
  databasePath: string
  accessTokens: VaultAccessTokenVerifier
  limits?: VaultCoordinatorStoreLimits
}

export interface OidcVaultCoordinatorDeploymentOptions extends Omit<VaultCoordinatorDeploymentOptions, 'accessTokens'> {
  oidc: OidcJwtAccessTokenVerifierOptions
}

export function createVaultCoordinatorDeployment(options: VaultCoordinatorDeploymentOptions) {
  const store = SqliteVaultCoordinatorStore.open(options.databasePath, options.limits)
  return {
    store,
    fetch: createVaultCoordinatorFetchHandler({ store, accessTokens: options.accessTokens }),
    close(): void { store.close() },
  }
}

export function createOidcVaultCoordinatorDeployment(options: OidcVaultCoordinatorDeploymentOptions) {
  return createVaultCoordinatorDeployment({ ...options, accessTokens: new OidcJwtAccessTokenVerifier(options.oidc) })
}
