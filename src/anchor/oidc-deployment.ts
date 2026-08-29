import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { SqliteAnchorOidcState } from './oidc-sqlite.ts'
import {
  AnchorOidcProvider,
  type AnchorOidcClient,
  type AnchorOidcProviderOptions,
  type AnchorSubjectAuthenticator,
} from './oidc.ts'
import { AnchorOid4vpProvider } from './oid4vp.ts'

export interface PersistentAnchorOidcOptions {
  dataDir: string
  issuer: string
  clients: AnchorOidcClient[]
  authenticator: AnchorSubjectAuthenticator
  signingKeyId?: string
  codeTtlSeconds?: number
  accessTokenTtlSeconds?: number
  idTokenTtlSeconds?: number
  now?: () => Date
}

export interface PersistentAnchorOidcDeployment {
  readonly provider: AnchorOidcProvider
  readonly state: SqliteAnchorOidcState
  close(): void
}

export interface PersistentAnchorOid4vpOidcDeployment {
  readonly oidc: AnchorOidcProvider
  readonly oid4vp: AnchorOid4vpProvider
  readonly state: SqliteAnchorOidcState
  close(): void
}

/**
 * Composes the OIDC protocol engine with durable issuer secrets and one-use
 * authorization codes. Login/session policy remains an injected Anchor concern.
 */
export function createPersistentAnchorOidcProvider(options: PersistentAnchorOidcOptions): PersistentAnchorOidcDeployment {
  if (!options.dataDir) throw new TypeError('Anchor OIDC data directory is required')
  mkdirSync(options.dataDir, { recursive: true })
  const state = SqliteAnchorOidcState.open(join(options.dataDir, 'anchor-oidc.sqlite'))
  try {
    const secrets = state.secrets()
    const providerOptions: AnchorOidcProviderOptions = {
      issuer: options.issuer,
      clients: options.clients,
      authenticator: options.authenticator,
      codes: state,
      signingPrivateKey: secrets.signingPrivateKey,
      pairwiseSecret: secrets.pairwiseSecret,
      signingKeyId: options.signingKeyId,
      codeTtlSeconds: options.codeTtlSeconds,
      accessTokenTtlSeconds: options.accessTokenTtlSeconds,
      idTokenTtlSeconds: options.idTokenTtlSeconds,
      now: options.now,
    }
    const provider = new AnchorOidcProvider(providerOptions)
    return { provider, state, close: () => state.close() }
  } catch (error) {
    state.close()
    throw error
  }
}

/** Production composition: OID4VP is the sole interactive Anchor login method. */
export function createPersistentAnchorOid4vpOidcProvider(options: Omit<PersistentAnchorOidcOptions, 'authenticator'> & {
  walletAuthorizationEndpoint?: string
}): PersistentAnchorOid4vpOidcDeployment {
  if (!options.dataDir) throw new TypeError('Anchor OIDC data directory is required')
  mkdirSync(options.dataDir, { recursive: true })
  const state = SqliteAnchorOidcState.open(join(options.dataDir, 'anchor-oidc.sqlite'))
  try {
    const secrets = state.secrets()
    const oid4vp = new AnchorOid4vpProvider({
      issuer: options.issuer,
      store: state,
      credentialSigningPrivateKey: secrets.credentialSigningPrivateKey,
      mailAddressSigningPrivateKey: secrets.mailAddressCredentialSigningPrivateKey,
      walletAuthorizationEndpoint: options.walletAuthorizationEndpoint,
      now: options.now,
    })
    const oidc = new AnchorOidcProvider({
      issuer: options.issuer,
      clients: options.clients,
      authenticator: oid4vp,
      codes: state,
      signingPrivateKey: secrets.signingPrivateKey,
      pairwiseSecret: secrets.pairwiseSecret,
      signingKeyId: options.signingKeyId,
      codeTtlSeconds: options.codeTtlSeconds,
      accessTokenTtlSeconds: options.accessTokenTtlSeconds,
      idTokenTtlSeconds: options.idTokenTtlSeconds,
      now: options.now,
    })
    return { oidc, oid4vp, state, close: () => state.close() }
  } catch (error) {
    state.close()
    throw error
  }
}
