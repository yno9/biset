import { openPgpCredentialKind, type OpenPgpPrivateCredentialV1 } from './openpgp-credential.ts'
import { VaultCredentialSink, type VaultCredentialSinkOptions, type VaultCredentialStoreResult } from './credential-store.ts'

/** Unchanged shape, now defined once in credential-store.ts. */
export type OpenPgpCredentialVaultSinkOptions = VaultCredentialSinkOptions

export type OpenPgpCredentialStoreResult = VaultCredentialStoreResult

/**
 * Writes a newly generated or rotated OpenPGP private key through the same
 * atomic local-vault and shared-delivery outbox path as normal vault changes.
 * It deliberately leaves the user-visible JMAP projection unchanged.
 */
export class OpenPgpCredentialVaultSink {
  private readonly sink: VaultCredentialSink<OpenPgpPrivateCredentialV1>

  constructor(options: OpenPgpCredentialVaultSinkOptions) {
    this.sink = new VaultCredentialSink(openPgpCredentialKind, options)
  }

  async store(credential: OpenPgpPrivateCredentialV1): Promise<OpenPgpCredentialStoreResult> {
    return this.sink.store(credential)
  }
}
