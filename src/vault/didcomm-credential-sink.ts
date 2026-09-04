import { didCommCredentialKind, type DidCommPrivateCredentialV1 } from './didcomm-credential.ts'
import { VaultCredentialSink, type VaultCredentialSinkOptions, type VaultCredentialStoreResult } from './credential-store.ts'

/** Unchanged shape, now defined once in credential-store.ts. */
export type DidCommCredentialVaultSinkOptions = VaultCredentialSinkOptions

export type DidCommCredentialStoreResult = VaultCredentialStoreResult

/**
 * Writes a newly generated or rotated DIDComm keyAgreement private key
 * through the same atomic local-vault and shared-delivery outbox path as
 * normal vault changes -- same shape as vault/openpgp-credential-sink.ts.
 * Leaves the user-visible JMAP projection unchanged.
 */
export class DidCommCredentialVaultSink {
  private readonly sink: VaultCredentialSink<DidCommPrivateCredentialV1>

  constructor(options: DidCommCredentialVaultSinkOptions) {
    this.sink = new VaultCredentialSink(didCommCredentialKind, options)
  }

  async store(credential: DidCommPrivateCredentialV1): Promise<DidCommCredentialStoreResult> {
    return this.sink.store(credential)
  }
}
