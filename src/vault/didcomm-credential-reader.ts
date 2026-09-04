import { didCommCredentialKind, type DidCommPrivateCredentialV1 } from './didcomm-credential.ts'
import { selectUnsuperseded, VaultCredentialReader, type VaultCredentialReaderOptions } from './credential-store.ts'
import type { VaultCredentialEventReader } from './store.ts'

/** Unchanged shape, now defined once in credential-store.ts. */
export type DidCommCredentialReaderOptions = VaultCredentialReaderOptions<VaultCredentialEventReader>

/**
 * Endpoint-only reader for the identity-shared DIDComm keyAgreement
 * credential held in the encrypted vault -- same shape and same reasoning
 * as vault/openpgp-credential-reader.ts.
 */
export class DidCommCredentialReader {
  private readonly reader: VaultCredentialReader<DidCommPrivateCredentialV1, VaultCredentialEventReader>

  constructor(options: DidCommCredentialReaderOptions) {
    this.reader = new VaultCredentialReader(didCommCredentialKind, options)
  }

  /** Returns every verified credential, including historical keys superseded by a rotation. */
  async readAll(): Promise<DidCommPrivateCredentialV1[]> {
    return this.reader.readAll()
  }

  /**
   * Selects the unique unsuperseded key for this identity's DIDComm
   * keyAgreement kid. If two keys are independently introduced (e.g. two
   * devices raced to mint one before either had synced the other's), fail
   * closed and require an explicit rotation decision instead of silently
   * picking one by local clock order.
   */
  async readCurrent(): Promise<DidCommPrivateCredentialV1> {
    const credentials = await this.readAll()
    if (credentials.length === 0) throw new Error('no DIDComm credential is available')
    return didCommCredentialKind.copy(selectUnsuperseded(credentials, {
      kidOf: credential => credential.didCommKid,
      supersededKidOf: credential => credential.supersedesKid,
      duplicateMessage: 'duplicate DIDComm credential kid',
      ambiguousMessage: 'DIDComm current credential is ambiguous; explicit rotation is required',
    }))
  }
}
