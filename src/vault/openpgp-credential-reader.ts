import { openPgpCredentialKind, type OpenPgpPrivateCredentialV1 } from './openpgp-credential.ts'
import { selectUnsuperseded, VaultCredentialReader, type VaultCredentialReaderOptions } from './credential-store.ts'
import type { VaultCredentialEventReader } from './store.ts'

/** Unchanged shape, now defined once in credential-store.ts. */
export type OpenPgpCredentialReaderOptions = VaultCredentialReaderOptions<VaultCredentialEventReader>

/**
 * Endpoint-only reader for the mail key held in the encrypted vault. It does
 * not add credentials to the JMAP projection and it never exposes a VEK.
 */
export class OpenPgpCredentialReader {
  private readonly reader: VaultCredentialReader<OpenPgpPrivateCredentialV1, VaultCredentialEventReader>

  constructor(options: OpenPgpCredentialReaderOptions) {
    this.reader = new VaultCredentialReader(openPgpCredentialKind, options)
  }

  /** Returns every verified credential, including historical keys needed to read old mail. */
  async readAll(): Promise<OpenPgpPrivateCredentialV1[]> {
    return this.reader.readAll()
  }

  /**
   * Selects the unique unsuperseded key for new outbound mail. If two keys are
   * independently introduced, fail closed and require an explicit rotation
   * decision instead of silently selecting by local clock order.
   */
  async readCurrent(): Promise<OpenPgpPrivateCredentialV1> {
    const credentials = await this.readAll()
    if (credentials.length === 0) throw new Error('no OpenPGP credential is available')
    return openPgpCredentialKind.copy(selectUnsuperseded(credentials, {
      kidOf: credential => credential.fingerprint,
      supersededKidOf: credential => credential.supersedesFingerprint,
      duplicateMessage: 'duplicate OpenPGP credential fingerprint',
      ambiguousMessage: 'OpenPGP current credential is ambiguous; explicit rotation is required',
    }))
  }
}
