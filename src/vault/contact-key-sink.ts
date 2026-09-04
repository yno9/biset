import { contactKeyCredentialKind, type ContactKeyV1 } from './contact-key.ts'
import { VaultCredentialSink, type VaultCredentialSinkOptions, type VaultCredentialStoreResult } from './credential-store.ts'

/** Unchanged shape, now defined once in credential-store.ts. */
export type ContactKeyVaultSinkOptions = VaultCredentialSinkOptions

export type ContactKeyStoreResult = VaultCredentialStoreResult

export class ContactKeyVaultSink {
  private readonly sink: VaultCredentialSink<ContactKeyV1>

  constructor(options: ContactKeyVaultSinkOptions) {
    this.sink = new VaultCredentialSink(contactKeyCredentialKind, options)
  }

  async store(contactKey: ContactKeyV1): Promise<ContactKeyStoreResult> {
    return this.sink.store(contactKey)
  }
}
