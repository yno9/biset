import { didCommDeviceKeyKind, type DidCommDeviceKeyV1 } from './didcomm-device-key.ts'
import { VaultCredentialSink, type VaultCredentialSinkOptions, type VaultCredentialStoreResult } from './credential-store.ts'

/** Unchanged shape, now defined once in credential-store.ts. */
export type DidCommDeviceKeyVaultSinkOptions = VaultCredentialSinkOptions

export type DidCommDeviceKeyStoreResult = VaultCredentialStoreResult

/**
 * Writes this device's own (deviceKid, didCommKid) pairing through the same
 * atomic local-vault and shared-delivery outbox path as normal vault
 * changes, so every other trusted device eventually sees it too. Leaves the
 * user-visible JMAP projection unchanged -- see didcomm-device-key.ts's own
 * header for why this lives in the vault rather than routing.json.
 */
export class DidCommDeviceKeyVaultSink {
  private readonly sink: VaultCredentialSink<DidCommDeviceKeyV1>

  constructor(options: DidCommDeviceKeyVaultSinkOptions) {
    this.sink = new VaultCredentialSink(didCommDeviceKeyKind, options)
  }

  async store(key: DidCommDeviceKeyV1): Promise<DidCommDeviceKeyStoreResult> {
    return this.sink.store(key)
  }
}
