import { didCommDeviceKeyKind, type DidCommDeviceKeyV1 } from './didcomm-device-key.ts'
import { VaultCredentialReader, type VaultCredentialReaderOptions } from './credential-store.ts'
import type { VaultRecordReader } from './store.ts'

/** Unchanged shape, now defined once in credential-store.ts. */
export type DidCommDeviceKeyReaderOptions = VaultCredentialReaderOptions<VaultRecordReader>

/**
 * Endpoint-only reader for the (deviceKid, didCommKid) pairings held in the
 * encrypted vault -- see didcomm-device-key.ts's own header. The only
 * caller is revokeDevice (main.ts), looking up the DIDComm key a specific
 * MLS device kid minted so it can be removed from routing.json too.
 *
 * Unlike the other three credential families this one reads the full event
 * log rather than the narrow local credential index.
 */
export class DidCommDeviceKeyReader {
  private readonly reader: VaultCredentialReader<DidCommDeviceKeyV1, VaultRecordReader>

  constructor(options: DidCommDeviceKeyReaderOptions) {
    this.reader = new VaultCredentialReader(didCommDeviceKeyKind, options)
  }

  /** Every verified pairing this device currently knows about. */
  async readAll(): Promise<DidCommDeviceKeyV1[]> {
    return this.reader.readAll()
  }

  /** The pairing for one specific MLS device kid, or undefined if none is known yet. */
  async forDeviceKid(deviceKid: string): Promise<DidCommDeviceKeyV1 | undefined> {
    return (await this.readAll()).find(record => record.deviceKid === deviceKid)
  }
}
