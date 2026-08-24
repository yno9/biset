import { defaultFetch } from '../net-fetch.ts'
import type { VaultDeliveryAppendTransport } from './delivery-outbox.ts'
import type { VaultDeliveryPullTransport } from './delivery-sync.ts'
import type { VaultDeliveryAckV1, VaultDeliveryAppendV1, VaultDeliveryPullV1 } from '../protocol/vault.ts'
import type { DeliveryPullResult } from '../protocol/vault.ts'
import {
  decodeDeliveryPullResultWire,
  encodeVaultDeliveryAckWire,
  encodeVaultDeliveryAppendWire,
  encodeVaultDeliveryPullWire,
} from '../protocol/vault-delivery-wire.ts'

export interface CoreDeliveryTransportOptions {
  baseUrl: string
  fetch?: typeof fetch
}

/** Browser client for the core's bounded delivery API, never a JMAP transport. */
export class CoreVaultDeliveryTransport implements VaultDeliveryAppendTransport, VaultDeliveryPullTransport {
  private readonly fetchValue: typeof fetch
  private readonly baseUrl: string

  constructor(options: CoreDeliveryTransportOptions) {
    if (!options.baseUrl) throw new TypeError('core delivery base URL is required')
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.fetchValue = options.fetch ?? defaultFetch()
  }

  async append(input: VaultDeliveryAppendV1): Promise<void> {
    await this.post('/v1/vault-delivery/append', encodeVaultDeliveryAppendWire(input))
  }

  async pull(input: VaultDeliveryPullV1): Promise<DeliveryPullResult> {
    return decodeDeliveryPullResultWire(await this.post('/v1/vault-delivery/pull', encodeVaultDeliveryPullWire(input)))
  }

  async acknowledge(ack: VaultDeliveryAckV1): Promise<void> {
    await this.post('/v1/vault-delivery/ack', encodeVaultDeliveryAckWire(ack))
  }

  private async post(path: string, body: string): Promise<string> {
    const response = await this.fetchValue(`${this.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    const text = await response.text()
    if (!response.ok) throw new Error(`core vault delivery request failed (${response.status}): ${text.slice(0, 256)}`)
    return text
  }
}
