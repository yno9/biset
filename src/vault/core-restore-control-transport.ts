import {
  decodeRestoreOffersWire,
  decodeRestoreRequestsWire,
  encodeRestoreCancelWire,
  encodeRestoreControlPullWire,
  encodeRestoreOfferWire,
  encodeRestoreRequestWire,
} from '../protocol/restore-control-wire.ts'
import type { RestoreCancelV1, RestoreControlPullV1, RestoreOfferV1, RestoreRequestV1 } from '../protocol/vault.ts'

export interface RestoreControlTransport {
  request(input: RestoreRequestV1): Promise<void>
  pullRequests(input: RestoreControlPullV1): Promise<RestoreRequestV1[]>
  offer(input: RestoreOfferV1): Promise<void>
  pullOffers(input: RestoreControlPullV1): Promise<RestoreOfferV1[]>
  cancel(input: RestoreCancelV1): Promise<void>
}

/** Browser endpoint for short restore control only; vault transfer is never routed here. */
export class CoreRestoreControlTransport implements RestoreControlTransport {
  constructor(private readonly options: { baseUrl: string; fetch?: typeof globalThis.fetch }) {}

  async request(input: RestoreRequestV1): Promise<void> { await this.post('/v1/restore/request', encodeRestoreRequestWire(input)) }

  async pullRequests(input: RestoreControlPullV1): Promise<RestoreRequestV1[]> {
    return decodeRestoreRequestsWire(await this.post('/v1/restore/requests/pull', encodeRestoreControlPullWire({ ...input, kind: 'requests' })))
  }

  async offer(input: RestoreOfferV1): Promise<void> { await this.post('/v1/restore/offer', encodeRestoreOfferWire(input)) }

  async pullOffers(input: RestoreControlPullV1): Promise<RestoreOfferV1[]> {
    return decodeRestoreOffersWire(await this.post('/v1/restore/offers/pull', encodeRestoreControlPullWire({ ...input, kind: 'offers' })))
  }

  async cancel(input: RestoreCancelV1): Promise<void> { await this.post('/v1/restore/cancel', encodeRestoreCancelWire(input)) }

  private async post(path: string, body: string): Promise<string> {
    const response = await (this.options.fetch ?? globalThis.fetch)(new URL(path, this.options.baseUrl).toString(), { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    const text = await response.text()
    if (!response.ok) throw new Error(`core restore-control request failed (${response.status}): ${text}`)
    return text
  }
}
