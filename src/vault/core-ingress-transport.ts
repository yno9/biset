import { defaultFetch } from '../net-fetch.ts'
import type { IngressAckV1, IngressEnvelopeV1, IngressPullV1 } from '../protocol/ingress.ts'
import { decodeIngressPullResultWire, encodeIngressAckWire, encodeIngressPullWire } from '../protocol/ingress-wire.ts'

export interface CoreIngressTransportOptions {
  baseUrl: string
  fetch?: typeof fetch
}

/** Browser transport for device-signed short ingress retrieval and ACK only. */
export class CoreIngressTransport {
  private readonly fetchValue: typeof fetch
  private readonly baseUrl: string

  constructor(options: CoreIngressTransportOptions) {
    if (!options.baseUrl) throw new TypeError('core ingress base URL is required')
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.fetchValue = options.fetch ?? defaultFetch()
  }

  async pull(input: IngressPullV1): Promise<IngressEnvelopeV1[]> {
    return decodeIngressPullResultWire(await this.post('/v1/ingress/pull', encodeIngressPullWire(input)))
  }

  async acknowledge(input: IngressAckV1): Promise<void> {
    const response = await this.fetchValue(`${this.baseUrl}/v1/ingress/ack`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: encodeIngressAckWire(input),
    })
    const text = await response.text()
    if (response.ok) return
    // The vault commit and its ACK outbox record are atomic, so these
    // tombstone answers mean only that the remote body is already gone.
    // Retrying such an ACK forever cannot recover anything and used to pin
    // the first outbox row permanently, preventing every later ACK from
    // being flushed. Other 400s (bad signature/hash/claim) remain failures.
    if (response.status === 400 && (
      text === 'unknown ingressId'
      || text === 'ingress is already vault-ingested'
      || text === 'ingress is already expired'
      || text === 'ingress is already rejected'
    )) return
    throw new Error(`core ingress request failed (${response.status}): ${text.slice(0, 256)}`)
  }

  private async post(path: string, body: string): Promise<string> {
    const response = await this.fetchValue(`${this.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    const text = await response.text()
    if (!response.ok) throw new Error(`core ingress request failed (${response.status}): ${text.slice(0, 256)}`)
    return text
  }
}
