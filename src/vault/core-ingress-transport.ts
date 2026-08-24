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
    await this.post('/v1/ingress/ack', encodeIngressAckWire(input))
  }

  private async post(path: string, body: string): Promise<string> {
    const response = await this.fetchValue(`${this.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    const text = await response.text()
    if (!response.ok) throw new Error(`core ingress request failed (${response.status}): ${text.slice(0, 256)}`)
    return text
  }
}
