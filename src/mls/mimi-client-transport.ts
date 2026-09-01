/** Browser/client transport for a MIMI provider's local client boundary. */
import { defaultFetch } from '../net-fetch.ts'
import type { DeliveriesPullRequest, DeliveriesWatchRequest, KeyMaterialRequest, SubmitMessageRequest, UpdateRoomRequest, MimiDeliveryEntry } from '../mimi/protocol-types.ts'
import { decodeDeliveriesWire, decodeDeliveriesWatchTokenWire, decodeKeyMaterialResponseWire, decodeSubmitMessageResponseWire, decodeUpdateRoomResponseWire, encodeDeliveriesPullRequestWire, encodeDeliveriesWatchRequestWire, encodeKeyMaterialRequestWire, encodeSubmitMessageRequestWire, encodeUpdateRoomRequestWire } from '../mimi/wire.ts'

export interface MimiClientTransportOptions { normalBaseUrl: string; anonBaseUrl: string; fetch?: typeof fetch }
export type MimiClientMode = 'normal' | 'anon'

export class MimiClientTransport {
  private readonly fetchValue: typeof fetch
  private readonly baseUrls: Record<MimiClientMode, string>
  constructor(options: MimiClientTransportOptions) {
    if (!options.normalBaseUrl || !options.anonBaseUrl) throw new TypeError('normal and anon MIMI base URLs are required')
    this.baseUrls = { normal: options.normalBaseUrl.replace(/\/$/, ''), anon: options.anonBaseUrl.replace(/\/$/, '') }
    this.fetchValue = options.fetch ?? defaultFetch()
  }
  async update(mode: MimiClientMode, input: UpdateRoomRequest) { return decodeUpdateRoomResponseWire(await this.post(mode, `/update/${encodeURIComponent(input.roomId)}`, encodeUpdateRoomRequestWire(input))) }
  async keyMaterial(mode: MimiClientMode, input: KeyMaterialRequest) { return decodeKeyMaterialResponseWire(await this.post(mode, `/keyMaterial/${encodeURIComponent(input.targetUser)}`, encodeKeyMaterialRequestWire(input))) }
  async submitMessage(mode: MimiClientMode, input: SubmitMessageRequest) { return decodeSubmitMessageResponseWire(await this.post(mode, `/submitMessage/${encodeURIComponent(input.roomId)}`, encodeSubmitMessageRequestWire(input))) }
  async pullDeliveries(mode: MimiClientMode, input: DeliveriesPullRequest): Promise<MimiDeliveryEntry[]> { return decodeDeliveriesWire(await this.post(mode, '/v1/mimi/deliveries/pull', encodeDeliveriesPullRequestWire(input))) }
  async watchDeliveries(mode: MimiClientMode, input: DeliveriesWatchRequest): Promise<{ token: string; expiresAt: string }> { return decodeDeliveriesWatchTokenWire(await this.post(mode, '/v1/mimi/deliveries/watch', encodeDeliveriesWatchRequestWire(input))) }
  streamUrl(mode: MimiClientMode, token: string, afterSeq: number): string { if (!Number.isSafeInteger(afterSeq) || afterSeq < 0) throw new TypeError('delivery cursor is invalid'); return `${this.baseUrls[mode]}/v1/mimi/deliveries/stream?token=${encodeURIComponent(token)}&afterSeq=${afterSeq}` }
  private async post(mode: MimiClientMode, path: string, body: string): Promise<string> { const response = await this.fetchValue(`${this.baseUrls[mode]}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body }); const text = await response.text(); if (!response.ok) throw new Error(`MIMI request failed (${response.status}): ${text.slice(0, 256)}`); return text }
}
