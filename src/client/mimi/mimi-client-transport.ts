/** Browser/client transport for a MIMI provider's local client boundary. */
import { defaultFetch } from '../app/net-fetch.ts'
import type { DeliveriesPullRequest, DeliveriesWatchRequest, GroupInfoRequest, KeyMaterialRequest, KeyPackagePublishRequest, SubmitMessageRequest, SubmitVaultCheckpointRequest, UpdateRoomRequest, MimiDeliveryEntry } from '../../shared/mimi/protocol-types.ts'
import { decodeDeliveriesWire, decodeDeliveriesWatchTokenWire, decodeFrankingAgentDataWire, decodeGroupInfoResponseWire, decodeKeyMaterialResponseWire, decodeKeyPackagePublishResponseWire, decodeSubmitMessageResponseWire, decodeSubmitVaultCheckpointResponseWire, decodeUpdateRoomResponseWire, encodeDeliveriesPullRequestWire, encodeDeliveriesWatchRequestWire, encodeGroupInfoRequestWire, encodeKeyMaterialRequestWire, encodeKeyPackagePublishWire, encodeSubmitMessageRequestWire, encodeSubmitVaultCheckpointRequestWire, encodeUpdateRoomRequestWire } from '../../shared/mimi/wire.ts'

export interface MimiClientTransportOptions {
  normalBaseUrl: string
  anonBaseUrl: string
  /** Dedicated normal-mode endpoint for the one-user Self/Vault room. */
  selfBaseUrl?: string
  fetch?: typeof fetch
}
export type MimiClientMode = 'normal' | 'anon' | 'self'

export class MimiClientTransport {
  private readonly fetchValue: typeof fetch
  private readonly baseUrls: Record<MimiClientMode, string>
  constructor(options: MimiClientTransportOptions) {
    if (!options.normalBaseUrl || !options.anonBaseUrl) throw new TypeError('normal and anon MIMI base URLs are required')
    this.baseUrls = {
      normal: options.normalBaseUrl.replace(/\/$/, ''),
      anon: options.anonBaseUrl.replace(/\/$/, ''),
      self: (options.selfBaseUrl ?? options.normalBaseUrl).replace(/\/$/, ''),
    }
    this.fetchValue = options.fetch ?? defaultFetch()
  }
  async update(mode: MimiClientMode, input: UpdateRoomRequest) { return decodeUpdateRoomResponseWire(await this.post(mode, `/update/${encodeURIComponent(input.roomId)}`, encodeUpdateRoomRequestWire(input))) }
  async frankingAgent(mode: MimiClientMode, roomId: string) { return decodeFrankingAgentDataWire(await this.get(mode, `/v1/mimi/franking-agent/${encodeURIComponent(roomId)}`)) }
  async groupInfo(mode: MimiClientMode, roomId: string, input: GroupInfoRequest) { return decodeGroupInfoResponseWire(await this.post(mode, `/groupInfo/${encodeURIComponent(roomId)}`, encodeGroupInfoRequestWire(input))) }
  async keyMaterial(mode: MimiClientMode, input: KeyMaterialRequest) { return decodeKeyMaterialResponseWire(await this.post(mode, `/keyMaterial/${encodeURIComponent(input.targetUser)}`, encodeKeyMaterialRequestWire(input))) }
  /** Biset's own extension (§5.1, PLAN_biset-mimi-server.md) -- publishes
   * this client's own spare KeyPackages so someone else can later add it to
   * a room via `keyMaterial`. The MIMI draft leaves this client-server step
   * unspecified. */
  async publishKeyPackages(mode: MimiClientMode, input: KeyPackagePublishRequest) { return decodeKeyPackagePublishResponseWire(await this.post(mode, '/v1/mimi/keypackage/publish', encodeKeyPackagePublishWire(input))) }
  async submitMessage(mode: MimiClientMode, input: SubmitMessageRequest) { return decodeSubmitMessageResponseWire(await this.post(mode, `/submitMessage/${encodeURIComponent(input.roomId)}`, encodeSubmitMessageRequestWire(input))) }
  async submitVaultCheckpoint(mode: MimiClientMode, input: SubmitVaultCheckpointRequest) { return decodeSubmitVaultCheckpointResponseWire(await this.post(mode, `/v1/mimi/vault-checkpoint/${encodeURIComponent(input.roomId)}`, encodeSubmitVaultCheckpointRequestWire(input))) }
  async pullDeliveries(mode: MimiClientMode, input: DeliveriesPullRequest): Promise<MimiDeliveryEntry[]> { return decodeDeliveriesWire(await this.post(mode, '/v1/mimi/deliveries/pull', encodeDeliveriesPullRequestWire(input))) }
  async watchDeliveries(mode: MimiClientMode, input: DeliveriesWatchRequest): Promise<{ token: string; expiresAt: string }> { return decodeDeliveriesWatchTokenWire(await this.post(mode, '/v1/mimi/deliveries/watch', encodeDeliveriesWatchRequestWire(input))) }
  streamUrl(mode: MimiClientMode, token: string, afterSeq: number): string { if (!Number.isSafeInteger(afterSeq) || afterSeq < 0) throw new TypeError('delivery cursor is invalid'); return `${this.baseUrls[mode]}/v1/mimi/deliveries/stream?token=${encodeURIComponent(token)}&afterSeq=${afterSeq}` }
  private async post(mode: MimiClientMode, path: string, body: string): Promise<string> { const response = await this.fetchValue(`${this.baseUrls[mode]}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body }); const text = await response.text(); if (!response.ok) throw new Error(`MIMI request failed (${response.status}): ${text.slice(0, 256)}`); return text }
  private async get(mode: MimiClientMode, path: string): Promise<string> { const response = await this.fetchValue(`${this.baseUrls[mode]}${path}`); const text = await response.text(); if (!response.ok) throw new Error(`MIMI request failed (${response.status}): ${text.slice(0, 256)}`); return text }
}
