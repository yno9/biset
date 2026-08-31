// Browser/client-side HTTP transport for the Conversation Group DS
// (mls-ds/http.ts), mirroring mls/coordinator-mls-delivery-transport.ts's
// shape exactly -- every method sends an already-signed control message
// (signing is the caller's job, using this device's group-local Ed25519
// key for this specific group -- conversation-mls-ds.ts's `GroupLocalId`)
// and decodes whatever the DS answers with, over
// protocol/conversation-mls-ds-wire.ts's shared encode/decode pair. No
// `deviceCredential`/`authenticated()` wrapper any more -- the group-local
// id embedded in each message IS the verification key, nothing else to attach.
import { defaultFetch } from '../net-fetch.ts'
import type {
  ConversationCommitSubmitV1,
  ConversationDeliveriesPullV1,
  ConversationDeliveriesWatchV1,
  ConversationGroupCreateV1,
  ConversationKeyPackageCountPullV1,
  ConversationKeyPackageDropV1,
  ConversationKeyPackagePublishV1,
  ConversationKeyPackageTakeV1,
  ConversationLogEntry,
  ConversationMessageSubmitV1,
  ConversationPendingRemovalsClearV1,
  ConversationSelfRemoveSubmitV1,
} from '../protocol/conversation-mls-ds.ts'
import {
  decodeConversationCommitRejectionWire,
  decodeConversationDeliveriesWatchTokenWire,
  decodeConversationDeliveriesWire,
  decodeConversationGroupRosterResultWire,
  decodeConversationKeyPackageCountResultWire,
  decodeConversationKeyPackageTakenWire,
  encodeConversationCommitSubmitWire,
  encodeConversationDeliveriesPullWire,
  encodeConversationDeliveriesWatchWire,
  encodeConversationGroupCreateWire,
  encodeConversationKeyPackageCountPullWire,
  encodeConversationKeyPackageDropWire,
  encodeConversationKeyPackagePublishWire,
  encodeConversationKeyPackageTakeWire,
  encodeConversationMessageSubmitWire,
  encodeConversationPendingRemovalsClearWire,
  encodeConversationSelfRemoveSubmitWire,
} from '../protocol/conversation-mls-ds-wire.ts'

export type ConversationDsCommitResult = { ok: true; roster: string[] } | { ok: false; reason: string; epoch: string }

export interface ConversationMlsDeliveryTransportOptions {
  baseUrl: string
  fetch?: typeof fetch
}

export class ConversationMlsDeliveryTransport {
  private readonly fetchValue: typeof fetch
  private readonly baseUrl: string

  constructor(options: ConversationMlsDeliveryTransportOptions) {
    if (!options.baseUrl) throw new TypeError('Conversation DS base URL is required')
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.fetchValue = options.fetch ?? defaultFetch()
  }

  async createGroup(input: ConversationGroupCreateV1): Promise<string[]> {
    return decodeConversationGroupRosterResultWire(await this.post('/v1/conversation-mls/group/create', encodeConversationGroupCreateWire(input))).roster
  }

  /** `ok: false` on a normal MLS tie-break loss (epoch-conflict) or an unauthorized sender -- never thrown, so a caller can retry against the new epoch. */
  submitCommit(input: ConversationCommitSubmitV1): Promise<ConversationDsCommitResult> {
    return this.postCommit('/v1/conversation-mls/commit/submit', encodeConversationCommitSubmitWire(input))
  }

  submitSelfRemove(input: ConversationSelfRemoveSubmitV1): Promise<ConversationDsCommitResult> {
    return this.postCommit('/v1/conversation-mls/self-remove/submit', encodeConversationSelfRemoveSubmitWire(input))
  }

  /** Application message log entry (mls-ds-1.0.md §5.1) -- the one operation
   * with no Self Group DS equivalent. Same accept/reject shape as a commit
   * (epoch-gated), even though it never advances the group epoch itself.
   * No fan-out any more -- every recipient learns of it via `pullDeliveries`. */
  submitMessage(input: ConversationMessageSubmitV1): Promise<ConversationDsCommitResult> {
    return this.postCommit('/v1/conversation-mls/message/submit', encodeConversationMessageSubmitWire(input))
  }

  async clearPendingRemovals(input: ConversationPendingRemovalsClearV1): Promise<void> {
    await this.post('/v1/conversation-mls/pending-removals/clear', encodeConversationPendingRemovalsClearWire(input))
  }

  async pullDeliveries(input: ConversationDeliveriesPullV1): Promise<ConversationLogEntry[]> {
    return decodeConversationDeliveriesWire(await this.post('/v1/conversation-mls/deliveries/pull', encodeConversationDeliveriesPullWire(input)))
  }

  /** Mints a short-lived token authorizing `streamUrl`'s `GET
   * /deliveries/stream` connection -- the request that CAN carry a
   * signature (`EventSource` itself can't). */
  async watchDeliveries(input: ConversationDeliveriesWatchV1): Promise<{ token: string; expiresAt: string }> {
    return decodeConversationDeliveriesWatchTokenWire(await this.post('/v1/conversation-mls/deliveries/watch', encodeConversationDeliveriesWatchWire(input)))
  }

  /** A plain URL, not a `fetch` call -- `EventSource` opens this itself
   * (mls/conversation-group-watch.ts). `token` must come from
   * `watchDeliveries`; `afterSeq` is the caller's own resume cursor (0 for
   * a fresh connection with no prior catch-up). */
  streamUrl(token: string, afterSeq: number): string {
    return `${this.baseUrl}/v1/conversation-mls/deliveries/stream?token=${encodeURIComponent(token)}&afterSeq=${afterSeq}`
  }

  async publishKeyPackages(input: ConversationKeyPackagePublishV1): Promise<number> {
    return decodeConversationKeyPackageCountResultWire(await this.post('/v1/conversation-mls/keypackage/publish', encodeConversationKeyPackagePublishWire(input))).count
  }

  async takeKeyPackage(input: ConversationKeyPackageTakeV1): Promise<{ keyPackage: Uint8Array } | undefined> {
    return decodeConversationKeyPackageTakenWire(await this.post('/v1/conversation-mls/keypackage/take', encodeConversationKeyPackageTakeWire(input)))
  }

  async dropKeyPackages(input: ConversationKeyPackageDropV1): Promise<void> {
    await this.post('/v1/conversation-mls/keypackage/drop', encodeConversationKeyPackageDropWire(input))
  }

  async keyPackageCount(input: ConversationKeyPackageCountPullV1): Promise<number> {
    return decodeConversationKeyPackageCountResultWire(await this.post('/v1/conversation-mls/keypackage/count', encodeConversationKeyPackageCountPullWire(input))).count
  }

  private async postCommit(path: string, body: string): Promise<ConversationDsCommitResult> {
    const response = await this.fetchValue(`${this.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    const text = await response.text()
    if (response.status === 201) return { ok: true, ...decodeConversationGroupRosterResultWire(text) }
    if (response.status === 403 || response.status === 409) return { ok: false, ...decodeConversationCommitRejectionWire(text) }
    throw new Error(`Conversation DS request failed (${response.status}): ${text.slice(0, 256)}`)
  }

  private async post(path: string, body: string): Promise<string> {
    const response = await this.fetchValue(`${this.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    const text = await response.text()
    if (!response.ok) throw new Error(`Conversation DS request failed (${response.status}): ${text.slice(0, 256)}`)
    return text
  }
}
