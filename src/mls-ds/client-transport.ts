// Browser/client-side HTTP transport for the Conversation Group DS
// (mls-ds/http.ts), mirroring mls/coordinator-mls-delivery-transport.ts's
// shape exactly -- every method sends an already-signed control message
// (signing is the caller's job, using this identity's MLS leaf key) and
// decodes whatever the DS answers with, over
// protocol/conversation-mls-ds-wire.ts's shared encode/decode pair.
//
// No `identityId` anywhere (PLAN_biset-mls-ds.md §7) -- `authenticated`
// only attaches `deviceCredential`, unlike the Self Group version's
// implicit identityId binding.
import { defaultFetch } from '../net-fetch.ts'
import type {
  ConversationCommitSubmitV1,
  ConversationDeliveriesPullV1,
  ConversationExternalCommitSubmitV1,
  ConversationGroupCreateV1,
  ConversationGroupInfoAnswer,
  ConversationGroupInfoPullV1,
  ConversationGroupsForPullV1,
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
  decodeConversationDeliveriesWire,
  decodeConversationGroupInfoAnswerWire,
  decodeConversationGroupRosterResultWire,
  decodeConversationGroupsForWire,
  decodeConversationKeyPackageCountResultWire,
  decodeConversationKeyPackageTakenWire,
  encodeConversationCommitSubmitWire,
  encodeConversationDeliveriesPullWire,
  encodeConversationExternalCommitSubmitWire,
  encodeConversationGroupCreateWire,
  encodeConversationGroupInfoPullWire,
  encodeConversationGroupsForPullWire,
  encodeConversationKeyPackageCountPullWire,
  encodeConversationKeyPackageDropWire,
  encodeConversationKeyPackagePublishWire,
  encodeConversationKeyPackageTakeWire,
  encodeConversationMessageSubmitWire,
  encodeConversationPendingRemovalsClearWire,
  encodeConversationSelfRemoveSubmitWire,
  type ConversationGroupsForResultWire,
} from '../protocol/conversation-mls-ds-wire.ts'

export type ConversationDsCommitResult = { ok: true; roster: string[] } | { ok: false; reason: string; epoch: string }

export interface ConversationMlsDeliveryTransportOptions {
  baseUrl: string
  /** Canonical generation-bound MLS BasicCredential identity bytes -- the
   * same shape Self Group control messages sign with, no group-specific
   * variant. */
  deviceCredential: Uint8Array
  fetch?: typeof fetch
}

export class ConversationMlsDeliveryTransport {
  private readonly fetchValue: typeof fetch
  private readonly baseUrl: string
  private readonly deviceCredential: Uint8Array

  constructor(options: ConversationMlsDeliveryTransportOptions) {
    if (!options.baseUrl) throw new TypeError('Conversation DS base URL is required')
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    if (options.deviceCredential.length === 0) throw new TypeError('Conversation DS device credential is required')
    this.deviceCredential = options.deviceCredential.slice()
    this.fetchValue = options.fetch ?? defaultFetch()
  }

  async createGroup(input: ConversationGroupCreateV1): Promise<string[]> {
    return decodeConversationGroupRosterResultWire(await this.post('/v1/conversation-mls/group/create', encodeConversationGroupCreateWire(this.authenticated(input)))).roster
  }

  /** `ok: false` on a normal MLS tie-break loss (epoch-conflict) or an unauthorized sender -- never thrown, so a caller can retry against the new epoch. */
  submitCommit(input: ConversationCommitSubmitV1): Promise<ConversationDsCommitResult> {
    return this.postCommit('/v1/conversation-mls/commit/submit', encodeConversationCommitSubmitWire(this.authenticated(input)))
  }

  submitExternalCommit(input: ConversationExternalCommitSubmitV1): Promise<ConversationDsCommitResult> {
    return this.postCommit('/v1/conversation-mls/commit/external', encodeConversationExternalCommitSubmitWire(this.authenticated(input)))
  }

  submitSelfRemove(input: ConversationSelfRemoveSubmitV1): Promise<ConversationDsCommitResult> {
    return this.postCommit('/v1/conversation-mls/self-remove/submit', encodeConversationSelfRemoveSubmitWire(this.authenticated(input)))
  }

  /** Application message fan-out (mls-ds-1.0.md §5.1) -- the one operation
   * with no Self Group DS equivalent. Same accept/reject shape as a commit
   * (epoch-gated), even though it never advances the group epoch itself. */
  submitMessage(input: ConversationMessageSubmitV1): Promise<ConversationDsCommitResult> {
    return this.postCommit('/v1/conversation-mls/message/submit', encodeConversationMessageSubmitWire(this.authenticated(input)))
  }

  async pullGroupInfo(input: ConversationGroupInfoPullV1): Promise<ConversationGroupInfoAnswer> {
    return decodeConversationGroupInfoAnswerWire(await this.post('/v1/conversation-mls/group-info/pull', encodeConversationGroupInfoPullWire(this.authenticated(input))))
  }

  async clearPendingRemovals(input: ConversationPendingRemovalsClearV1): Promise<void> {
    await this.post('/v1/conversation-mls/pending-removals/clear', encodeConversationPendingRemovalsClearWire(this.authenticated(input)))
  }

  async pullDeliveries(input: ConversationDeliveriesPullV1): Promise<ConversationLogEntry[]> {
    return decodeConversationDeliveriesWire(await this.post('/v1/conversation-mls/deliveries/pull', encodeConversationDeliveriesPullWire(this.authenticated(input))))
  }

  async publishKeyPackages(input: ConversationKeyPackagePublishV1): Promise<number> {
    return decodeConversationKeyPackageCountResultWire(await this.post('/v1/conversation-mls/keypackage/publish', encodeConversationKeyPackagePublishWire(this.authenticated(input)))).count
  }

  async takeKeyPackage(input: ConversationKeyPackageTakeV1): Promise<{ keyPackage: Uint8Array } | undefined> {
    return decodeConversationKeyPackageTakenWire(await this.post('/v1/conversation-mls/keypackage/take', encodeConversationKeyPackageTakeWire(this.authenticated(input))))
  }

  async dropKeyPackages(input: ConversationKeyPackageDropV1): Promise<void> {
    await this.post('/v1/conversation-mls/keypackage/drop', encodeConversationKeyPackageDropWire(this.authenticated(input)))
  }

  async keyPackageCount(input: ConversationKeyPackageCountPullV1): Promise<number> {
    return decodeConversationKeyPackageCountResultWire(await this.post('/v1/conversation-mls/keypackage/count', encodeConversationKeyPackageCountPullWire(this.authenticated(input)))).count
  }

  async groupsFor(input: ConversationGroupsForPullV1): Promise<ConversationGroupsForResultWire[]> {
    return decodeConversationGroupsForWire(await this.post('/v1/conversation-mls/groups-for', encodeConversationGroupsForPullWire(this.authenticated(input))))
  }

  private authenticated<T extends object>(input: T): T & { deviceCredential: Uint8Array } {
    return { ...input, deviceCredential: this.deviceCredential }
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
