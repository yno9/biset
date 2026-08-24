import { defaultFetch } from '../net-fetch.ts'
// Browser transport for the MLS self-group DS narrow HTTP API
// (core/mediation/mls-delivery-http.ts), mirroring vault/core-ingress-transport.ts's
// shape. Every method sends an already-signed control message (signing is
// the caller's job, using this identity's MLS leaf key — see
// mls/webvh-authentication-service.ts and PLANMLSARCH.md §4.1.1) and decodes
// whatever core answers with, over protocol/mls-ds-wire.ts's shared
// encode/decode pair.
//
// Not yet used by anything: the endpoint-side self-group bootstrap (join a
// group, hold ClientState across a commit, retry on epoch-conflict) has not
// been written. This is only the wire.
import type {
  MlsCommitSubmissionV1,
  MlsDeliveriesPullV1,
  MlsExternalCommitSubmissionV1,
  MlsGroupCreationV1,
  MlsGroupInfoAnswer,
  MlsGroupInfoPullV1,
  MlsGroupsForPullV1,
  MlsKeyPackageCountPullV1,
  MlsKeyPackageDropV1,
  MlsKeyPackagePublishV1,
  MlsKeyPackageTakeV1,
  MlsLogEntry,
  MlsPendingRemovalsClearV1,
  MlsSelfRemoveSubmissionV1,
} from '../protocol/mls-ds.ts'
import {
  decodeMlsCommitRejectionWire,
  decodeMlsDeliveriesWire,
  decodeMlsGroupInfoAnswerWire,
  decodeMlsGroupRosterResultWire,
  decodeMlsGroupsForWire,
  decodeMlsKeyPackageCountResultWire,
  decodeMlsKeyPackagesTakenWire,
  encodeMlsCommitSubmissionWire,
  encodeMlsDeliveriesPullWire,
  encodeMlsExternalCommitSubmissionWire,
  encodeMlsGroupCreationWire,
  encodeMlsGroupInfoPullWire,
  encodeMlsGroupsForPullWire,
  encodeMlsKeyPackageCountPullWire,
  encodeMlsKeyPackageDropWire,
  encodeMlsKeyPackagePublishWire,
  encodeMlsKeyPackageTakeWire,
  encodeMlsPendingRemovalsClearWire,
  encodeMlsSelfRemoveSubmissionWire,
  type MlsGroupsForResultWire,
} from '../protocol/mls-ds-wire.ts'

export type MlsDsCommitResult = { ok: true; roster: string[] } | { ok: false; reason: string; epoch: string }

export interface CoreMlsDeliveryTransportOptions {
  baseUrl: string
  fetch?: typeof fetch
}

export class CoreMlsDeliveryTransport {
  private readonly fetchValue: typeof fetch
  private readonly baseUrl: string

  constructor(options: CoreMlsDeliveryTransportOptions) {
    if (!options.baseUrl) throw new TypeError('core MLS delivery base URL is required')
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.fetchValue = options.fetch ?? defaultFetch()
  }

  async createGroup(input: MlsGroupCreationV1): Promise<string[]> {
    return decodeMlsGroupRosterResultWire(await this.post('/v1/mls/group/create', encodeMlsGroupCreationWire(input))).roster
  }

  /** `ok: false` on a normal MLS tie-break loss (epoch-conflict) or an unauthorized sender — never thrown, so a caller can retry against the new epoch. */
  submitCommit(input: MlsCommitSubmissionV1): Promise<MlsDsCommitResult> {
    return this.postCommit('/v1/mls/commit/submit', encodeMlsCommitSubmissionWire(input))
  }

  submitExternalCommit(input: MlsExternalCommitSubmissionV1): Promise<MlsDsCommitResult> {
    return this.postCommit('/v1/mls/commit/external', encodeMlsExternalCommitSubmissionWire(input))
  }

  submitSelfRemove(input: MlsSelfRemoveSubmissionV1): Promise<MlsDsCommitResult> {
    return this.postCommit('/v1/mls/self-remove/submit', encodeMlsSelfRemoveSubmissionWire(input))
  }

  async pullGroupInfo(input: MlsGroupInfoPullV1): Promise<MlsGroupInfoAnswer> {
    return decodeMlsGroupInfoAnswerWire(await this.post('/v1/mls/group-info/pull', encodeMlsGroupInfoPullWire(input)))
  }

  async clearPendingRemovals(input: MlsPendingRemovalsClearV1): Promise<void> {
    await this.post('/v1/mls/pending-removals/clear', encodeMlsPendingRemovalsClearWire(input))
  }

  async pullDeliveries(input: MlsDeliveriesPullV1): Promise<MlsLogEntry[]> {
    return decodeMlsDeliveriesWire(await this.post('/v1/mls/deliveries/pull', encodeMlsDeliveriesPullWire(input)))
  }

  async publishKeyPackages(input: MlsKeyPackagePublishV1): Promise<number> {
    return decodeMlsKeyPackageCountResultWire(await this.post('/v1/mls/keypackage/publish', encodeMlsKeyPackagePublishWire(input))).count
  }

  async takeKeyPackages(input: MlsKeyPackageTakeV1): Promise<Array<{ kid: string; keyPackage: Uint8Array }>> {
    return decodeMlsKeyPackagesTakenWire(await this.post('/v1/mls/keypackage/take', encodeMlsKeyPackageTakeWire(input)))
  }

  async dropKeyPackages(input: MlsKeyPackageDropV1): Promise<void> {
    await this.post('/v1/mls/keypackage/drop', encodeMlsKeyPackageDropWire(input))
  }

  async keyPackageCount(input: MlsKeyPackageCountPullV1): Promise<number> {
    return decodeMlsKeyPackageCountResultWire(await this.post('/v1/mls/keypackage/count', encodeMlsKeyPackageCountPullWire(input))).count
  }

  async groupsFor(input: MlsGroupsForPullV1): Promise<MlsGroupsForResultWire[]> {
    return decodeMlsGroupsForWire(await this.post('/v1/mls/groups-for', encodeMlsGroupsForPullWire(input)))
  }

  private async postCommit(path: string, body: string): Promise<MlsDsCommitResult> {
    const response = await this.fetchValue(`${this.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    const text = await response.text()
    if (response.status === 201) return { ok: true, ...decodeMlsGroupRosterResultWire(text) }
    if (response.status === 403 || response.status === 409) return { ok: false, ...decodeMlsCommitRejectionWire(text) }
    throw new Error(`core MLS delivery request failed (${response.status}): ${text.slice(0, 256)}`)
  }

  private async post(path: string, body: string): Promise<string> {
    const response = await this.fetchValue(`${this.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    const text = await response.text()
    if (!response.ok) throw new Error(`core MLS delivery request failed (${response.status}): ${text.slice(0, 256)}`)
    return text
  }
}
