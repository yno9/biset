import { defaultFetch } from '../net-fetch.ts'
// Browser transport for the MLS self-group DS narrow HTTP API
// (coordinator/mls-delivery-http.ts), mirroring the other narrow transports'
// shape. Every method sends an already-signed control message (signing is
// the caller's job, using this identity's MLS leaf key — see
// mls/webvh-authentication-service.ts and PLANMLSARCH.md §4.1.1) and decodes
// whatever Coordinator answers with, over protocol/mls-ds-wire.ts's shared
// encode/decode pair.
//
// Used by identity creation/restore, boot maintenance, device revocation and
// did:webvh domain moves. Public roster projection remains a separate legacy
// transport until Anchor owns that control-plane state.
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

export interface CoordinatorMlsDeliveryTransportOptions {
  baseUrl: string
  /** Canonical Root-signed MLS BasicCredential identity bytes. */
  deviceCredential: Uint8Array
  fetch?: typeof fetch
}

export class CoordinatorMlsDeliveryTransport {
  private readonly fetchValue: typeof fetch
  private readonly baseUrl: string
  private readonly deviceCredential: Uint8Array

  constructor(options: CoordinatorMlsDeliveryTransportOptions) {
    if (!options.baseUrl) throw new TypeError('Coordinator MLS delivery base URL is required')
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    if (options.deviceCredential.length === 0) throw new TypeError('Coordinator MLS device credential is required')
    this.deviceCredential = options.deviceCredential.slice()
    this.fetchValue = options.fetch ?? defaultFetch()
  }

  async createGroup(input: MlsGroupCreationV1): Promise<string[]> {
    return decodeMlsGroupRosterResultWire(await this.post('/v1/mls/group/create', encodeMlsGroupCreationWire(this.authenticated(input)))).roster
  }

  /** `ok: false` on a normal MLS tie-break loss (epoch-conflict) or an unauthorized sender — never thrown, so a caller can retry against the new epoch. */
  submitCommit(input: MlsCommitSubmissionV1): Promise<MlsDsCommitResult> {
    return this.postCommit('/v1/mls/commit/submit', encodeMlsCommitSubmissionWire(this.authenticated(input)))
  }

  submitExternalCommit(input: MlsExternalCommitSubmissionV1): Promise<MlsDsCommitResult> {
    return this.postCommit('/v1/mls/commit/external', encodeMlsExternalCommitSubmissionWire(this.authenticated(input)))
  }

  submitSelfRemove(input: MlsSelfRemoveSubmissionV1): Promise<MlsDsCommitResult> {
    return this.postCommit('/v1/mls/self-remove/submit', encodeMlsSelfRemoveSubmissionWire(this.authenticated(input)))
  }

  async pullGroupInfo(input: MlsGroupInfoPullV1): Promise<MlsGroupInfoAnswer> {
    return decodeMlsGroupInfoAnswerWire(await this.post('/v1/mls/group-info/pull', encodeMlsGroupInfoPullWire(this.authenticated(input))))
  }

  async clearPendingRemovals(input: MlsPendingRemovalsClearV1): Promise<void> {
    await this.post('/v1/mls/pending-removals/clear', encodeMlsPendingRemovalsClearWire(this.authenticated(input)))
  }

  async pullDeliveries(input: MlsDeliveriesPullV1): Promise<MlsLogEntry[]> {
    return decodeMlsDeliveriesWire(await this.post('/v1/mls/deliveries/pull', encodeMlsDeliveriesPullWire(this.authenticated(input))))
  }

  async publishKeyPackages(input: MlsKeyPackagePublishV1): Promise<number> {
    return decodeMlsKeyPackageCountResultWire(await this.post('/v1/mls/keypackage/publish', encodeMlsKeyPackagePublishWire(this.authenticated(input)))).count
  }

  async takeKeyPackages(input: MlsKeyPackageTakeV1): Promise<Array<{ kid: string; keyPackage: Uint8Array }>> {
    return decodeMlsKeyPackagesTakenWire(await this.post('/v1/mls/keypackage/take', encodeMlsKeyPackageTakeWire(this.authenticated(input))))
  }

  async dropKeyPackages(input: MlsKeyPackageDropV1): Promise<void> {
    await this.post('/v1/mls/keypackage/drop', encodeMlsKeyPackageDropWire(this.authenticated(input)))
  }

  async keyPackageCount(input: MlsKeyPackageCountPullV1): Promise<number> {
    return decodeMlsKeyPackageCountResultWire(await this.post('/v1/mls/keypackage/count', encodeMlsKeyPackageCountPullWire(this.authenticated(input)))).count
  }

  async groupsFor(input: MlsGroupsForPullV1): Promise<MlsGroupsForResultWire[]> {
    return decodeMlsGroupsForWire(await this.post('/v1/mls/groups-for', encodeMlsGroupsForPullWire(this.authenticated(input))))
  }

  private authenticated<T extends object>(input: T): T & { deviceCredential: Uint8Array } {
    return { ...input, deviceCredential: this.deviceCredential }
  }

  private async postCommit(path: string, body: string): Promise<MlsDsCommitResult> {
    const response = await this.fetchValue(`${this.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    const text = await response.text()
    if (response.status === 201) return { ok: true, ...decodeMlsGroupRosterResultWire(text) }
    if (response.status === 403 || response.status === 409) return { ok: false, ...decodeMlsCommitRejectionWire(text) }
    throw new Error(`Coordinator MLS delivery request failed (${response.status}): ${text.slice(0, 256)}`)
  }

  private async post(path: string, body: string): Promise<string> {
    const response = await this.fetchValue(`${this.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    const text = await response.text()
    if (!response.ok) throw new Error(`Coordinator MLS delivery request failed (${response.status}): ${text.slice(0, 256)}`)
    return text
  }
}
