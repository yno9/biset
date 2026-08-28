import { defaultFetch } from '../net-fetch.ts'
import {
  decodeVaultCoordinatorCheckpoint,
  decodeVaultCoordinatorOwnedVaults,
  decodeVaultCoordinatorPullResult,
  encodeVaultCoordinatorAck,
  encodeVaultCoordinatorAppend,
  encodeVaultCoordinatorCheckpointPull,
  encodeVaultCoordinatorCheckpointPut,
  encodeVaultCoordinatorPull,
  type VaultCoordinatorAckV1,
  type VaultCoordinatorAppendV1,
  type VaultCoordinatorCheckpointPullV1,
  type VaultCoordinatorCheckpointPutV1,
  type VaultCoordinatorCheckpointV1,
  type VaultCoordinatorOwnedVaultV1,
  type VaultCoordinatorPullResult,
  type VaultCoordinatorPullV1,
} from '../protocol/coordinator.ts'
import { assertDeliverySeq, type DeliverySeq } from '../protocol/ids.ts'
import { encodeVaultGroupView, type VaultGroupViewV1 } from '../protocol/vault-group-view.ts'
import {
  decodeVaultMlsKeyPackageList,
  decodeVaultMlsTransitionItems,
  decodeVaultMlsWelcomeDelivery,
  encodeVaultMlsKeyPackage,
  encodeVaultMlsMemberRequest,
  encodeVaultMlsTransition,
  type VaultMlsKeyPackagePublishV1,
  type VaultMlsMemberRequestV1,
  type VaultMlsTransitionItemV1,
  type VaultMlsTransitionV1,
  type VaultMlsWelcomeDeliveryV1,
  decodeVaultMlsInvitation,
  decodeVaultMlsInvitationRedemption,
  encodeVaultMlsInvitationRedeem,
  type VaultMlsInvitationRedeemV1,
  type VaultMlsInvitationV1,
} from '../protocol/vault-mls-ds.ts'
import {
  decodeVaultStream,
  decodeVaultStreamCheckpoint,
  decodeVaultStreamPullResult,
  encodeVaultStreamAppend,
  encodeVaultStreamCheckpointPut,
  encodeVaultStreamPull,
  type VaultStreamAppendV2,
  type VaultStreamCheckpointPutV2,
  type VaultStreamCheckpointV2,
  type VaultStreamPullResultV2,
  type VaultStreamPullV2,
  type VaultStreamV2,
} from '../protocol/coordinator-stream.ts'

export type VaultCoordinatorScope = 'vault.create' | 'vault.group.install' | 'vault.append' | 'vault.pull' | 'vault.ack'

export interface VaultCoordinatorAccessTokenProvider {
  getAccessToken(scope: VaultCoordinatorScope): Promise<string>
}

export interface VaultCoordinatorTransportOptions {
  baseUrl: string
  accessTokens: VaultCoordinatorAccessTokenProvider
  fetch?: typeof fetch
}

/** Browser-safe OAuth client for the identity-free Vault Coordinator API. */
export class VaultCoordinatorTransport {
  private readonly baseUrl: string
  private readonly fetchValue: typeof fetch

  constructor(private readonly options: VaultCoordinatorTransportOptions) {
    if (!options.baseUrl) throw new TypeError('Vault Coordinator base URL is required')
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.fetchValue = options.fetch ?? defaultFetch()
  }

  async defaultStream(): Promise<VaultStreamV2> {
    return decodeVaultStream(await this.postText('/v2/vaults/default', 'vault.create', JSON.stringify({ version: 2 })))
  }

  async appendStream(value: VaultStreamAppendV2): Promise<DeliverySeq> {
    const response = record(await this.post('/v2/entries/append', 'vault.append', encodeVaultStreamAppend(value)), ['seq'], 'stream append response')
    assertDeliverySeq(response.seq)
    return response.seq
  }

  async pullStream(value: VaultStreamPullV2): Promise<VaultStreamPullResultV2> {
    return decodeVaultStreamPullResult(await this.postText('/v2/entries/pull', 'vault.pull', encodeVaultStreamPull(value)))
  }

  async putStreamCheckpoint(value: VaultStreamCheckpointPutV2): Promise<void> {
    record(await this.post('/v2/checkpoints/put', 'vault.append', encodeVaultStreamCheckpointPut(value)), [], 'stream checkpoint put response')
  }

  async pullStreamCheckpoint(vaultId: import('../protocol/ids.ts').VaultId): Promise<VaultStreamCheckpointV2 | null> {
    return decodeVaultStreamCheckpoint(await this.postText('/v2/checkpoints/pull', 'vault.pull', JSON.stringify({ version: 2, vaultId })))
  }

  async createVault(view: VaultGroupViewV1): Promise<string> {
    return groupViewHash(await this.post('/v1/vaults', 'vault.create', encodeVaultGroupView(view)), 'create')
  }

  async ownedVaults(): Promise<VaultCoordinatorOwnedVaultV1[]> {
    return decodeVaultCoordinatorOwnedVaults(await this.postText('/v1/vaults/owned', 'vault.pull', JSON.stringify({ version: 1 })))
  }

  async putCheckpoint(value: VaultCoordinatorCheckpointPutV1): Promise<void> {
    record(await this.post('/v1/checkpoints/put', 'vault.append', encodeVaultCoordinatorCheckpointPut(value)), [], 'checkpoint put response')
  }

  async pullCheckpoint(value: VaultCoordinatorCheckpointPullV1): Promise<VaultCoordinatorCheckpointV1 | null> {
    return decodeVaultCoordinatorCheckpoint(await this.postText('/v1/checkpoints/pull', 'vault.pull', encodeVaultCoordinatorCheckpointPull(value)))
  }

  async publishMlsKeyPackage(value: VaultMlsKeyPackagePublishV1): Promise<void> {
    record(await this.post('/v1/mls/key-packages/publish', 'vault.group.install', encodeVaultMlsKeyPackage(value)), [], 'KeyPackage publish response')
  }

  async pullMlsKeyPackages(value: VaultMlsMemberRequestV1): Promise<VaultMlsKeyPackagePublishV1[]> {
    return decodeVaultMlsKeyPackageList(await this.postText('/v1/mls/key-packages/pull', 'vault.group.install', encodeVaultMlsMemberRequest(value)))
  }

  async installMlsTransition(value: VaultMlsTransitionV1): Promise<string> {
    return groupViewHash(await this.post('/v1/mls/transitions/install', 'vault.group.install', encodeVaultMlsTransition(value)), 'MLS transition install')
  }

  async pullMlsTransitions(value: VaultMlsMemberRequestV1): Promise<VaultMlsTransitionItemV1[]> {
    return decodeVaultMlsTransitionItems(await this.postText('/v1/mls/transitions/pull', 'vault.group.install', encodeVaultMlsMemberRequest(value)))
  }

  async pullMlsWelcome(value: VaultMlsMemberRequestV1): Promise<VaultMlsWelcomeDeliveryV1 | null> {
    return decodeVaultMlsWelcomeDelivery(await this.postText('/v1/mls/welcomes/pull', 'vault.group.install', encodeVaultMlsMemberRequest(value)))
  }

  async createMlsInvitation(value: VaultMlsMemberRequestV1): Promise<VaultMlsInvitationV1> {
    return decodeVaultMlsInvitation(await this.postText('/v1/mls/invitations/create', 'vault.group.install', encodeVaultMlsMemberRequest(value)))
  }

  async redeemMlsInvitation(value: VaultMlsInvitationRedeemV1): Promise<{ vaultId: import('../protocol/ids.ts').VaultId }> {
    return decodeVaultMlsInvitationRedemption(await this.postText('/v1/mls/invitations/redeem', 'vault.group.install', encodeVaultMlsInvitationRedeem(value)))
  }

  async append(value: VaultCoordinatorAppendV1): Promise<DeliverySeq> {
    const response = record(await this.post('/v1/deliveries/append', 'vault.append', encodeVaultCoordinatorAppend(value)), ['seq'], 'append response')
    assertDeliverySeq(response.seq)
    return response.seq
  }

  async pull(value: VaultCoordinatorPullV1): Promise<VaultCoordinatorPullResult> {
    return decodeVaultCoordinatorPullResult(await this.postText('/v1/deliveries/pull', 'vault.pull', encodeVaultCoordinatorPull(value)))
  }

  async acknowledge(value: VaultCoordinatorAckV1): Promise<void> {
    record(await this.post('/v1/deliveries/ack', 'vault.ack', encodeVaultCoordinatorAck(value)), [], 'ACK response')
  }

  private async post(path: string, scope: VaultCoordinatorScope, body: string): Promise<unknown> {
    const text = await this.postText(path, scope, body)
    try { return JSON.parse(text) } catch { throw new TypeError(`Vault Coordinator ${scope} response is not JSON`) }
  }

  private async postText(path: string, scope: VaultCoordinatorScope, body: string): Promise<string> {
    const token = await this.options.accessTokens.getAccessToken(scope)
    if (!token || /[\r\n]/.test(token)) throw new TypeError('Vault Coordinator access token is invalid')
    const response = await this.fetchValue(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body,
    })
    const text = await response.text()
    if (!response.ok) throw new Error(`Vault Coordinator ${scope} request failed (${response.status}): ${text.slice(0, 256)}`)
    return text
  }
}

function groupViewHash(value: unknown, operation: string): string {
  const response = record(value, ['groupViewHash'], `${operation} response`)
  if (typeof response.groupViewHash !== 'string' || !/^sha256:[A-Za-z0-9_-]{43}$/.test(response.groupViewHash)) throw new TypeError(`Vault Coordinator ${operation} response has invalid groupViewHash`)
  return response.groupViewHash
}

function record(value: unknown, keys: string[], name: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`Vault Coordinator ${name} must be an object`)
  const result = value as Record<string, unknown>
  const actual = Object.keys(result).sort()
  const expected = [...keys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new TypeError(`Vault Coordinator ${name} has unexpected fields`)
  return result
}
