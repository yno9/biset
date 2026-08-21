import { equalBytes, sha256Bytes } from '../../protocol/canonical.ts'
import {
  assertDeliverySeq,
  deliverySeq,
  type DeliverySeq,
  type DeviceId,
  type IdentityId,
} from '../../protocol/ids.ts'
import type {
  DeliveryPullResult,
  RestoreRequiredReason,
  VaultDeliveryAckV1,
  VaultDeliveryAppendV1,
  VaultDeliveryItemV1,
} from '../../protocol/vault.ts'
import { assertVaultDeliveryAck, assertVaultDeliveryAppend, ProtocolValidationError } from '../../protocol/validate.ts'

export interface VaultDeliveryStoreLimits {
  maxPayloadBytes: number
  maxIdentityPayloadBytes: number
  maxIdentityPendingItems: number
}

/**
 * Identity is the control plane. It decides whether a device is trusted and
 * the first sequence it may obtain through ordinary delivery. A newly added
 * device has a later floor and must restore older history from a peer/archive.
 */
export interface VaultDeliveryAuthorizer {
  deliveryFloor(identityId: IdentityId, deviceId: DeviceId): Promise<DeliverySeq | undefined>
  verifyRecipients(identityId: IdentityId, deviceIds: DeviceId[]): Promise<boolean>
  verifyAck(ack: VaultDeliveryAckV1, item: VaultDeliveryItemV1): Promise<boolean>
}

export interface VaultDeliveryStatus {
  identityId: IdentityId
  latestSeq: DeliverySeq
  retainedFrom: DeliverySeq
  payloadBytes: number
  pendingItems: number
}

export interface VaultDeliveryStore {
  append(input: VaultDeliveryAppendV1, now?: Date): Promise<VaultDeliveryItemV1>
  pull(identityId: IdentityId, deviceId: DeviceId, after: DeliverySeq, now?: Date): Promise<DeliveryPullResult>
  acknowledge(ack: VaultDeliveryAckV1, now?: Date): Promise<void>
  expire(now?: Date): Promise<void>
  status(identityId: IdentityId): Promise<VaultDeliveryStatus>
}

type EntryState = 'pending' | 'completed' | 'expired'

interface Entry {
  item: VaultDeliveryItemV1
  recipientsAtAppend: Set<DeviceId>
  acknowledgements: Set<DeviceId>
  state: EntryState
  gapReason?: RestoreRequiredReason
}

interface IdentityState {
  latest: bigint
  entries: Map<bigint, Entry>
}

const DEFAULT_LIMITS: VaultDeliveryStoreLimits = {
  maxPayloadBytes: 25 * 1024 * 1024,
  maxIdentityPayloadBytes: 100 * 1024 * 1024,
  maxIdentityPendingItems: 128,
}

/**
 * Reference implementation of shared vault delivery. Each Entry owns one
 * payload body; device-specific state is limited to an ACK set. Production
 * persistence must retain the same state transitions and gap semantics.
 */
export class MemoryVaultDeliveryStore implements VaultDeliveryStore {
  private readonly identities = new Map<IdentityId, IdentityState>()

  constructor(
    private readonly authorizer: VaultDeliveryAuthorizer,
    private readonly limits: VaultDeliveryStoreLimits = DEFAULT_LIMITS,
  ) {}

  async append(input: VaultDeliveryAppendV1, now = new Date()): Promise<VaultDeliveryItemV1> {
    assertVaultDeliveryAppend(input)
    if (!equalBytes(sha256Bytes(input.payload), input.payloadHash)) {
      throw new ProtocolValidationError('payloadHash must equal SHA-256(payload)')
    }
    if (input.payload.length > this.limits.maxPayloadBytes) {
      throw new ProtocolValidationError('delivery payload exceeds maxPayloadBytes')
    }
    if (!(await this.authorizer.verifyRecipients(input.identityId, input.recipientsAtAppend))) {
      throw new ProtocolValidationError('recipient snapshot is not authorised')
    }

    await this.expire(now)
    const state = this.stateFor(input.identityId)
    const seq = state.latest + 1n
    const item: VaultDeliveryItemV1 = {
      version: 1,
      identityId: input.identityId,
      seq: deliverySeq(seq),
      payload: input.payload.slice(),
      payloadHash: input.payloadHash.slice(),
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
    }
    state.latest = seq
    state.entries.set(seq, {
      item,
      recipientsAtAppend: new Set(input.recipientsAtAppend),
      acknowledgements: new Set(),
      state: 'pending',
    })
    this.enforceQuota(input.identityId, state)
    return copyItem(item)
  }

  async pull(identityId: IdentityId, deviceId: DeviceId, after: DeliverySeq, now = new Date()): Promise<DeliveryPullResult> {
    try {
      assertDeliverySeq(after)
    } catch {
      throw new ProtocolValidationError('after must be an unsigned 64-bit decimal string')
    }
    await this.expire(now)
    const floor = await this.authorizer.deliveryFloor(identityId, deviceId)
    if (!floor) throw new ProtocolValidationError('device is not trusted for this identity')

    const state = this.identities.get(identityId)
    const latest = state?.latest ?? 0n
    const retainedFrom = this.retainedFrom(state)
    const requested = BigInt(after)
    const firstNormalDelivery = BigInt(floor)

    if (requested < firstNormalDelivery - 1n) {
      return this.restoreRequired(after, retainedFrom, latest, 'new-device')
    }
    if (requested < retainedFrom - 1n) {
      return this.restoreRequired(after, retainedFrom, latest, this.gapReason(state, requested + 1n))
    }
    if (!state) return this.items([], after, retainedFrom, latest)

    const items: VaultDeliveryItemV1[] = []
    for (const [seq, entry] of state.entries) {
      if (seq <= requested || entry.state !== 'pending') continue
      if (!entry.recipientsAtAppend.has(deviceId) || entry.acknowledgements.has(deviceId)) continue
      items.push(copyItem(entry.item))
    }
    const nextCursor = items.length === 0 ? after : items[items.length - 1].seq
    return this.items(items, nextCursor, retainedFrom, latest)
  }

  async acknowledge(ack: VaultDeliveryAckV1, now = new Date()): Promise<void> {
    assertVaultDeliveryAck(ack)
    await this.expire(now)
    const state = this.identities.get(ack.identityId)
    const sequence = BigInt(ack.seq)
    const entry = state?.entries.get(sequence)
    if (!entry) throw new ProtocolValidationError('unknown delivery sequence')
    if (entry.state !== 'pending') throw new ProtocolValidationError(`delivery is already ${entry.state}`)
    if (!entry.recipientsAtAppend.has(ack.recipientDeviceId)) {
      throw new ProtocolValidationError('ACK device is not in the recipient snapshot')
    }
    if (!equalBytes(ack.payloadHash, entry.item.payloadHash)) {
      throw new ProtocolValidationError('ACK payload hash does not match delivery')
    }
    if (!(await this.authorizer.verifyAck(ack, entry.item))) {
      throw new ProtocolValidationError('ACK is not authorised')
    }

    entry.acknowledgements.add(ack.recipientDeviceId)
    if (entry.acknowledgements.size === entry.recipientsAtAppend.size) {
      entry.item.payload = new Uint8Array()
      entry.state = 'completed'
      entry.gapReason = 'delivery-confirmed'
    }
  }

  async expire(now = new Date()): Promise<void> {
    for (const state of this.identities.values()) {
      for (const entry of state.entries.values()) {
        if (entry.state !== 'pending' || Date.parse(entry.item.expiresAt) > now.getTime()) continue
        entry.item.payload = new Uint8Array()
        entry.state = 'expired'
        entry.gapReason = 'ttl-expired'
      }
    }
  }

  async status(identityId: IdentityId): Promise<VaultDeliveryStatus> {
    const state = this.identities.get(identityId)
    return {
      identityId,
      latestSeq: deliverySeq(state?.latest ?? 0n),
      retainedFrom: deliverySeq(this.retainedFrom(state)),
      payloadBytes: this.payloadBytes(state),
      pendingItems: this.pendingItems(state),
    }
  }

  private stateFor(identityId: IdentityId): IdentityState {
    let state = this.identities.get(identityId)
    if (!state) {
      state = { latest: 0n, entries: new Map() }
      this.identities.set(identityId, state)
    }
    return state
  }

  private retainedFrom(state: IdentityState | undefined): bigint {
    if (!state) return 1n
    for (const [seq, entry] of state.entries) if (entry.state === 'pending') return seq
    return state.latest + 1n
  }

  private gapReason(state: IdentityState | undefined, firstMissing: bigint): RestoreRequiredReason {
    const reason = state?.entries.get(firstMissing)?.gapReason
    return reason ?? 'ttl-expired'
  }

  private payloadBytes(state: IdentityState | undefined): number {
    if (!state) return 0
    let total = 0
    for (const entry of state.entries.values()) if (entry.state === 'pending') total += entry.item.payload.length
    return total
  }

  private pendingItems(state: IdentityState | undefined): number {
    if (!state) return 0
    let total = 0
    for (const entry of state.entries.values()) if (entry.state === 'pending') total += 1
    return total
  }

  private enforceQuota(identityId: IdentityId, state: IdentityState): void {
    while (
      this.pendingItems(state) > this.limits.maxIdentityPendingItems
      || this.payloadBytes(state) > this.limits.maxIdentityPayloadBytes
    ) {
      const oldest = [...state.entries.values()].find((entry) => entry.state === 'pending')
      if (!oldest) throw new ProtocolValidationError(`cannot enforce delivery quota for ${identityId}`)
      oldest.item.payload = new Uint8Array()
      oldest.state = 'expired'
      oldest.gapReason = 'retention-quota'
    }
  }

  private restoreRequired(
    requestedCursor: DeliverySeq,
    retainedFrom: bigint,
    latest: bigint,
    reason: RestoreRequiredReason,
  ): DeliveryPullResult {
    return {
      kind: 'restoreRequired',
      requestedCursor,
      retainedFrom: deliverySeq(retainedFrom),
      latestSeq: deliverySeq(latest),
      reason,
    }
  }

  private items(
    items: VaultDeliveryItemV1[],
    nextCursor: DeliverySeq,
    retainedFrom: bigint,
    latest: bigint,
  ): DeliveryPullResult {
    return {
      kind: 'items',
      items,
      nextCursor,
      retainedFrom: deliverySeq(retainedFrom),
      latestSeq: deliverySeq(latest),
    }
  }
}

function copyItem(item: VaultDeliveryItemV1): VaultDeliveryItemV1 {
  return { ...item, payload: item.payload.slice(), payloadHash: item.payloadHash.slice() }
}
