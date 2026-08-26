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
  VaultDeliveryPullV1,
  VaultDeliveryItemV1,
} from '../../protocol/vault.ts'
import { assertVaultDeliveryAck, assertVaultDeliveryAppend, assertVaultDeliveryPull, ProtocolValidationError } from '../../protocol/validate.ts'
import { stableIdKey } from '../../identity/idkey.ts'

export interface VaultDeliveryStoreLimits {
  maxPayloadBytes: number
  maxIdentityPayloadBytes: number
  maxIdentityPendingItems: number
  /** Bounded relay retention chosen by core policy, never an append caller. */
  deliveryTtlMs: number
}

/**
 * Identity is the control plane. It decides whether a device is trusted and
 * the first sequence it may obtain through ordinary delivery. A newly added
 * device has a later floor and must restore older history from a peer/archive.
 */
export interface VaultDeliveryAuthorizer {
  deliveryFloor(identityId: IdentityId, deviceId: DeviceId): Promise<DeliverySeq | undefined>
  /** The core, rather than an untrusted append caller, freezes this snapshot. */
  recipientsAtAppend(identityId: IdentityId): Promise<DeviceId[]>
  verifyAppend(append: VaultDeliveryAppendV1): Promise<boolean>
  verifyPull(pull: VaultDeliveryPullV1): Promise<boolean>
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
  pull(input: VaultDeliveryPullV1, now?: Date): Promise<DeliveryPullResult>
  acknowledge(ack: VaultDeliveryAckV1, now?: Date): Promise<void>
  expire(now?: Date): Promise<void>
  status(identityId: IdentityId): Promise<VaultDeliveryStatus>
}

type EntryState = 'pending' | 'completed' | 'expired'

interface Entry {
  appendId: string
  item: VaultDeliveryItemV1
  recipientsAtAppend: Set<DeviceId>
  acknowledgements: Set<DeviceId>
  state: EntryState
  gapReason?: RestoreRequiredReason
}

interface IdentityState {
  latest: bigint
  entries: Map<bigint, Entry>
  entriesByAppendId: Map<string, Entry>
}

/**
 * 30 days: a device offline for longer than this falls back to peer/archive
 * restore (`restoreRequired`) rather than catching up through ordinary
 * delivery. Chosen to tolerate a long vacation/storage-drawer phone without
 * unbounded mediator retention -- product policy decision, 2026-08-24.
 */
const DEFAULT_LIMITS: VaultDeliveryStoreLimits = {
  maxPayloadBytes: 25 * 1024 * 1024,
  maxIdentityPayloadBytes: 100 * 1024 * 1024,
  maxIdentityPendingItems: 128,
  deliveryTtlMs: 30 * 24 * 60 * 60 * 1000,
}

/**
 * Reference implementation of shared vault delivery. Each Entry owns one
 * payload body; device-specific state is limited to an ACK set. Production
 * persistence must retain the same state transitions and gap semantics.
 *
 * Keyed by `stableIdKey(identityId)` (the SCID), not the raw identityId --
 * same reasoning as device-roster.ts's own MemoryTrustedDeviceRoster: a
 * did:webvh domain move changes the DID string one device at a time, and an
 * exact-string key would silently split one identity's pending delivery
 * queue into two the moment the first device's calls started using the new
 * string.
 */
export class MemoryVaultDeliveryStore implements VaultDeliveryStore {
  private readonly identities = new Map<IdentityId, IdentityState>()

  constructor(
    private readonly authorizer: VaultDeliveryAuthorizer,
    private readonly limits: VaultDeliveryStoreLimits = DEFAULT_LIMITS,
  ) {
    if (!Number.isSafeInteger(limits.deliveryTtlMs) || limits.deliveryTtlMs <= 0) throw new TypeError('deliveryTtlMs must be a positive safe integer')
  }

  async append(input: VaultDeliveryAppendV1, now = new Date()): Promise<VaultDeliveryItemV1> {
    assertVaultDeliveryAppend(input)
    if (!equalBytes(sha256Bytes(input.payload), input.payloadHash)) {
      throw new ProtocolValidationError('payloadHash must equal SHA-256(payload)')
    }
    if (!(await this.authorizer.verifyAppend(input))) {
      throw new ProtocolValidationError('delivery append is not authorised')
    }
    if (input.payload.length > this.limits.maxPayloadBytes) {
      throw new ProtocolValidationError('delivery payload exceeds maxPayloadBytes')
    }

    const existing = this.identities.get(stableIdKey(input.identityId))?.entriesByAppendId.get(input.appendId)
    if (existing) {
      if (!equalBytes(existing.item.payloadHash, input.payloadHash)) {
        throw new ProtocolValidationError('appendId is already bound to a different payload')
      }
      return copyItem(existing.item)
    }

    const recipientsAtAppend = await this.authorizer.recipientsAtAppend(input.identityId)
    if (recipientsAtAppend.length === 0 || new Set(recipientsAtAppend).size !== recipientsAtAppend.length || recipientsAtAppend.some(deviceId => !deviceId)) {
      throw new ProtocolValidationError('core returned an invalid recipient snapshot')
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
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + this.limits.deliveryTtlMs).toISOString(),
    }
    state.latest = seq
    const entry: Entry = {
      appendId: input.appendId,
      item,
      recipientsAtAppend: new Set(recipientsAtAppend),
      acknowledgements: new Set(),
      state: 'pending',
    }
    state.entries.set(seq, entry)
    state.entriesByAppendId.set(input.appendId, entry)
    this.enforceQuota(input.identityId, state)
    return copyItem(item)
  }

  async pull(input: VaultDeliveryPullV1, now = new Date()): Promise<DeliveryPullResult> {
    assertVaultDeliveryPull(input)
    if (!(await this.authorizer.verifyPull(input))) throw new ProtocolValidationError('delivery pull is not authorised')
    await this.expire(now)
    const { identityId, recipientDeviceId: deviceId, after } = input
    const floor = await this.authorizer.deliveryFloor(identityId, deviceId)
    if (!floor) throw new ProtocolValidationError('device is not trusted for this identity')

    const state = this.identities.get(stableIdKey(identityId))
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
    const state = this.identities.get(stableIdKey(ack.identityId))
    const sequence = BigInt(ack.seq)
    const entry = state?.entries.get(sequence)
    if (!entry) throw new ProtocolValidationError('unknown delivery sequence')
    if (!entry.recipientsAtAppend.has(ack.recipientDeviceId)) {
      throw new ProtocolValidationError('ACK device is not in the recipient snapshot')
    }
    if (!equalBytes(ack.payloadHash, entry.item.payloadHash)) {
      throw new ProtocolValidationError('ACK payload hash does not match delivery')
    }
    if (!(await this.authorizer.verifyAck(ack, entry.item))) {
      throw new ProtocolValidationError('ACK is not authorised')
    }
    // An accepted ACK can be retried after its core response was lost. Once a
    // completed entry has recorded this exact recipient acknowledgement, the
    // body has already been safely deleted and the retry is a no-op.
    if (entry.state === 'completed' && entry.acknowledgements.has(ack.recipientDeviceId)) return
    if (entry.state !== 'pending') throw new ProtocolValidationError(`delivery is already ${entry.state}`)

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
    const state = this.identities.get(stableIdKey(identityId))
    return {
      identityId,
      latestSeq: deliverySeq(state?.latest ?? 0n),
      retainedFrom: deliverySeq(this.retainedFrom(state)),
      payloadBytes: this.payloadBytes(state),
      pendingItems: this.pendingItems(state),
    }
  }

  private stateFor(identityId: IdentityId): IdentityState {
    const key = stableIdKey(identityId)
    let state = this.identities.get(key)
    if (!state) {
      state = { latest: 0n, entries: new Map(), entriesByAppendId: new Map() }
      this.identities.set(key, state)
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
