import { equalBytes, sha256Bytes } from '../../protocol/canonical.ts'
import type { IngressAckV1, IngressEnvelopeV1, IngressPullV1 } from '../../protocol/ingress.ts'
import type { IdentityId, IngressId } from '../../protocol/ids.ts'
import { assertIngressAck, assertIngressEnvelope, assertIngressPull, ProtocolValidationError } from '../../protocol/validate.ts'

export type IngressStatus = 'pending' | 'vault-ingested' | 'expired' | 'rejected'

export interface IngressStatusRecord {
  ingressId: IngressId
  identityId: IdentityId
  status: IngressStatus
  expiresAt: string
  payloadRetained: boolean
}

export interface IngressStoreLimits {
  maxPayloadBytes: number
  maxIdentityPayloadBytes: number
  maxIdentityPendingItems: number
  /** Short exclusive processing lease after an endpoint receives a body. */
  claimLeaseMs?: number
}

export interface IngressAuthorizer {
  /** Verifies a current device's signed pull before any body is exposed. */
  verifyPull(pull: IngressPullV1): Promise<boolean>
  /** Verifies both the device's current authorisation and its ACK signature. */
  verify(ack: IngressAckV1, envelope: IngressEnvelopeV1): Promise<boolean>
}

export interface IngressStore {
  offer(envelope: IngressEnvelopeV1): Promise<void>
  pull(pull: IngressPullV1, now?: Date): Promise<IngressEnvelopeV1[]>
  acknowledge(ack: IngressAckV1, now?: Date): Promise<IngressStatusRecord>
  expire(now?: Date): Promise<IngressStatusRecord[]>
  status(ingressId: IngressId): Promise<IngressStatusRecord | undefined>
}

interface Entry {
  envelope?: IngressEnvelopeV1
  status: IngressStatus
  identityId: IdentityId
  expiresAt: string
  claimDeviceId?: string
  claimExpiresAt?: string
}

const DEFAULT_LIMITS: IngressStoreLimits = {
  maxPayloadBytes: 25 * 1024 * 1024,
  maxIdentityPayloadBytes: 100 * 1024 * 1024,
  maxIdentityPendingItems: 128,
  claimLeaseMs: 60_000,
}

/**
 * Reference implementation for the mediator's bounded ingress semantics.
 * Production persistence must preserve exactly the same transitions across a
 * restart; it may not turn a tombstone into a recoverable payload archive.
 */
export class MemoryIngressStore implements IngressStore {
  private readonly entries = new Map<IngressId, Entry>()

  constructor(
    private readonly authorizer: IngressAuthorizer,
    private readonly limits: IngressStoreLimits = DEFAULT_LIMITS,
  ) {}

  async offer(envelope: IngressEnvelopeV1): Promise<void> {
    assertIngressEnvelope(envelope)
    if (!equalBytes(sha256Bytes(envelope.protectedPayload), envelope.protectedPayloadHash)) {
      throw new ProtocolValidationError('ingress protectedPayloadHash does not match payload')
    }
    const size = envelope.protectedPayload.length
    if (size > this.limits.maxPayloadBytes) {
      throw new ProtocolValidationError('ingress payload exceeds maxPayloadBytes')
    }

    const existing = this.entries.get(envelope.ingressId)
    if (existing) {
      if (existing.envelope && equalBytes(existing.envelope.protectedPayloadHash, envelope.protectedPayloadHash)) return
      throw new ProtocolValidationError('ingressId already exists with a different payload')
    }

    const pending = [...this.entries.values()].filter(
      (entry) => entry.status === 'pending' && entry.identityId === envelope.recipientIdentityId && entry.envelope,
    )
    if (pending.length >= this.limits.maxIdentityPendingItems) {
      throw new ProtocolValidationError('identity pending ingress item limit exceeded')
    }
    const pendingBytes = pending.reduce((total, entry) => total + (entry.envelope?.protectedPayload.length ?? 0), 0)
    if (pendingBytes + size > this.limits.maxIdentityPayloadBytes) {
      throw new ProtocolValidationError('identity pending ingress byte limit exceeded')
    }

    this.entries.set(envelope.ingressId, {
      envelope: copyEnvelope(envelope),
      status: 'pending',
      identityId: envelope.recipientIdentityId,
      expiresAt: envelope.expiresAt,
    })
  }

  async pull(pull: IngressPullV1, now = new Date()): Promise<IngressEnvelopeV1[]> {
    assertIngressPull(pull)
    await this.expire(now)
    if (!(await this.authorizer.verifyPull(pull))) throw new ProtocolValidationError('ingress pull is not authorised')
    const values: IngressEnvelopeV1[] = []
    for (const entry of this.entries.values()) {
      if (entry.status !== 'pending' || entry.identityId !== pull.identityId || !entry.envelope) continue
      if (!entry.envelope.recipientDeviceSnapshot.includes(pull.recipientDeviceId)) continue
      if (entry.claimExpiresAt && Date.parse(entry.claimExpiresAt) <= now.getTime()) {
        entry.claimDeviceId = undefined
        entry.claimExpiresAt = undefined
      }
      if (entry.claimDeviceId && entry.claimDeviceId !== pull.recipientDeviceId) continue
      entry.claimDeviceId = pull.recipientDeviceId
      entry.claimExpiresAt = leaseExpiry(now, entry.expiresAt, this.limits)
      values.push(copyEnvelope(entry.envelope))
    }
    return values
  }

  async acknowledge(ack: IngressAckV1, now = new Date()): Promise<IngressStatusRecord> {
    assertIngressAck(ack)
    await this.expire(now)
    const entry = this.entries.get(ack.ingressId)
    if (!entry) throw new ProtocolValidationError('unknown ingressId')
    if (entry.status !== 'pending' || !entry.envelope) {
      throw new ProtocolValidationError(`ingress is already ${entry.status}`)
    }
    if (!entry.envelope.recipientDeviceSnapshot.includes(ack.recipientDeviceId)) {
      throw new ProtocolValidationError('ACK device is not in the recipient snapshot')
    }
    if (entry.claimDeviceId !== ack.recipientDeviceId || !entry.claimExpiresAt || Date.parse(entry.claimExpiresAt) <= now.getTime()) {
      throw new ProtocolValidationError('ACK device does not hold the active ingress claim')
    }
    if (!equalBytes(ack.protectedPayloadHash, entry.envelope.protectedPayloadHash)) {
      throw new ProtocolValidationError('ACK payload hash does not match ingress')
    }
    if (!(await this.authorizer.verify(ack, entry.envelope))) {
      throw new ProtocolValidationError('ACK is not authorised')
    }

    entry.envelope = undefined
    entry.status = 'vault-ingested'
    return this.toStatus(ack.ingressId, entry)
  }

  async expire(now = new Date()): Promise<IngressStatusRecord[]> {
    const expired: IngressStatusRecord[] = []
    for (const [ingressId, entry] of this.entries) {
      if (entry.status !== 'pending' || Date.parse(entry.expiresAt) > now.getTime()) continue
      entry.envelope = undefined
      entry.status = 'expired'
      entry.claimDeviceId = undefined
      entry.claimExpiresAt = undefined
      expired.push(this.toStatus(ingressId, entry))
    }
    return expired
  }

  async status(ingressId: IngressId): Promise<IngressStatusRecord | undefined> {
    const entry = this.entries.get(ingressId)
    return entry ? this.toStatus(ingressId, entry) : undefined
  }

  private toStatus(ingressId: IngressId, entry: Entry): IngressStatusRecord {
    return {
      ingressId,
      identityId: entry.identityId,
      status: entry.status,
      expiresAt: entry.expiresAt,
      payloadRetained: entry.envelope !== undefined,
    }
  }
}

function leaseExpiry(now: Date, envelopeExpiresAt: string, limits: IngressStoreLimits): string {
  const duration = limits.claimLeaseMs ?? DEFAULT_LIMITS.claimLeaseMs!
  if (!Number.isSafeInteger(duration) || duration < 1) throw new TypeError('ingress claimLeaseMs must be a positive safe integer')
  return new Date(Math.min(now.getTime() + duration, Date.parse(envelopeExpiresAt))).toISOString()
}

function copyEnvelope(envelope: IngressEnvelopeV1): IngressEnvelopeV1 {
  return {
    ...envelope,
    recipientDeviceSnapshot: [...envelope.recipientDeviceSnapshot],
    transportMetadata: { ...envelope.transportMetadata },
    sourceEvidence: envelope.sourceEvidence.slice(),
    protectedPayload: envelope.protectedPayload.slice(),
    protectedPayloadHash: envelope.protectedPayloadHash.slice(),
  }
}
