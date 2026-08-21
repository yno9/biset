import { equalBytes } from '../../protocol/canonical.ts'
import type { IngressAckV1, IngressEnvelopeV1 } from '../../protocol/ingress.ts'
import type { DeviceId, IdentityId, IngressId } from '../../protocol/ids.ts'
import { assertIngressAck, assertIngressEnvelope, ProtocolValidationError } from '../../protocol/validate.ts'

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
}

export interface IngressAckAuthorizer {
  /** Verifies both the device's current authorisation and its ACK signature. */
  verify(ack: IngressAckV1, envelope: IngressEnvelopeV1): Promise<boolean>
}

export interface IngressStore {
  offer(envelope: IngressEnvelopeV1): Promise<void>
  pull(identityId: IdentityId, deviceId: DeviceId, now?: Date): Promise<IngressEnvelopeV1[]>
  acknowledge(ack: IngressAckV1, now?: Date): Promise<IngressStatusRecord>
  expire(now?: Date): Promise<IngressStatusRecord[]>
  status(ingressId: IngressId): Promise<IngressStatusRecord | undefined>
}

interface Entry {
  envelope?: IngressEnvelopeV1
  status: IngressStatus
  identityId: IdentityId
  expiresAt: string
}

const DEFAULT_LIMITS: IngressStoreLimits = {
  maxPayloadBytes: 25 * 1024 * 1024,
  maxIdentityPayloadBytes: 100 * 1024 * 1024,
  maxIdentityPendingItems: 128,
}

/**
 * Reference implementation for the mediator's bounded ingress semantics.
 * Production persistence must preserve exactly the same transitions across a
 * restart; it may not turn a tombstone into a recoverable payload archive.
 */
export class MemoryIngressStore implements IngressStore {
  private readonly entries = new Map<IngressId, Entry>()

  constructor(
    private readonly authorizer: IngressAckAuthorizer,
    private readonly limits: IngressStoreLimits = DEFAULT_LIMITS,
  ) {}

  async offer(envelope: IngressEnvelopeV1): Promise<void> {
    assertIngressEnvelope(envelope)
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

  async pull(identityId: IdentityId, deviceId: DeviceId, now = new Date()): Promise<IngressEnvelopeV1[]> {
    await this.expire(now)
    return [...this.entries.values()]
      .filter((entry) => entry.status === 'pending' && entry.identityId === identityId && entry.envelope)
      .map((entry) => entry.envelope!)
      .filter((envelope) => envelope.recipientDeviceSnapshot.includes(deviceId))
      .map(copyEnvelope)
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
