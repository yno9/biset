import type { DeviceId, IdentityId } from '../../protocol/ids.ts'
import type { RestoreCancelV1, RestoreOfferV1, RestoreRequestV1 } from '../../protocol/vault.ts'
import {
  assertRestoreCancel,
  assertRestoreOffer,
  assertRestoreRequest,
  ProtocolValidationError,
} from '../../protocol/validate.ts'

/**
 * The MLS/self-group integration belongs behind this authorizer. The mediator
 * only decides whether a short control message may be relayed; it cannot
 * inspect or provide vault content.
 */
export interface RestoreControlAuthorizer {
  isTrustedDevice(identityId: IdentityId, deviceId: DeviceId): Promise<boolean>
  verifyRequest(request: RestoreRequestV1): Promise<boolean>
  verifyOffer(offer: RestoreOfferV1): Promise<boolean>
  verifyCancel(cancel: RestoreCancelV1, request: RestoreRequestV1): Promise<boolean>
}

export interface RestoreControlStore {
  request(input: RestoreRequestV1, now?: Date): Promise<void>
  pullRequests(identityId: IdentityId, peerDeviceId: DeviceId, now?: Date): Promise<RestoreRequestV1[]>
  offer(input: RestoreOfferV1, now?: Date): Promise<void>
  pullOffers(identityId: IdentityId, requesterDeviceId: DeviceId, now?: Date): Promise<RestoreOfferV1[]>
  cancel(input: RestoreCancelV1, now?: Date): Promise<void>
  expire(now?: Date): Promise<void>
}

interface RequestEntry {
  request: RestoreRequestV1
  offers: Map<DeviceId, RestoreOfferV1>
}

/**
 * Reference short-lived control plane. It deliberately has no API accepting
 * a manifest, ciphertext, attachment, or transfer chunk.
 */
export class MemoryRestoreControlStore implements RestoreControlStore {
  private readonly requests = new Map<string, RequestEntry>()

  constructor(private readonly authorizer: RestoreControlAuthorizer) {}

  async request(input: RestoreRequestV1, now = new Date()): Promise<void> {
    assertRestoreRequest(input)
    await this.expire(now)
    if (Date.parse(input.expiresAt) <= now.getTime()) throw new ProtocolValidationError('restore request is already expired')
    if (!(await this.authorizer.isTrustedDevice(input.identityId, input.requesterDeviceId))) {
      throw new ProtocolValidationError('restore requester is not trusted')
    }
    if (!(await this.authorizer.verifyRequest(input))) throw new ProtocolValidationError('restore request signature is invalid')
    const key = requestKey(input.identityId, input.requestId)
    const existing = this.requests.get(key)
    if (existing) {
      if (!sameRequest(existing.request, input)) throw new ProtocolValidationError('restore request ID conflicts with existing request')
      return
    }
    this.requests.set(key, { request: copyRequest(input), offers: new Map() })
  }

  async pullRequests(identityId: IdentityId, peerDeviceId: DeviceId, now = new Date()): Promise<RestoreRequestV1[]> {
    await this.expire(now)
    if (!(await this.authorizer.isTrustedDevice(identityId, peerDeviceId))) {
      throw new ProtocolValidationError('restore peer is not trusted')
    }
    const visible: RestoreRequestV1[] = []
    for (const { request } of this.requests.values()) {
      if (request.identityId !== identityId || request.requesterDeviceId === peerDeviceId) continue
      if (await this.authorizer.isTrustedDevice(identityId, request.requesterDeviceId)) visible.push(copyRequest(request))
    }
    return visible
  }

  async offer(input: RestoreOfferV1, now = new Date()): Promise<void> {
    assertRestoreOffer(input)
    await this.expire(now)
    if (Date.parse(input.expiresAt) <= now.getTime()) throw new ProtocolValidationError('restore offer is already expired')
    const entry = this.requests.get(requestKey(input.identityId, input.requestId))
    if (!entry || entry.request.requesterDeviceId !== input.requesterDeviceId) {
      throw new ProtocolValidationError('restore request is absent or no longer active')
    }
    if (!(await this.authorizer.isTrustedDevice(input.identityId, input.responderDeviceId))) {
      throw new ProtocolValidationError('restore responder is not trusted')
    }
    if (!(await this.authorizer.isTrustedDevice(input.identityId, input.requesterDeviceId))) {
      throw new ProtocolValidationError('restore requester is no longer trusted')
    }
    if (!(await this.authorizer.verifyOffer(input))) throw new ProtocolValidationError('restore offer signature is invalid')
    entry.offers.set(input.responderDeviceId, copyOffer(input))
  }

  async pullOffers(identityId: IdentityId, requesterDeviceId: DeviceId, now = new Date()): Promise<RestoreOfferV1[]> {
    await this.expire(now)
    if (!(await this.authorizer.isTrustedDevice(identityId, requesterDeviceId))) {
      throw new ProtocolValidationError('restore requester is not trusted')
    }
    return [...this.requests.values()]
      .filter(entry => entry.request.identityId === identityId && entry.request.requesterDeviceId === requesterDeviceId)
      .flatMap(entry => [...entry.offers.values()])
      .map(copyOffer)
  }

  async cancel(input: RestoreCancelV1, now = new Date()): Promise<void> {
    assertRestoreCancel(input)
    await this.expire(now)
    const key = requestKey(input.identityId, input.requestId)
    const entry = this.requests.get(key)
    if (!entry) return
    if (entry.request.requesterDeviceId !== input.requesterDeviceId) {
      throw new ProtocolValidationError('restore cancel requester does not match request')
    }
    if (!(await this.authorizer.verifyCancel(input, entry.request))) {
      throw new ProtocolValidationError('restore cancel signature is invalid')
    }
    this.requests.delete(key)
  }

  async expire(now = new Date()): Promise<void> {
    for (const [key, entry] of this.requests) {
      if (Date.parse(entry.request.expiresAt) <= now.getTime()) {
        this.requests.delete(key)
        continue
      }
      for (const [deviceId, offer] of entry.offers) {
        if (Date.parse(offer.expiresAt) <= now.getTime()) entry.offers.delete(deviceId)
      }
    }
  }
}

function requestKey(identityId: IdentityId, requestId: string): string {
  return `${identityId}\u0000${requestId}`
}

function sameRequest(left: RestoreRequestV1, right: RestoreRequestV1): boolean {
  return left.requestId === right.requestId
    && left.identityId === right.identityId
    && left.requesterDeviceId === right.requesterDeviceId
    && left.reason === right.reason
    && left.knownManifestRoot === right.knownManifestRoot
    && left.requestedAt === right.requestedAt
    && left.expiresAt === right.expiresAt
    && equalBytes(left.signature, right.signature)
}

function copyRequest(value: RestoreRequestV1): RestoreRequestV1 {
  return { ...value, signature: value.signature.slice() }
}

function copyOffer(value: RestoreOfferV1): RestoreOfferV1 {
  return { ...value, signature: value.signature.slice() }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  let different = 0
  for (let index = 0; index < left.length; index += 1) different |= left[index] ^ right[index]
  return different === 0
}
