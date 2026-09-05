import { bytesToBase64url, canonicalBytes } from './canonical.ts'
import type { IngressAckV1, IngressPullV1 } from './ingress.ts'
import type { MailSubmissionRequestV1 } from './mail-submission.ts'
import type { VaultDeliveryAckV1, VaultDeliveryAppendV1, VaultDeliveryPullV1 } from './vault.ts'

/**
 * Canonical bytes for device-control signatures. These functions omit only
 * `signature`; every routing, identity, expiry, and payload-binding field is
 * authenticated. They are shared by client signing and core verification.
 */
export function ingressAckSigningBytes(ack: Omit<IngressAckV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/ingress-ack/v1',
    version: ack.version,
    ingressId: ack.ingressId,
    protectedPayloadHash: bytesToBase64url(ack.protectedPayloadHash),
    recipientDeviceId: ack.recipientDeviceId,
    vaultEventId: ack.vaultEventId,
    checkpointId: ack.checkpointId,
    ackedAt: ack.ackedAt,
  })
}

export function ingressPullSigningBytes(pull: Omit<IngressPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/ingress-pull/v1',
    version: pull.version,
    identityId: pull.identityId,
    recipientDeviceId: pull.recipientDeviceId,
    requestedAt: pull.requestedAt,
  })
}

export function vaultDeliveryAckSigningBytes(ack: Omit<VaultDeliveryAckV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/vault-delivery-ack/v1',
    version: ack.version,
    identityId: ack.identityId,
    seq: ack.seq,
    payloadHash: bytesToBase64url(ack.payloadHash),
    recipientDeviceId: ack.recipientDeviceId,
    checkpointId: ack.checkpointId,
    ackedAt: ack.ackedAt,
  })
}

export function vaultDeliveryAppendSigningBytes(append: Omit<VaultDeliveryAppendV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/vault-delivery-append/v1',
    version: append.version,
    identityId: append.identityId,
    appendId: append.appendId,
    payloadHash: bytesToBase64url(append.payloadHash),
    senderDeviceId: append.senderDeviceId,
    sentAt: append.sentAt,
  })
}

export function vaultDeliveryPullSigningBytes(pull: Omit<VaultDeliveryPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/vault-delivery-pull/v1',
    version: pull.version,
    identityId: pull.identityId,
    recipientDeviceId: pull.recipientDeviceId,
    after: pull.after,
    requestedAt: pull.requestedAt,
  })
}

export function mailSubmissionSigningBytes(request: Omit<MailSubmissionRequestV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mail-submission/v1',
    version: request.version,
    identityId: request.identityId,
    deviceId: request.deviceId,
    mailFrom: request.mailFrom,
    rcptTo: request.rcptTo,
    rawRfc5322: bytesToBase64url(request.rawRfc5322),
    submittedAt: request.submittedAt,
  })
}
