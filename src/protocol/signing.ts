import { bytesToBase64url, canonicalBytes } from './canonical.ts'
import type { IngressAckV1 } from './ingress.ts'
import type { MailSubmissionRequestV1 } from './mail-submission.ts'

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
