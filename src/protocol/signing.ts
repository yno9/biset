import { bytesToBase64url, canonicalBytes } from './canonical.ts'
import type { IngressAckV1 } from './ingress.ts'

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
