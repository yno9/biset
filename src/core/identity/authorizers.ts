import type { RestoreControlAuthorizer } from '../mediation/restore-control-store.ts'
import type { IngressAckAuthorizer } from '../mediation/ingress-store.ts'
import type { VaultDeliveryAuthorizer } from '../mediation/vault-delivery-store.ts'
import type { IngressAckV1, IngressEnvelopeV1 } from '../../protocol/ingress.ts'
import type { RestoreCancelV1, RestoreOfferV1, RestoreRequestV1, VaultDeliveryAckV1, VaultDeliveryItemV1 } from '../../protocol/vault.ts'
import type { DeviceId, IdentityId } from '../../protocol/ids.ts'
import type { TrustedDeviceRoster, TrustedDeviceV1 } from './device-roster.ts'

/** Signature verification stays with the identity/MLS adapter, never with mediation. */
export interface DeviceControlSignatureVerifier {
  verifyIngressAck(ack: IngressAckV1, envelope: IngressEnvelopeV1, device: TrustedDeviceV1): Promise<boolean>
  verifyVaultDeliveryAck(ack: VaultDeliveryAckV1, item: VaultDeliveryItemV1, device: TrustedDeviceV1): Promise<boolean>
  verifyRestoreRequest(request: RestoreRequestV1, device: TrustedDeviceV1): Promise<boolean>
  verifyRestoreOffer(offer: RestoreOfferV1, device: TrustedDeviceV1): Promise<boolean>
  verifyRestoreCancel(cancel: RestoreCancelV1, request: RestoreRequestV1, device: TrustedDeviceV1): Promise<boolean>
}

export function rosterBackedIngressAckAuthorizer(
  roster: TrustedDeviceRoster,
  verifier: Pick<DeviceControlSignatureVerifier, 'verifyIngressAck'>,
): IngressAckAuthorizer {
  return {
    isTrustedDevice: (identityId, deviceId) => roster.isTrustedDevice(identityId, deviceId),
    async verify(ack, envelope) {
      const device = await currentDevice(roster, envelope.recipientIdentityId, ack.recipientDeviceId)
      return device !== undefined && verifier.verifyIngressAck(ack, envelope, device)
    },
  }
}

export function rosterBackedVaultDeliveryAuthorizer(
  roster: TrustedDeviceRoster,
  verifier: Pick<DeviceControlSignatureVerifier, 'verifyVaultDeliveryAck'>,
): VaultDeliveryAuthorizer {
  return {
    deliveryFloor: (identityId, deviceId) => roster.deliveryFloor(identityId, deviceId),
    async verifyRecipients(identityId, deviceIds) {
      if (new Set(deviceIds).size !== deviceIds.length) return false
      return (await Promise.all(deviceIds.map(deviceId => roster.isTrustedDevice(identityId, deviceId)))).every(Boolean)
    },
    async verifyAck(ack, item) {
      const device = await currentDevice(roster, ack.identityId, ack.recipientDeviceId)
      return device !== undefined && verifier.verifyVaultDeliveryAck(ack, item, device)
    },
  }
}

export function rosterBackedRestoreControlAuthorizer(
  roster: TrustedDeviceRoster,
  verifier: Omit<DeviceControlSignatureVerifier, 'verifyVaultDeliveryAck'>,
): RestoreControlAuthorizer {
  return {
    isTrustedDevice: (identityId, deviceId) => roster.isTrustedDevice(identityId, deviceId),
    async verifyRequest(request) {
      const device = await currentDevice(roster, request.identityId, request.requesterDeviceId)
      return device !== undefined && verifier.verifyRestoreRequest(request, device)
    },
    async verifyOffer(offer) {
      const device = await currentDevice(roster, offer.identityId, offer.responderDeviceId)
      return device !== undefined && verifier.verifyRestoreOffer(offer, device)
    },
    async verifyCancel(cancel, request) {
      const device = await currentDevice(roster, cancel.identityId, cancel.requesterDeviceId)
      return device !== undefined && verifier.verifyRestoreCancel(cancel, request, device)
    },
  }
}

async function currentDevice(
  roster: TrustedDeviceRoster,
  identityId: IdentityId,
  deviceId: DeviceId,
): Promise<TrustedDeviceV1 | undefined> {
  return (await roster.trustedDevices(identityId)).find(device => device.deviceId === deviceId)
}
