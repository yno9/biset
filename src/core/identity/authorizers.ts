import type { RestoreControlAuthorizer } from '../mediation/restore-control-store.ts'
import type { IngressAuthorizer } from '../mediation/ingress-store.ts'
import type { VaultDeliveryAuthorizer } from '../mediation/vault-delivery-store.ts'
import type { IngressAckV1, IngressEnvelopeV1, IngressPullV1 } from '../../protocol/ingress.ts'
import type { MailSubmissionRequestV1 } from '../../protocol/mail-submission.ts'
import type { RestoreCancelV1, RestoreControlPullV1, RestoreOfferV1, RestoreRequestV1, VaultDeliveryAckV1, VaultDeliveryAppendV1, VaultDeliveryItemV1, VaultDeliveryPullV1 } from '../../protocol/vault.ts'
import type { DeviceId, IdentityId } from '../../protocol/ids.ts'
import { assertAcceptedSelfGroupProjection, type TrustedDeviceRoster, type TrustedDeviceV1 } from './device-roster.ts'
import type { RosterInstallOutcome, RosterInstallV1 } from './roster-install.ts'

/** Signature verification stays with the identity/MLS adapter, never with mediation. */
export interface DeviceControlSignatureVerifier {
  verifyIngressAck(ack: IngressAckV1, envelope: IngressEnvelopeV1, device: TrustedDeviceV1): Promise<boolean>
  verifyIngressPull(pull: IngressPullV1, device: TrustedDeviceV1): Promise<boolean>
  verifyVaultDeliveryAppend(append: VaultDeliveryAppendV1, device: TrustedDeviceV1): Promise<boolean>
  verifyVaultDeliveryPull(pull: VaultDeliveryPullV1, device: TrustedDeviceV1): Promise<boolean>
  verifyVaultDeliveryAck(ack: VaultDeliveryAckV1, item: VaultDeliveryItemV1, device: TrustedDeviceV1): Promise<boolean>
  verifyRestoreRequest(request: RestoreRequestV1, device: TrustedDeviceV1): Promise<boolean>
  verifyRestoreOffer(offer: RestoreOfferV1, device: TrustedDeviceV1): Promise<boolean>
  verifyRestoreCancel(cancel: RestoreCancelV1, request: RestoreRequestV1, device: TrustedDeviceV1): Promise<boolean>
  verifyRestoreControlPull(pull: RestoreControlPullV1, device: TrustedDeviceV1): Promise<boolean>
  verifyRosterInstall(install: RosterInstallV1, device: TrustedDeviceV1): Promise<boolean>
  verifyMailSubmission(request: MailSubmissionRequestV1, device: TrustedDeviceV1): Promise<boolean>
}

/** A device's mail submission is authorized only when it is a current
 * trusted member of the identity's self group -- same trust boundary as
 * every other device-control action, no separate allowlist. */
export interface MailSubmissionAuthorizer {
  verify(request: MailSubmissionRequestV1): Promise<boolean>
}

export function rosterBackedMailSubmissionAuthorizer(
  roster: TrustedDeviceRoster,
  verifier: Pick<DeviceControlSignatureVerifier, 'verifyMailSubmission'>,
): MailSubmissionAuthorizer {
  return {
    async verify(request) {
      const device = await currentDevice(roster, request.identityId, request.deviceId)
      return device !== undefined && verifier.verifyMailSubmission(request, device)
    },
  }
}

export function rosterBackedIngressAuthorizer(
  roster: TrustedDeviceRoster,
  verifier: Pick<DeviceControlSignatureVerifier, 'verifyIngressAck' | 'verifyIngressPull'>,
): IngressAuthorizer {
  return {
    async verifyPull(pull) {
      const device = await currentDevice(roster, pull.identityId, pull.recipientDeviceId)
      return device !== undefined && verifier.verifyIngressPull(pull, device)
    },
    async verify(ack, envelope) {
      const device = await currentDevice(roster, envelope.recipientIdentityId, ack.recipientDeviceId)
      return device !== undefined && verifier.verifyIngressAck(ack, envelope, device)
    },
  }
}

export function rosterBackedVaultDeliveryAuthorizer(
  roster: TrustedDeviceRoster,
  verifier: Pick<DeviceControlSignatureVerifier, 'verifyVaultDeliveryAppend' | 'verifyVaultDeliveryPull' | 'verifyVaultDeliveryAck'>,
): VaultDeliveryAuthorizer {
  return {
    deliveryFloor: (identityId, deviceId) => roster.deliveryFloor(identityId, deviceId),
    async recipientsAtAppend(identityId) {
      return (await roster.trustedDevices(identityId)).map(device => device.deviceId)
    },
    async verifyAppend(append) {
      const device = await currentDevice(roster, append.identityId, append.senderDeviceId)
      return device !== undefined && verifier.verifyVaultDeliveryAppend(append, device)
    },
    async verifyPull(pull) {
      const device = await currentDevice(roster, pull.identityId, pull.recipientDeviceId)
      return device !== undefined && verifier.verifyVaultDeliveryPull(pull, device)
    },
    async verifyAck(ack, item) {
      const device = await currentDevice(roster, ack.identityId, ack.recipientDeviceId)
      return device !== undefined && verifier.verifyVaultDeliveryAck(ack, item, device)
    },
  }
}

export function rosterBackedRestoreControlAuthorizer(
  roster: TrustedDeviceRoster,
  verifier: Pick<DeviceControlSignatureVerifier, 'verifyRestoreRequest' | 'verifyRestoreOffer' | 'verifyRestoreCancel' | 'verifyRestoreControlPull'>,
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
    async verifyPull(pull) {
      const device = await currentDevice(roster, pull.identityId, pull.deviceId)
      return device !== undefined && verifier.verifyRestoreControlPull(pull, device)
    },
  }
}

/**
 * Applies core's DS-only trust model (`PLANMLSARCH.md` §4.1-4.2) to a roster
 * install: core never inspects MLS Commit content, and only checks that the
 * installer is a device the roster already trusts. `roster.projection` (not
 * yet updated by this call) is what "the roster already trusts" means at
 * this point — a genuinely new identity has no such projection yet, and only
 * then may the installer attest to itself (the genesis exception: the new
 * projection's own device list vouches for the installer, since nothing else
 * can). Epoch monotonicity and same-epoch tie-break are enforced inside
 * `roster.installAcceptedProjection` itself.
 */
export async function installRosterProjection(
  roster: TrustedDeviceRoster,
  verifier: Pick<DeviceControlSignatureVerifier, 'verifyRosterInstall'>,
  install: RosterInstallV1,
): Promise<RosterInstallOutcome> {
  assertAcceptedSelfGroupProjection(install.projection)
  const existing = await roster.projection(install.projection.identityId)
  const authorizedDevices = existing ? existing.devices : install.projection.devices
  const installer = authorizedDevices.find(device => device.deviceId === install.installerDeviceId)
  if (!installer) return 'rejected'
  const verified = await verifier.verifyRosterInstall(install, installer)
  if (!verified) return 'rejected'
  return roster.installAcceptedProjection(install.projection)
}

async function currentDevice(
  roster: TrustedDeviceRoster,
  identityId: IdentityId,
  deviceId: DeviceId,
): Promise<TrustedDeviceV1 | undefined> {
  return (await roster.trustedDevices(identityId)).find(device => device.deviceId === deviceId)
}
