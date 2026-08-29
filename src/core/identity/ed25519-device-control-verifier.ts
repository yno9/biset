import { ed25519 } from '@noble/curves/ed25519.js'
import {
  ingressAckSigningBytes,
  ingressPullSigningBytes,
  mailSubmissionSigningBytes,
  restoreCancelSigningBytes,
  restoreControlPullSigningBytes,
  restoreOfferSigningBytes,
  restoreRequestSigningBytes,
  vaultDeliveryAckSigningBytes,
  vaultDeliveryAppendSigningBytes,
  vaultDeliveryPullSigningBytes,
} from '../../protocol/signing.ts'
import type { IngressAckV1, IngressEnvelopeV1, IngressPullV1 } from '../../protocol/ingress.ts'
import type { MailSubmissionRequestV1 } from '../../protocol/mail-submission.ts'
import type { RestoreCancelV1, RestoreControlPullV1, RestoreOfferV1, RestoreRequestV1, VaultDeliveryAckV1, VaultDeliveryAppendV1, VaultDeliveryItemV1, VaultDeliveryPullV1 } from '../../protocol/vault.ts'
import type { TrustedDeviceV1 } from './device-roster.ts'
import type { DeviceControlSignatureVerifier } from './authorizers.ts'
import { rosterInstallSigningBytes, type RosterInstallV1 } from './roster-install.ts'
import { equalBytes } from '../../protocol/canonical.ts'

/** DID/webvh adapter boundary. It returns public Ed25519 keys only. */
export interface DeviceSigningPublicKeyResolver {
  resolveEd25519PublicKey(signingKeyId: string, identityId: string, deviceCredential: Uint8Array): Promise<Uint8Array | undefined>
}

/**
 * Concrete verifier for all signed mediation controls. The core receives only
 * the roster's public key ID and a resolver; it never receives a device
 * private key or MLS group state.
 */
export class Ed25519DeviceControlSignatureVerifier implements DeviceControlSignatureVerifier {
  constructor(private readonly keys: DeviceSigningPublicKeyResolver) {}

  verifyIngressAck(ack: IngressAckV1, _envelope: IngressEnvelopeV1, device: TrustedDeviceV1): Promise<boolean> {
    return this.verify(device, ingressAckSigningBytes(ack), ack.signature)
  }

  verifyIngressPull(pull: IngressPullV1, device: TrustedDeviceV1): Promise<boolean> {
    return this.verify(device, ingressPullSigningBytes(pull), pull.signature)
  }

  verifyVaultDeliveryAppend(append: VaultDeliveryAppendV1, device: TrustedDeviceV1): Promise<boolean> {
    return this.verify(device, vaultDeliveryAppendSigningBytes(append), append.signature)
  }

  verifyVaultDeliveryPull(pull: VaultDeliveryPullV1, device: TrustedDeviceV1): Promise<boolean> {
    return this.verify(device, vaultDeliveryPullSigningBytes(pull), pull.signature)
  }

  verifyVaultDeliveryAck(ack: VaultDeliveryAckV1, _item: VaultDeliveryItemV1, device: TrustedDeviceV1): Promise<boolean> {
    return this.verify(device, vaultDeliveryAckSigningBytes(ack), ack.signature)
  }

  verifyRestoreRequest(request: RestoreRequestV1, device: TrustedDeviceV1): Promise<boolean> {
    return this.verify(device, restoreRequestSigningBytes(request), request.signature)
  }

  verifyRestoreOffer(offer: RestoreOfferV1, device: TrustedDeviceV1): Promise<boolean> {
    return this.verify(device, restoreOfferSigningBytes(offer), offer.signature)
  }

  verifyRestoreCancel(cancel: RestoreCancelV1, _request: RestoreRequestV1, device: TrustedDeviceV1): Promise<boolean> {
    return this.verify(device, restoreCancelSigningBytes(cancel), cancel.signature)
  }

  verifyRestoreControlPull(pull: RestoreControlPullV1, device: TrustedDeviceV1): Promise<boolean> {
    return this.verify(device, restoreControlPullSigningBytes(pull), pull.signature)
  }

  verifyRosterInstall(install: RosterInstallV1, device: TrustedDeviceV1): Promise<boolean> {
    return this.verifyRosterCredential(install, device)
  }

  verifyMailSubmission(request: MailSubmissionRequestV1, device: TrustedDeviceV1): Promise<boolean> {
    return this.verify(device, mailSubmissionSigningBytes(request), request.signature)
  }

  private async verify(device: TrustedDeviceV1, bytes: Uint8Array, signature: Uint8Array): Promise<boolean> {
    if (signature.length !== 64) return false
    return device.signingPublicKey.length === 32 && ed25519.verify(signature, bytes, device.signingPublicKey)
  }

  private async verifyRosterCredential(install: RosterInstallV1, device: TrustedDeviceV1): Promise<boolean> {
    if (install.signature.length !== 64) return false
    const credentialKey = await this.keys.resolveEd25519PublicKey(device.deviceId, install.projection.identityId, device.deviceCredential)
    return credentialKey !== undefined
      && equalBytes(credentialKey, device.signingPublicKey)
      && ed25519.verify(install.signature, rosterInstallSigningBytes(install), device.signingPublicKey)
  }
}
