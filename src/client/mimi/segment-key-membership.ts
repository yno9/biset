// Adapts MLS device keys to the two different Vault verification questions:
// a SegmentKeyWrap grant is checked against CURRENT Self Group membership,
// while an immutable historical Vault event may carry its Root-authorized
// actor credential and remains verifiable after that actor is removed. A
// revoke must prevent future grants, not corrupt already-valid history.
import { ed25519 } from '@noble/curves/ed25519.js'
import { memberSignaturePublicKey, ownMlsDeviceCredential, ownSignaturePrivateKey } from './group.ts'
import { decodeMlsDeviceCredential, encodeMlsDeviceCredential, verifyMlsDeviceCredentialRoot } from './device-credential.ts'
import type { ClientState } from '../../vendor/mls/index.ts'
import type { SegmentKeyWrapSigner, SegmentKeyWrapVerifier } from '../store/vault/crypto.ts'
import type { DeviceId } from '../../shared/protocol/ids.ts'

/** `state` is a thunk rather than a fixed value so a long-lived resolver
 * always checks against whatever this identity's self-group state most
 * recently was — MLS state is immutable and replaced wholesale on every
 * commit (group.ts's own note), so a resolver built once at boot must not
 * pin itself to that boot's snapshot. Async because the ordinary source is
 * `MlsSelfGroupStateStore.load` (an IndexedDB read), not memory. */
export class MlsMembershipSegmentKeyWrapVerifier implements SegmentKeyWrapVerifier {
  constructor(
    private readonly state: () => Promise<ClientState>,
    private readonly rootPublicKey?: Uint8Array,
  ) {}

  async verify(deviceId: DeviceId, bytes: Uint8Array, signature: Uint8Array, deviceCredential?: Uint8Array): Promise<boolean> {
    if (deviceCredential && this.rootPublicKey) {
      try {
        const credential = decodeMlsDeviceCredential(deviceCredential)
        return credential.deviceKid === deviceId
          && verifyMlsDeviceCredentialRoot(credential, this.rootPublicKey)
          && signature.length === 64
          && ed25519.verify(signature, bytes, credential.signaturePublicKey)
      } catch { return false }
    }
    const publicKey = memberSignaturePublicKey(await this.state(), deviceId)
    if (!publicKey) return false
    if (signature.length !== 64 || publicKey.length !== 32) return false
    return ed25519.verify(signature, bytes, publicKey)
  }
}

/** This device's own grantor identity: signs with its MLS leaf signature
 * private key, read fresh off `state()` on every call rather than pinned at
 * construction — the same key `webvh-authentication-service.ts`'s AS checks
 * against a resolved DID document, and `MlsMembershipSegmentKeyWrapVerifier`
 * checks against current self-group membership (one key, two checks,
 * PLANMLSDIDCRED.md §2.3's "no new key type" stance). */
export class MlsMembershipSegmentKeyWrapSigner implements SegmentKeyWrapSigner {
  private readonly verifier: MlsMembershipSegmentKeyWrapVerifier

  constructor(
    readonly deviceId: DeviceId,
    private readonly state: () => Promise<ClientState>,
  ) {
    this.verifier = new MlsMembershipSegmentKeyWrapVerifier(state)
  }

  async sign(bytes: Uint8Array): Promise<Uint8Array> {
    return ed25519.sign(bytes, ownSignaturePrivateKey(await this.state()))
  }

  async deviceCredential(): Promise<Uint8Array> {
    return encodeMlsDeviceCredential(ownMlsDeviceCredential(await this.state()))
  }

  verify(deviceId: DeviceId, bytes: Uint8Array, signature: Uint8Array, deviceCredential?: Uint8Array): Promise<boolean> {
    return this.verifier.verify(deviceId, bytes, signature, deviceCredential)
  }
}
