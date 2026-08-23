// Adapts MLS self-group membership to vault/crypto.ts's SegmentKeyWrap
// grantor signer/verifier boundary. A SegmentKeyWrap's grantor is checked
// against the CURRENT self-group member list, not a resolved DID document:
// the self group (not the DID) is the authority on who may grant a
// SegmentKey right now (PLAN.md §4.2) — a device the self group has
// removed must not still be able to verify (or, worse, forge) a grant just
// because its DID document has not caught up yet.
import { ed25519 } from '@noble/curves/ed25519.js'
import { memberSignaturePublicKey, ownSignaturePrivateKey } from './group.ts'
import type { ClientState } from './vendor/index.ts'
import type { SegmentKeyWrapSigner, SegmentKeyWrapVerifier } from '../vault/crypto.ts'
import type { DeviceId } from '../protocol/ids.ts'

/** `state` is a thunk rather than a fixed value so a long-lived resolver
 * always checks against whatever this identity's self-group state most
 * recently was — MLS state is immutable and replaced wholesale on every
 * commit (group.ts's own note), so a resolver built once at boot must not
 * pin itself to that boot's snapshot. Async because the ordinary source is
 * `MlsSelfGroupStateStore.load` (an IndexedDB read), not memory. */
export class MlsMembershipSegmentKeyWrapVerifier implements SegmentKeyWrapVerifier {
  constructor(private readonly state: () => Promise<ClientState>) {}

  async verify(deviceId: DeviceId, bytes: Uint8Array, signature: Uint8Array): Promise<boolean> {
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

  verify(deviceId: DeviceId, bytes: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return this.verifier.verify(deviceId, bytes, signature)
  }
}
