import { decodeMultikey } from '../../identity/webvh/multikey.ts'
import { resolve } from '../../identity/webvh/resolver.ts'
import { sameIdentity } from '../../identity/idkey.ts'
import { decodeMlsDeviceCredential, verifyMlsDeviceCredential } from '../../mls/device-credential.ts'
import type { DeviceSigningPublicKeyResolver } from './ed25519-device-control-verifier.ts'

/** Resolves only the stable identity Root Key and verifies the Root-signed
 * MLS device credential projected by the Client. Ordinary device controls
 * are verified directly with the public key persisted in the MLS roster. */
export class WebvhSigningKeyResolver implements DeviceSigningPublicKeyResolver {
  private readonly roots = new Map<string, Uint8Array>()

  async resolveEd25519PublicKey(signingKeyId: string, identityId: string, encoded: Uint8Array): Promise<Uint8Array | undefined> {
    let credential
    try { credential = decodeMlsDeviceCredential(encoded) } catch { return undefined }
    if (credential.deviceKid !== signingKeyId || !sameIdentity(credential.identityId, identityId)) return undefined
    let root = this.roots.get(credential.identityId)
    if (!root) {
      let doc
      try { doc = await resolve(credential.identityId) } catch { return undefined }
      const method = doc?.verificationMethod.find(entry => entry.id === `${doc.id}#key-1`)
      if (!method) return undefined
      try { root = decodeMultikey(method.publicKeyMultibase) } catch { return undefined }
      this.roots.set(credential.identityId, root)
    }
    return verifyMlsDeviceCredential(credential, root) ? credential.signaturePublicKey : undefined
  }
}
