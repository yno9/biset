import { decodeMultikey } from '../identity/webvh/multikey.ts'
import { resolve } from '../identity/webvh/resolver.ts'
import { sameIdentity } from '../identity/idkey.ts'
import { decodeMlsDeviceCredential, verifyMlsDeviceCredential } from '../mls/device-credential.ts'
import type { DeviceSigningPublicKeyResolver } from './mls-delivery-authorizer.ts'

/** Verifies a Root-signed device credential while resolving only the stable
 * identity Root Key from did:webvh. Per-device MLS keys never enter the DID
 * document or this resolver's cache. */
export class CoordinatorWebvhSigningKeyResolver implements DeviceSigningPublicKeyResolver {
  private readonly rootCache = new Map<string, Uint8Array>()

  async resolveEd25519PublicKey(signingKeyId: string, identityId: string, encoded: Uint8Array | undefined): Promise<Uint8Array | undefined> {
    if (!encoded) return undefined
    let credential
    try { credential = decodeMlsDeviceCredential(encoded) } catch { return undefined }
    if (credential.deviceKid !== signingKeyId || !sameIdentity(credential.identityId, identityId)) return undefined
    const rootPublicKey = await this.rootPublicKey(credential.identityId)
    if (!rootPublicKey || !verifyMlsDeviceCredential(credential, rootPublicKey)) return undefined
    return credential.signaturePublicKey
  }

  private async rootPublicKey(identityId: string): Promise<Uint8Array | undefined> {
    const cached = this.rootCache.get(identityId)
    if (cached) return cached
    let document
    try { document = await resolve(identityId) } catch { return undefined }
    const method = document?.verificationMethod.find(entry => entry.id === `${document.id}#key-1`)
    if (!method) return undefined
    try {
      const publicKey = decodeMultikey(method.publicKeyMultibase)
      this.rootCache.set(identityId, publicKey)
      return publicKey
    } catch { return undefined }
  }
}
