import { decodeMultikey } from '../identity/webvh/multikey.ts'
import { fetchCurrentLog } from '../identity/webvh/log-io.ts'
import { resolveEntries } from '../identity/webvh/resolver.ts'
import { sameIdentity } from '../identity/idkey.ts'
import { decodeMlsDeviceCredential, verifyMlsDeviceCredential } from '../mls/device-credential.ts'
import type { DeviceSigningPublicKeyResolver } from './mls-delivery-authorizer.ts'

/** Verifies a current-generation Sign-authorized device credential directly
 * against the validated did:webvh log. Per-device MLS keys never enter the
 * DID document. */
export class CoordinatorWebvhSigningKeyResolver implements DeviceSigningPublicKeyResolver {
  async resolveEd25519PublicKey(signingKeyId: string, identityId: string, encoded: Uint8Array | undefined): Promise<Uint8Array | undefined> {
    if (!encoded) return undefined
    let credential
    try { credential = decodeMlsDeviceCredential(encoded) } catch { return undefined }
    if (credential.deviceKid !== signingKeyId || !sameIdentity(credential.identityId, identityId)) return undefined
    try {
      const { entries, last } = await fetchCurrentLog(credential.identityId)
      if (!resolveEntries(credential.identityId, entries)) return undefined
      const keys = last.parameters.updateKeys ?? []
      if (keys.length !== 1 || credential.generation !== last.versionId || !verifyMlsDeviceCredential(credential, decodeMultikey(keys[0]!))) return undefined
      return credential.signaturePublicKey
    } catch { return undefined }
  }
}
