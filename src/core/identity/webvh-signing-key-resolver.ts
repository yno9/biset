import { decodeMultikey } from '../../identity/webvh/multikey.ts'
import { fetchCurrentLog } from '../../identity/webvh/log-io.ts'
import { resolveEntries } from '../../identity/webvh/resolver.ts'
import { sameIdentity } from '../../identity/idkey.ts'
import { decodeMlsDeviceCredential, verifyMlsDeviceCredential } from '../../mls/device-credential.ts'
import type { DeviceSigningPublicKeyResolver } from './ed25519-device-control-verifier.ts'

/** Verifies the Client credential against the validated log's current Sign
 * key and generation. Ordinary device controls use the leaf key projected
 * into the MLS roster. */
export class WebvhSigningKeyResolver implements DeviceSigningPublicKeyResolver {
  async resolveEd25519PublicKey(signingKeyId: string, identityId: string, encoded: Uint8Array): Promise<Uint8Array | undefined> {
    let credential
    try { credential = decodeMlsDeviceCredential(encoded) } catch { return undefined }
    if (credential.deviceKid !== signingKeyId || !sameIdentity(credential.identityId, identityId)) return undefined
    try {
      const { entries, last } = await fetchCurrentLog(credential.identityId)
      if (!resolveEntries(credential.identityId, entries)) return undefined
      const keys = last.parameters.updateKeys ?? []
      return keys.length === 1 && credential.generation === last.versionId && verifyMlsDeviceCredential(credential, decodeMultikey(keys[0]!)) ? credential.signaturePublicKey : undefined
    } catch { return undefined }
  }
}
