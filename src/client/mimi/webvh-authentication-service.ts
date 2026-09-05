// MLS Authentication Service: a leaf is admitted only by the current WebVH
// Sign key and exact log generation, without publishing the leaf key itself.
import { decodeMultikey } from '../identity/webvh/multikey.ts'
import { fetchCurrentLog } from '../identity/webvh/log-io.ts'
import { resolveEntries } from '../identity/webvh/resolver.ts'
import { mlsDeviceCredentialOf, verifyMlsDeviceCredential } from './device-credential.ts'
import type { AuthenticationService, Credential } from '../../vendor/mls/index.ts'

export const webvhAuthenticationService: AuthenticationService = {
  async validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<boolean> {
    let value
    try { value = mlsDeviceCredentialOf(credential) } catch { return false }
    try {
      const { entries, last } = await fetchCurrentLog(value.identityId)
      if (!resolveEntries(value.identityId, entries)) return false
      const keys = last.parameters.updateKeys ?? []
      return keys.length === 1 && value.generation === last.versionId && verifyMlsDeviceCredential(value, decodeMultikey(keys[0]!), signaturePublicKey)
    } catch {
      return false
    }
  },
}
