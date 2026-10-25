// MLS Authentication Service: a leaf is admitted by the Sign key that was active
// at the credential's recorded generation, plus the stable Root key. Later DID service
// edits must not invalidate an unchanged MLS leaf.
import { decodeMultikey } from '../../protocol/vh/multikey.ts'
import { fetchCurrentLog } from '../identity/log-io.ts'
import { updateKeysAtVersion } from '../../protocol/vh/log.ts'
import { mlsDeviceCredentialOf, verifyMlsDeviceCredential, verifyMlsDeviceCredentialRoot } from './device-credential.ts'
import type { AuthenticationService, Credential } from '../../protocol/mls/index.ts'

export const didAuthenticationService: AuthenticationService = {
  async validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<boolean> {
    let value
    try { value = mlsDeviceCredentialOf(credential) } catch { return false }
    try {
      const { entries, last } = await fetchCurrentLog(value.identityId)
      // fetchCurrentLog verified the whole log; the document is the latest entry's state.
      const document = last.state as { id: string; authentication: string[]; verificationMethod: Array<{ id: string; publicKeyMultibase: string }> }
      if (document.id !== value.identityId) return false
      const signKeys = updateKeysAtVersion(entries, value.generation)
      if (!signKeys) return false
      const rootMethod = document.verificationMethod.find(method => document.authentication.includes(method.id))
      if (signKeys.length !== 1 || !rootMethod) return false
      if (value.version === 3 && Date.parse(value.expiresAt!) <= Date.now()) return false
      return verifyMlsDeviceCredential(value, decodeMultikey(signKeys[0]!), signaturePublicKey)
        && verifyMlsDeviceCredentialRoot(value, decodeMultikey(rootMethod.publicKeyMultibase), signaturePublicKey)
    } catch {
      return false
    }
  },
}
