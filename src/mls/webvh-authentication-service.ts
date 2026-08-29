// MLS Authentication Service: a leaf is authorized by the identity Root Key
// carried in the DID document, not by publishing the leaf key itself there.
// The leaf's BasicCredential contains a canonical Root-signed device binding;
// this service resolves only the stable `#key-1` trust anchor and verifies the
// binding against the leaf signature key MLS handed us.
import { decodeMultikey } from '../identity/webvh/multikey.ts'
import { resolve } from '../identity/webvh/resolver.ts'
import { mlsDeviceCredentialOf, verifyMlsDeviceCredential } from './device-credential.ts'
import type { AuthenticationService, Credential } from './vendor/index.ts'

export const webvhAuthenticationService: AuthenticationService = {
  async validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<boolean> {
    let value
    try { value = mlsDeviceCredentialOf(credential) } catch { return false }
    let doc
    try { doc = await resolve(value.identityId) } catch { return false }
    if (!doc) return false
    const root = doc.verificationMethod.find(entry => entry.id === `${doc.id}#key-1`)
    if (!root) return false
    try {
      return verifyMlsDeviceCredential(value, decodeMultikey(root.publicKeyMultibase), signaturePublicKey)
    } catch {
      return false
    }
  },
}
