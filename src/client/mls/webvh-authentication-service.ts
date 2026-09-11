// MLS Authentication Service: a leaf is admitted by the WebVH Sign key that
// was active at the credential's recorded generation, plus the stable Root
// key. Later DID service edits must not invalidate an unchanged MLS leaf.
import { decodeMultikey } from '../../protocol/webvh/multikey.ts'
import { fetchCurrentLog } from '../identity/webvh/log-io.ts'
import { resolveEntries } from '../../protocol/webvh/resolver.ts'
import { resolveParameters, type LogParameters } from '../../protocol/webvh/log.ts'
import { mlsDeviceCredentialOf, verifyMlsDeviceCredential, verifyMlsDeviceCredentialRoot } from './device-credential.ts'
import type { AuthenticationService, Credential } from '../../protocol/mls/index.ts'

export const webvhAuthenticationService: AuthenticationService = {
  async validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<boolean> {
    let value
    try { value = mlsDeviceCredentialOf(credential) } catch { return false }
    try {
      const { entries } = await fetchCurrentLog(value.identityId)
      const document = resolveEntries(value.identityId, entries)
      if (!document) return false
      let generationParameters: LogParameters = {}
      let foundGeneration = false
      for (const entry of entries) {
        generationParameters = resolveParameters(generationParameters, entry.parameters)
        if (entry.versionId === value.generation) { foundGeneration = true; break }
      }
      if (!foundGeneration) return false
      const signKeys = generationParameters.updateKeys ?? []
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
