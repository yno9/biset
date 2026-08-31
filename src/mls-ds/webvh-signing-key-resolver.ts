// Mirrors coordinator/webvh-signing-key-resolver.ts's CoordinatorWebvhSigningKeyResolver
// with the identityId cross-check removed (PLAN_biset-mls-ds.md §7 -- there
// is no owner identity a Conversation Group control message's sender needs
// to belong to; `credential.deviceKid === signingKeyId` alone identifies
// whose credential this is, and `credential.identityId` names which DID's
// log to verify it against).
import { decodeMultikey } from '../identity/webvh/multikey.ts'
import { fetchCurrentLog } from '../identity/webvh/log-io.ts'
import { resolveEntries } from '../identity/webvh/resolver.ts'
import { decodeMlsDeviceCredential, verifyMlsDeviceCredential } from '../mls/device-credential.ts'
import type { ConversationDeviceSigningPublicKeyResolver } from './authorizer.ts'

/** Verifies a current-generation Sign-authorized device credential directly
 * against the validated did:webvh log -- same MLS BasicCredential shape
 * Self Group control messages sign with, per-device MLS keys never entering
 * the DID document either way. */
export class ConversationWebvhSigningKeyResolver implements ConversationDeviceSigningPublicKeyResolver {
  async resolveEd25519PublicKey(signingKeyId: string, encoded: Uint8Array | undefined): Promise<Uint8Array | undefined> {
    if (!encoded) return undefined
    let credential
    try { credential = decodeMlsDeviceCredential(encoded) } catch { return undefined }
    if (credential.deviceKid !== signingKeyId) return undefined
    try {
      const { entries, last } = await fetchCurrentLog(credential.identityId)
      if (!resolveEntries(credential.identityId, entries)) return undefined
      const keys = last.parameters.updateKeys ?? []
      if (keys.length !== 1 || credential.generation !== last.versionId || !verifyMlsDeviceCredential(credential, decodeMultikey(keys[0]!))) return undefined
      return credential.signaturePublicKey
    } catch { return undefined }
  }
}
