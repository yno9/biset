import { decodeMultikey } from '../../identity/webvh/multikey.ts'
import { resolve } from '../../identity/webvh/resolver.ts'
import type { DeviceSigningPublicKeyResolver } from './ed25519-device-control-verifier.ts'

/**
 * The Authentication Service role (RFC 9750 §4, `PLANMLSARCH.md` §3): resolves
 * a device's signing key id (`did:webvh:...#fragment`) to its current Ed25519
 * public key by fetching and verifying the DID's did:webvh log. Unlike MLS
 * credential validation elsewhere in the codebase, this resolver is
 * fail-closed — a DID that cannot be resolved, or a fragment absent from its
 * verificationMethod, yields `undefined`, and the caller's signature check
 * then fails. This resolver backs device-control signature verification
 * (roster ACK/pull/append/restore control), where accepting an unverifiable
 * key would defeat the check it is used for.
 *
 * No key-rotation cache: every call re-fetches the log. `PLAN.md` §2.2 tracks
 * adding one.
 */
export class WebvhSigningKeyResolver implements DeviceSigningPublicKeyResolver {
  async resolveEd25519PublicKey(signingKeyId: string): Promise<Uint8Array | undefined> {
    const hash = signingKeyId.indexOf('#')
    if (hash < 0) return undefined
    const did = signingKeyId.slice(0, hash)
    let doc
    try {
      doc = await resolve(did)
    } catch {
      return undefined
    }
    if (!doc) return undefined
    const vm = doc.verificationMethod.find(entry => entry.id === signingKeyId)
    if (!vm) return undefined
    try {
      return decodeMultikey(vm.publicKeyMultibase)
    } catch {
      return undefined
    }
  }
}
