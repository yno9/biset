import { decodeMultikey } from '../identity/webvh/multikey.ts'
import { resolve } from '../identity/webvh/resolver.ts'
import { sameIdentity } from '../identity/idkey.ts'
import type { DeviceSigningPublicKeyResolver } from './mls-delivery-authorizer.ts'

/** Resolves a signed MLS DS control kid against the current did:webvh log. */
export class CoordinatorWebvhSigningKeyResolver implements DeviceSigningPublicKeyResolver {
  private readonly cache = new Map<string, Uint8Array>()

  async resolveEd25519PublicKey(signingKeyId: string): Promise<Uint8Array | undefined> {
    const cached = this.cache.get(signingKeyId)
    if (cached) return cached
    const hash = signingKeyId.indexOf('#')
    if (hash < 0) return undefined
    const did = signingKeyId.slice(0, hash)
    const fragment = signingKeyId.slice(hash)
    let document
    try { document = await resolve(did) } catch { return undefined }
    const method = document?.verificationMethod.find(entry => entry.id === `${document.id}${fragment}`)
    if (!method) return undefined
    try {
      const publicKey = decodeMultikey(method.publicKeyMultibase)
      this.cache.set(signingKeyId, publicKey)
      return publicKey
    } catch { return undefined }
  }
}

/** Liveness deliberately bypasses caches: a revoked DID method must stop
 * receiving freshly consumed KeyPackages immediately. */
export async function isCurrentWebvhDevice(identityId: string, kid: string): Promise<boolean> {
  const hash = kid.indexOf('#')
  if (hash < 0 || !sameIdentity(kid.slice(0, hash), identityId)) return false
  let document
  try { document = await resolve(identityId) } catch { return false }
  const fragment = kid.slice(hash)
  return document?.verificationMethod.some(entry => entry.id === `${document.id}${fragment}`) ?? false
}
