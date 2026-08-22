import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import { reduceLocalJmapProjection } from '../local-jmap/reducer.ts'
import type { IdentityId, MlsEpoch, SegmentId } from '../protocol/ids.ts'
import type { SegmentKeyWrapV1, VaultObjectV1 } from '../protocol/vault.ts'
import { decryptVaultObject, verifyVaultObjectIntegrity } from './objects.ts'
import { assertOpenPgpCredentialRecord } from './openpgp-credential.ts'
import type { VaultDeliveryPackV1 } from './delivery-pack.ts'
import type { VaultDeliveryVerifierProjector } from './delivery-ingest.ts'
import { verifyVaultEvent, type VaultEventVerifier } from './events.ts'
import type { SegmentKeyWrapVerifier } from './crypto.ts'
import { StoredSegmentKeyResolver, type VaultEpochKeyResolver } from './segment-key-resolver.ts'
import type { SegmentKeyWrapReader } from './store.ts'

export interface VaultDeliveryProjectorOptions {
  identityId: IdentityId
  currentSnapshot(): Promise<LocalJmapSnapshot>
  epochs: VaultEpochKeyResolver
  verifier: VaultEventVerifier & SegmentKeyWrapVerifier
}

/**
 * Concrete receive-side verifier for the mutation subset currently supported
 * by Local JMAP. It checks every current MLS wrap and event signature before
 * decrypting its object, then produces the next deterministic projection.
 */
export class VaultDeliveryProjector implements VaultDeliveryVerifierProjector {
  constructor(private readonly options: VaultDeliveryProjectorOptions) {
    if (!options.identityId) throw new TypeError('vault delivery projector identity is required')
  }

  async verifyAndProject(pack: VaultDeliveryPackV1): Promise<{
    projection: LocalJmapProjectionV1
    jmapState: { state: string }
    checkpointId: string
  }> {
    if (pack.identityId !== this.options.identityId) throw new TypeError('vault delivery pack identity is not local identity')
    const current = await this.options.epochs.currentVaultEpoch(pack.identityId)
    const wraps = new PackSegmentKeyWrapReader(pack.keyWraps)
    validateCurrentWraps(pack.identityId, pack.keyWraps, current.selfGroupId, current.epoch)
    const keys = new Map<SegmentId, Uint8Array>()
    try {
      const resolver = new StoredSegmentKeyResolver(wraps, this.options.epochs, this.options.verifier)
      const objects = objectMap(pack.objects)
      for (const object of objects.values()) {
        if (!(await verifyVaultObjectIntegrity(object))) throw new TypeError('vault delivery object integrity is invalid')
      }
      const records = []
      for (const event of pack.events) {
        if (!(await verifyVaultEvent(event, this.options.verifier))) throw new TypeError('vault delivery event signature is invalid')
        const expectedObjectRefs = event.kind === 'message.add' ? 2 : 1
        if (event.objectRefs.length !== expectedObjectRefs) {
          throw new TypeError(event.kind === 'message.add'
            ? 'vault delivery message.add must reference metadata and raw RFC 5322 objects'
            : 'vault delivery mutation event must reference exactly one object')
        }
        const object = objects.get(event.objectRefs[0])
        if (!object) throw new TypeError('vault delivery event references an absent object')
        if (event.kind === 'message.add' && !objects.has(event.objectRefs[1])) {
          throw new TypeError('vault delivery message.add references an absent raw RFC 5322 object')
        }
        let key = keys.get(object.segmentId)
        if (!key) {
          key = await resolver.resolveSegmentKey(pack.identityId, object.segmentId)
          keys.set(object.segmentId, key)
        }
        const plaintext = await decryptVaultObject(key, object)
        if (event.kind === 'credential.openpgp.set') {
          assertOpenPgpCredentialRecord(event, object, plaintext)
        } else {
          records.push({ event, plaintext })
        }
      }
      const base = await this.options.currentSnapshot()
      const next = reduceLocalJmapProjection(pack.identityId, base, records)
      const projection: LocalJmapProjectionV1 = { version: 1, identityId: pack.identityId, ...next }
      return { projection, jmapState: { state: projection.state }, checkpointId: projection.state }
    } finally {
      for (const key of keys.values()) key.fill(0)
    }
  }
}

class PackSegmentKeyWrapReader implements SegmentKeyWrapReader {
  private readonly values = new Map<string, SegmentKeyWrapV1>()

  constructor(wraps: SegmentKeyWrapV1[]) {
    for (const wrap of wraps) {
      const key = wrapKey(wrap.identityId, wrap.segmentId, wrap.recipientEpoch)
      if (this.values.has(key)) throw new TypeError('vault delivery pack has duplicate current key wrap')
      this.values.set(key, wrap)
    }
  }

  async readSegmentKeyWrap(identityId: IdentityId, segmentId: string, recipientEpoch: string): Promise<SegmentKeyWrapV1 | undefined> {
    const wrap = this.values.get(wrapKey(identityId, segmentId, recipientEpoch))
    return wrap && copyWrap(wrap)
  }
}

function validateCurrentWraps(identityId: IdentityId, wraps: SegmentKeyWrapV1[], selfGroupId: string, epoch: MlsEpoch): void {
  if (wraps.length === 0) throw new TypeError('vault delivery pack has no current MLS key wraps')
  for (const wrap of wraps) {
    if (wrap.identityId !== identityId || wrap.selfGroupId !== selfGroupId || wrap.recipientEpoch !== epoch) {
      throw new TypeError('vault delivery key wrap is not for the current MLS epoch')
    }
  }
}

function objectMap(objects: VaultObjectV1[]): Map<string, VaultObjectV1> {
  const values = new Map<string, VaultObjectV1>()
  for (const object of objects) {
    if (values.has(object.objectId)) throw new TypeError('vault delivery pack has duplicate object ID')
    values.set(object.objectId, object)
  }
  return values
}

function wrapKey(identityId: IdentityId, segmentId: string, epoch: string): string {
  return `${identityId}\u0000${segmentId}\u0000${epoch}`
}

function copyWrap(wrap: SegmentKeyWrapV1): SegmentKeyWrapV1 {
  return { ...wrap, nonce: wrap.nonce.slice(), aad: wrap.aad.slice(), wrappedSegmentKey: wrap.wrappedSegmentKey.slice(), signature: wrap.signature.slice() }
}
