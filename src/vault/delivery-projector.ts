import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import { reduceLocalJmapProjection } from '../local-jmap/reducer.ts'
import type { IdentityId, MlsEpoch } from '../shared/protocol/ids.ts'
import type { SegmentKeyWrapV1 } from '../shared/protocol/vault.ts'
import type { VaultDeliveryPackV1 } from './delivery-pack.ts'
import type { VaultDeliveryVerifierProjector } from './delivery-ingest.ts'
import type { VaultEventVerifier } from './events.ts'
import type { SegmentKeyWrapVerifier } from './crypto.ts'
import { decryptVaultMutationRecords } from './mutation-records.ts'
import { StoredSegmentKeyResolver, type VaultEpochKeyResolver } from './segment-key-resolver.ts'
import type { SegmentKeyWrapReader } from './store.ts'
import { VAULT_STORAGE_EPOCH, VAULT_STORAGE_GROUP_ID } from './storage-root.ts'

export interface VaultDeliveryProjectorOptions {
  identityId: IdentityId
  currentSnapshot(): Promise<LocalJmapSnapshot>
  epochs: VaultEpochKeyResolver
  verifier: VaultEventVerifier & SegmentKeyWrapVerifier
  storageKek?: Uint8Array
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
    const wraps = new PackSegmentKeyWrapReader(pack.keyWraps)
    if (this.options.storageKek && pack.keyWraps.every(wrap => wrap.selfGroupId === VAULT_STORAGE_GROUP_ID && wrap.recipientEpoch === VAULT_STORAGE_EPOCH)) {
      validateStableWraps(pack.identityId, pack.keyWraps)
    } else {
      const current = await this.options.epochs.currentVaultEpoch(pack.identityId)
      validateCurrentWraps(pack.identityId, pack.keyWraps, current.selfGroupId, current.epoch)
    }
    const resolver = new StoredSegmentKeyResolver(wraps, this.options.epochs, this.options.verifier, this.options.storageKek)
    const records = await decryptVaultMutationRecords(pack.identityId, pack.events, pack.objects, resolver, this.options.verifier)
    const base = await this.options.currentSnapshot()
    const next = reduceLocalJmapProjection(pack.identityId, base, records)
    const projection: LocalJmapProjectionV1 = { version: 1, identityId: pack.identityId, ...next }
    return { projection, jmapState: { state: projection.state }, checkpointId: projection.state }
  }
}

function validateStableWraps(identityId: IdentityId, wraps: SegmentKeyWrapV1[]): void {
  if (wraps.length === 0) throw new TypeError('vault delivery pack has no Vault storage key wraps')
  for (const wrap of wraps) if (wrap.identityId !== identityId || wrap.selfGroupId !== VAULT_STORAGE_GROUP_ID || wrap.sourceEpoch !== VAULT_STORAGE_EPOCH || wrap.recipientEpoch !== VAULT_STORAGE_EPOCH) throw new TypeError('vault delivery key wrap is not for stable Vault storage')
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

function wrapKey(identityId: IdentityId, segmentId: string, epoch: string): string {
  return `${identityId}\u0000${segmentId}\u0000${epoch}`
}

function copyWrap(wrap: SegmentKeyWrapV1): SegmentKeyWrapV1 {
  return { ...wrap, nonce: wrap.nonce.slice(), aad: wrap.aad.slice(), wrappedSegmentKey: wrap.wrappedSegmentKey.slice(), signature: wrap.signature.slice() }
}
