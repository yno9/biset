// The Vault-side identity boundary: SegmentKey resolution, this device's
// writable segment, and the Local JMAP read model.
import { StoredSegmentKeyResolver, type SegmentKeyResolver } from '../store/vault/segment-key-resolver.ts'
import { ActiveVaultSegmentManager, type ActiveVaultSegment } from '../store/vault/active-segment.ts'
import type { ActiveVaultSegmentStore } from '../store/vault/store.ts'
import type { ActorSequenceStore, VaultObjectReader, VaultProjectionReader, VaultRecordReader } from '../store/vault/store.ts'
import { VaultObjectBlobReader } from '../store/vault/blob-reader.ts'
import type { LocalJmapReadModel } from '../store/projection/gateway.ts'
import { IndexedDbLocalJmapReadModel } from '../store/projection/indexeddb.ts'
import { type VaultEventId } from '../../protocol/ids.ts'
import type { VaultEventAuthor } from '../store/vault/events.ts'

export interface VaultCryptoBoundary {
  /** Resolves a SegmentKey for reading an already-encrypted vault object. */
  resolver: SegmentKeyResolver
  /** This device, as the author of new Vault events. */
  author: VaultEventAuthor
  /** `vault-mutation-sink.ts`'s `activeSegment()` option. */
  activeSegment(): Promise<ActiveVaultSegment>
}

/** A Wallet-authorized identity and this browser's Vault author id. */
export interface WalletVaultIdentity {
  did: string
  deviceId: string
}

export function buildWalletVaultCryptoBoundary(
  segments: ActiveVaultSegmentStore,
  identity: WalletVaultIdentity,
): VaultCryptoBoundary {
  if (!identity.did || !identity.deviceId) throw new Error('buildWalletVaultCryptoBoundary: Wallet device is incomplete')
  const author: VaultEventAuthor = { deviceId: identity.deviceId }
  const resolver = new StoredSegmentKeyResolver(segments)
  const segmentManager = new ActiveVaultSegmentManager({ identityId: identity.did, segments })
  return { resolver, author, activeSegment: () => segmentManager.activeSegment() }
}
/** Opens local Vault blobs with the SegmentKeys this device holds. */
export function buildLocalJmapReadModel(
  vault: VaultProjectionReader & VaultObjectReader & Pick<ActiveVaultSegmentStore, 'readSegmentKey'>,
  identityId: string,
): LocalJmapReadModel {
  const resolver = new StoredSegmentKeyResolver(vault)
  return new IndexedDbLocalJmapReadModel(vault, identityId, new VaultObjectBlobReader(vault, resolver))
}

/**
 * `VaultBackedLocalJmapMutationSink` needs `nextActorSeq()`/`initialParents()`
 * from every caller, and until now every one has been a test's own trivial
 * in-memory counter starting at zero. That's wrong for a real device across
 * page reloads: `actorSeq` feeds the reducer's LWW tie-break
 * (local-jmap/reducer.ts's `compareEvents`), so starting from zero again
 * risks colliding with sequences this device already used in a past
 * session. Sequence reservations are persisted and serialized by IndexedDB;
 * the store also seeds them from this device's actual vault history.
 *
 * `parents` is populated with a real value (the latest event, if any) but
 * costs nothing to get slightly wrong -- `VaultEventV1.parents` is signed
 * but confirmed unused by any reader anywhere in this codebase (PLAN.md's
 * own progress log), so no causal-ordering correctness rides on it.
 */
export async function buildActorSequencer(
  records: VaultRecordReader & ActorSequenceStore,
  identityId: string,
  deviceId: string,
): Promise<{ nextActorSeq(): Promise<number>; initialParents(): Promise<VaultEventId[]> }> {
  const events = await records.readVaultEvents(identityId)
  const mine = events.filter(event => event.actorDeviceId === deviceId)
  let latest: VaultEventId | undefined
  let latestSeq = 0
  for (const event of mine) if (event.actorSeq >= latestSeq) { latestSeq = event.actorSeq; latest = event.id }
  return {
    async nextActorSeq() { return records.reserveActorSeq(identityId, deviceId) },
    async initialParents() { return latest ? [latest] : [] },
  }
}
