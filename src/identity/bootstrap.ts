// The Vault-side identity boundary: MLS epoch keys, SegmentKey wraps and
// their membership signer/verifier, the Local JMAP read model and projection
// rebuild, and the MIMI Vault room a did.md Wallet device joins or creates.
//
// Everything here is now driven by a Wallet-authorized device -- a public
// DID plus this browser's own MLS leaf. The seed side of this file
// (`createNewIdentity`, `restoreIdentity`, `registerDevice`, the
// Master-derived storage KEK boundary, mail submission, `enableDidComm` and
// `ensureMimiVaultRoom`) was removed in N1 (2026-09-05): biset no longer
// issues or restores an identity of its own, so no Root, Sign, Spare or
// Master material is representable in this module at all.
import { ed25519 } from '@noble/curves/ed25519.js'
import { defaultFetch } from '../net-fetch.ts'
import { epochOf, exportSecret, ownMlsDeviceCredential, ownSignaturePrivateKey, setMlsAuthService } from '../mls/group.ts'
import { type MlsDeviceCredentialV2 } from '../mls/device-credential.ts'
import { webvhAuthenticationService } from '../mls/webvh-authentication-service.ts'
import { StoredSegmentKeyResolver, type SegmentKeyResolver, type VaultEpochKeyResolver } from '../vault/segment-key-resolver.ts'
import { ActiveVaultSegmentManager, type ActiveVaultSegment } from '../vault/active-segment.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter } from '../vault/store.ts'
import { deriveVaultEpochKey, MlsVaultEpochKeyResolver } from '../mls/vault-epoch.ts'
import { MlsMembershipSegmentKeyWrapSigner, MlsMembershipSegmentKeyWrapVerifier } from '../mls/segment-key-membership.ts'
import { StoredMlsSelfGroupProvider, type MlsSelfGroupStateStore } from '../mls/store.ts'
import { createMimiVaultRoom, joinMimiVaultRoom } from '../mls/mimi-vault-room.ts'
import { MimiClientTransport } from '../mls/mimi-client-transport.ts'
import type { MimiVaultSessionRecord, MimiVaultSessionStateStore } from '../mls/mimi-vault-session.ts'
import { createSegmentKeyWrap, segmentKeyWrapSigningBytes, unwrapSegmentKey } from '../vault/crypto.ts'
import type { RestoreTransferSource, RestoreTransferVerifier } from '../vault/restore-transfer.ts'
import { buildVaultManifest } from '../vault/manifest.ts'
import type { VaultObjectReader, VaultProjectionReader, VaultProjectionWriter, VaultRecordReader } from '../vault/store.ts'
import { VaultDeliveryProjector } from '../vault/delivery-projector.ts'
import { rebuildLocalJmapProjection } from '../vault/projection-rebuild.ts'
import { VaultObjectBlobReader } from '../vault/blob-reader.ts'
import type { LocalJmapProjectionV1, LocalJmapReadModel, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import { IndexedDbLocalJmapReadModel, type LocalVaultBlobReader } from '../local-jmap/indexeddb.ts'
import { equalBytes } from '../shared/protocol/canonical.ts'
import { mlsEpoch, type VaultEventId } from '../shared/protocol/ids.ts'
import type { ClientState } from '../mls/vendor/index.ts'
import { VAULT_STORAGE_GROUP_ID } from '../vault/storage-root.ts'

let authServiceInstalled = false
/** Idempotent: `setMlsAuthService` is one global (group.ts's own note on
 * why), so calling this more than once across a session's several
 * Wallet-device bootstraps must be harmless. */
export function ensureMlsAuthServiceInstalled(): void {
  if (authServiceInstalled) return
  setMlsAuthService(webvhAuthenticationService)
  authServiceInstalled = true
}

export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

/**
 * Repairs a local Vault whose segment metadata is more than one MLS epoch
 * behind. `selfGrantSegmentRewraps` can use the superseded exporter only at
 * the exact transition where it is observed; after a crash or a skipped
 * epoch that secret is intentionally gone. Local Vault segment records also
 * hold the same random SegmentKey needed for offline reads, so the endpoint
 * can safely mint a new current-epoch wrap without asking a server or peer.
 *
 * This is endpoint-local recovery only. No SegmentKey or identity metadata
 * leaves IndexedDB, and the replacement wrap is signed by the current MLS
 * member just like an ordinary self-grant.
 */
/** The repair needs only the locally held MLS leaf, not controller or Master
 * material.  Wallet-authorized Biset devices use the same repair after an
 * MLS epoch changes. */
export interface VaultSegmentRepairIdentity {
  did: string
  deviceKid?: string
}

export async function repairCurrentLocalSegmentKeyWraps(
  selfGroupStore: MlsSelfGroupStateStore,
  segments: ActiveVaultSegmentStore,
  wraps: SegmentKeyWrapReader & SegmentKeyWrapWriter,
  record: VaultSegmentRepairIdentity,
  now: () => Date = () => new Date(),
): Promise<number> {
  if (!record.deviceKid) return 0
  const stored = await selfGroupStore.load(record.did)
  if (!stored) return 0
  const state = stored.state
  const currentEpoch = mlsEpoch(epochOf(state))
  const signer = new MlsMembershipSegmentKeyWrapSigner(record.deviceKid, async () => state)
  const verifier = new MlsMembershipSegmentKeyWrapVerifier(async () => state)
  const localSegments = await segments.allSegments(record.did)
  if (localSegments.length === 0) return 0
  const vek = await deriveVaultEpochKey({ selfGroupId: stored.selfGroupId, epoch: currentEpoch, exportSecret: (label, context, length) => exportSecret(state, label, context, length) })
  let repaired = 0
  try {
    for (const segment of localSegments) {
      // A segment already on the storage-root scheme (vault/storage-root.ts)
      // is wrapped under a stable, root-derived KEK, not an epoch-derived
      // VEK -- there is no "more than one self-group epoch behind" concept
      // for it to repair, so it isn't this function's concern. Every fresh
      // Vault (ActiveVaultSegmentManager's stableActiveSegment path,
      // vault/active-segment.ts) creates its segments under this scheme
      // from the start, so without this skip every identity throws here on
      // every single boot; this function had no matching exclusion (found
      // live, 2026-08-31: the mismatch fired unconditionally, caught and
      // only ever logged as
      // "local Vault segment belongs to another self group").
      if (segment.selfGroupId === VAULT_STORAGE_GROUP_ID) continue
      if (segment.selfGroupId !== stored.selfGroupId) throw new TypeError('local Vault segment belongs to another self group')
      const current = await wraps.readSegmentKeyWrap(record.did, segment.segmentId, currentEpoch)
      if (current) {
        const unwrapped = await unwrapSegmentKey(vek, current, verifier)
        try {
          if (!equalBytes(unwrapped, segment.segmentKey)) throw new TypeError('local Vault segment key does not match its current wrap')
        } finally {
          unwrapped.fill(0)
        }
      } else {
        const replacement = await createSegmentKeyWrap(vek, segment.segmentKey, {
          identityId: record.did,
          selfGroupId: stored.selfGroupId,
          segmentId: segment.segmentId,
          sourceEpoch: segment.epoch,
          recipientEpoch: currentEpoch,
          grantorDeviceId: record.deviceKid,
          grantedAt: now().toISOString(),
        }, signer)
        await wraps.writeSegmentKeyWrap(replacement)
        repaired += 1
      }
      if (segment.epoch !== currentEpoch) await segments.recordSegmentRewrapped(record.did, segment.segmentId, currentEpoch)
    }
    return repaired
  } finally {
    vek.fill(0)
    for (const segment of localSegments) segment.segmentKey.fill(0)
  }
}

export interface VaultCryptoBoundary {
  /** Current self-group epoch boundary, also used to rewrap a recovered
   * remote checkpoint before committing it locally. */
  epochs: VaultEpochKeyResolver
  /** Resolves a SegmentKey for reading an already-encrypted vault object. */
  resolver: SegmentKeyResolver
  /** Signs (and, via the same underlying membership check, verifies) new
   * SegmentKeyWraps this device grants — `createSegmentKeyWrap`
   * (vault/crypto.ts) takes this directly. */
  signer: MlsMembershipSegmentKeyWrapSigner
  /** `vault-mutation-sink.ts`'s `activeSegment()` option, straight from this
   * boundary's own epoch/signer wiring — mints a fresh SegmentKey and seals
   * the old one whenever the self-group epoch has moved on (PLAN.md §4.2). */
  activeSegment(): Promise<ActiveVaultSegment>
}

/**
 * The narrow Vault boundary available to an external, Wallet-authorized
 * Biset device.  It intentionally accepts only the public DID and this
 * device's MLS leaf ID: Root, Sign, Spare, and Master material are neither
 * required nor representable here.
 *
 * Unlike a locally-created Biset identity, this boundary never enables the
 * stable Master-derived storage KEK.  New delivery wraps therefore stay
 * bound to the current MLS epoch and a newly joined Wallet device cannot
 * read pre-join Vault history merely because it has a browser session.
 */
export interface WalletVaultIdentity {
  did: string
  deviceKid: string
}

export function buildWalletVaultCryptoBoundary(
  wraps: SegmentKeyWrapReader & SegmentKeyWrapWriter,
  segments: ActiveVaultSegmentStore,
  selfGroupStore: MlsSelfGroupStateStore,
  identity: WalletVaultIdentity,
): VaultCryptoBoundary {
  if (!identity.did || !identity.deviceKid) throw new Error('buildWalletVaultCryptoBoundary: Wallet device is incomplete')
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(identity.did)
    if (!stored) throw new Error('buildWalletVaultCryptoBoundary: no self-group state for this Wallet device')
    return stored.state
  }
  const epochs = new MlsVaultEpochKeyResolver(new StoredMlsSelfGroupProvider(selfGroupStore))
  const signer = new MlsMembershipSegmentKeyWrapSigner(identity.deviceKid, loadState)
  const resolver = new StoredSegmentKeyResolver(wraps, epochs, signer)
  const segmentManager = new ActiveVaultSegmentManager({ identityId: identity.did, segments, wraps, epochs, signer })
  return { epochs, resolver, signer, activeSegment: () => segmentManager.activeSegment() }
}

/**
 * Wires PLAN.md §4.3's "actual MLS grant verification" — `RestoreTransferVerifier`
 * (`vault/restore-transfer.ts`) has always needed one, but nothing built it
 * against a real self group. Both halves it asks for — an event's actor and
 * a SegmentKeyWrap's grantor — are the same "is this device kid currently a
 * self-group member with this signature key" question
 * `MlsMembershipSegmentKeyWrapVerifier` already answers (both
 * `VaultEventVerifier` and `SegmentKeyWrapVerifier` share that
 * `verify(deviceId, bytes, signature)` shape), so one instance backs both.
 *
 * Deliberately takes no local device identity: verifying an incoming
 * transfer frame is a property of the receiver's OWN current self-group
 * view, not of who is asking.
 */
export function buildRestoreTransferVerifier(selfGroupStore: MlsSelfGroupStateStore, identityId: string, rootPublicKey?: Uint8Array): RestoreTransferVerifier {
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(identityId)
    if (!stored) throw new Error('buildRestoreTransferVerifier: no self-group state for this identity')
    return stored.state
  }
  const verifier = new MlsMembershipSegmentKeyWrapVerifier(loadState, rootPublicKey)
  return {
    eventVerifier: verifier,
    verifyCurrentEpochWrap: wrap => verifier.verify(wrap.grantorDeviceId, segmentKeyWrapSigningBytes(wrap), wrap.signature),
  }
}

/**
 * The SENDING side of a peer restore transfer (`vault/restore-transfer.ts`'s
 * `RestoreTransferSource`, consumed by `createRestoreTransferChunk`) — the
 * counterpart to `buildRestoreTransferVerifier`, which is the receiving
 * side. `manifest`/`readEvents`/`readObjects` are plain reads off this
 * device's own vault records; `readCurrentEpochWraps` is PLAN.md §4.2's
 * "restore grant": it never touches the requested segment's ciphertext or
 * mints a new SegmentKey, it only unwraps this device's own current-epoch
 * wrap (`resolver.resolveSegmentKey`) and re-wraps the SAME SegmentKey under
 * the requester's current epoch — the thing the requester actually asked
 * for.
 *
 * Requires the caller (`identityId`'s current epoch) and the requester
 * (`recipientEpoch`) to be at the SAME current self-group epoch: a restore
 * grant is a live-member operation, not a way to hand out a key for an
 * epoch this device cannot itself derive a VEK for.
 */
export function buildRestoreTransferSource(
  records: VaultRecordReader,
  wraps: SegmentKeyWrapReader,
  selfGroupStore: MlsSelfGroupStateStore,
  record: VaultSegmentRepairIdentity,
): RestoreTransferSource {
  if (!record.deviceKid) throw new Error('buildRestoreTransferSource: identity has no deviceKid yet')
  const deviceKid = record.deviceKid
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(record.did)
    if (!stored) throw new Error('buildRestoreTransferSource: no self-group state for this identity')
    return stored.state
  }
  const epochs = new MlsVaultEpochKeyResolver(new StoredMlsSelfGroupProvider(selfGroupStore))
  const resolver = new StoredSegmentKeyResolver(wraps, epochs, new MlsMembershipSegmentKeyWrapVerifier(loadState))
  const signer = new MlsMembershipSegmentKeyWrapSigner(deviceKid, loadState)

  return {
    async manifest(identityId) {
      const [events, objects] = await Promise.all([records.readVaultEvents(identityId), records.readVaultObjects(identityId)])
      return buildVaultManifest(identityId, events.map(event => event.id), objects.map(object => object.objectId), new Date().toISOString())
    },
    async readEvents(identityId, ids) {
      const byId = new Map((await records.readVaultEvents(identityId)).map(event => [event.id, event]))
      return ids.map(id => {
        const event = byId.get(id)
        if (!event) throw new Error(`buildRestoreTransferSource: missing event ${id}`)
        return event
      })
    },
    async readObjects(identityId, ids) {
      const byId = new Map((await records.readVaultObjects(identityId)).map(object => [object.objectId, object]))
      return ids.map(id => {
        const object = byId.get(id)
        if (!object) throw new Error(`buildRestoreTransferSource: missing object ${id}`)
        return object
      })
    },
    async readCurrentEpochWraps(identityId, segmentIds, recipientEpoch) {
      const current = await epochs.currentVaultEpoch(identityId)
      if (current.epoch !== recipientEpoch) {
        throw new Error('buildRestoreTransferSource: requested epoch is not this device\'s own current epoch')
      }
      const grantedAt = new Date().toISOString()
      return Promise.all(segmentIds.map(async segmentId => {
        const segmentKey = await resolver.resolveSegmentKey(identityId, segmentId)
        try {
          const vek = await epochs.deriveVaultEpochKey(identityId, current.selfGroupId, current.epoch)
          try {
            return await createSegmentKeyWrap(vek, segmentKey, {
              identityId,
              selfGroupId: current.selfGroupId,
              segmentId,
              sourceEpoch: current.epoch,
              recipientEpoch: current.epoch,
              grantorDeviceId: deviceKid,
              grantedAt,
            }, signer)
          } finally {
            vek.fill(0)
          }
        } finally {
          segmentKey.fill(0)
        }
      }))
    },
  }
}

/**
 * Wires PLAN.md §3.3's shared vault delivery ingest to this identity's
 * actual self group: `VaultDeliveryProjector` (`vault/delivery-projector.ts`)
 * has always performed the real verify-then-decrypt-then-project work, but
 * needed a `VaultEpochKeyResolver` and a `VaultEventVerifier &
 * SegmentKeyWrapVerifier` to do it against — the same
 * `MlsVaultEpochKeyResolver`/`MlsMembershipSegmentKeyWrapVerifier` pair
 * `buildVaultCryptoBoundary` already assembles for local writes.
 *
 * `currentSnapshot` is the caller's own read of its current Local JMAP
 * projection (`local-jmap/gateway.ts`'s `LocalJmapSnapshot`) — this module
 * has no projection store of its own to read one from.
 */
export function buildVaultDeliveryProjector(
  selfGroupStore: MlsSelfGroupStateStore,
  identityId: string,
  currentSnapshot: () => Promise<LocalJmapSnapshot>,
): VaultDeliveryProjector {
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(identityId)
    if (!stored) throw new Error('buildVaultDeliveryProjector: no self-group state for this identity')
    return stored.state
  }
  const epochs = new MlsVaultEpochKeyResolver(new StoredMlsSelfGroupProvider(selfGroupStore))
  const verifier = new MlsMembershipSegmentKeyWrapVerifier(loadState)
  return new VaultDeliveryProjector({ identityId, currentSnapshot, epochs, verifier })
}

/**
 * Wires PLAN.md §3.2/§5.2's "full projection rebuild" to this identity's
 * actual self group — the same `MlsVaultEpochKeyResolver`/
 * `MlsMembershipSegmentKeyWrapVerifier` pair `buildVaultDeliveryProjector`
 * assembles, handed to `rebuildLocalJmapProjection`
 * (`vault/projection-rebuild.ts`) instead. Returns a function rather than a
 * bare promise since this is meant to be called more than once per identity
 * — at minimum once to seed a brand-new identity's very first (empty)
 * `vault_projection` row (nothing else does; see `VaultProjectionWriter`'s
 * own doc comment), and again on demand for disaster recovery.
 */
export function buildLocalJmapProjectionRebuild(
  records: VaultRecordReader,
  wraps: SegmentKeyWrapReader,
  projections: VaultProjectionWriter,
  selfGroupStore: MlsSelfGroupStateStore,
  identityId: string,
): () => Promise<LocalJmapProjectionV1> {
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(identityId)
    if (!stored) throw new Error('buildLocalJmapProjectionRebuild: no self-group state for this identity')
    return stored.state
  }
  const epochs = new MlsVaultEpochKeyResolver(new StoredMlsSelfGroupProvider(selfGroupStore))
  const verifier = new MlsMembershipSegmentKeyWrapVerifier(loadState)
  return async () => {
    const projection = await rebuildLocalJmapProjection({ identityId, records, wraps, epochs, verifier })
    await projections.writeProjection(identityId, projection, { state: projection.state })
    return projection
  }
}

/**
 * Wires PLAN.md §5.2's "stored key wrap からの SegmentKey resolver /
 * attachment chunk reader" to this identity's actual self group —
 * `local-jmap/indexeddb.ts`'s `IndexedDbLocalJmapReadModel` takes exactly
 * this shape (`LocalVaultBlobReader`) for its own `download`. Reuses the
 * same current-epoch `StoredSegmentKeyResolver`/`MlsMembershipSegmentKeyWrapVerifier`
 * pairing every other boundary in this module builds; a blob is just
 * another vault object, decrypted the same way a mutation's is.
 */
export function buildVaultBlobReader(
  objects: VaultObjectReader,
  wraps: SegmentKeyWrapReader,
  selfGroupStore: MlsSelfGroupStateStore,
  identityId: string,
): LocalVaultBlobReader {
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(identityId)
    if (!stored) throw new Error('buildVaultBlobReader: no self-group state for this identity')
    return stored.state
  }
  const epochs = new MlsVaultEpochKeyResolver(new StoredMlsSelfGroupProvider(selfGroupStore))
  const verifier = new MlsMembershipSegmentKeyWrapVerifier(loadState)
  const resolver = new StoredSegmentKeyResolver(wraps, epochs, verifier)
  return new VaultObjectBlobReader(objects, resolver)
}

/**
 * PLAN.md §7's vault UI needs one thing from the identity layer: a ready
 * `LocalJmapReadModel` for the account it just found locally. This is that
 * boundary — it composes `buildVaultBlobReader` (above) with
 * `IndexedDbLocalJmapReadModel` (`local-jmap/indexeddb.ts`), the same way
 * every other function in this module composes the MLS/vault-crypto
 * primitives once so the UI layer never has to know `SegmentKeyResolver`,
 * `VaultEpochKeyResolver`, or self-group state exist. `vault` doubles as
 * the `VaultProjectionReader` the read model itself needs and the
 * `VaultObjectReader` the blob reader needs — `IndexedDbVaultStore`
 * already implements both, so callers pass one store for both roles.
 */
export function buildLocalJmapReadModel(
  vault: VaultProjectionReader & VaultObjectReader & SegmentKeyWrapReader,
  selfGroupStore: MlsSelfGroupStateStore,
  identityId: string,
): LocalJmapReadModel {
  const blobs = buildVaultBlobReader(vault, vault, selfGroupStore, identityId)
  return new IndexedDbLocalJmapReadModel(vault, identityId, blobs)
}

export interface EnsuredMimiVaultRoom {
  credential: MlsDeviceCredentialV2
  signaturePrivateKey: Uint8Array
  selfGroupId: string
  room: MimiVaultSessionRecord
  transport: MimiClientTransport
  provider: URL
}

/** A did.md Wallet device has the same Biset MLS leaf shape as a locally
 * created identity, but intentionally lacks the Root, Sign, and Master
 * secrets that `IdentityRecord` carries.  This narrower bootstrap keeps the
 * controller boundary honest: Wallet has already signed the routing pointer
 * and certified the leaf, so Biset only creates the initially reserved room
 * or externally joins the one a prior device created. */
export interface WalletMimiVaultDevice {
  did: string
  credential: MlsDeviceCredentialV2
  signaturePrivateKey: Uint8Array
  roomId: string
  providerUrl: string
  /** True only for the device which reserved an empty room through Wallet. */
  createRoom: boolean
}

export async function ensureWalletMimiVaultRoom(
  device: WalletMimiVaultDevice,
  selfGroupStore: MlsSelfGroupStateStore & MimiVaultSessionStateStore,
  mimiSelfBaseUrl: string,
): Promise<EnsuredMimiVaultRoom> {
  ensureMlsAuthServiceInstalled()
  const provider = new URL(mimiSelfBaseUrl)
  if (provider.protocol !== 'https:' || provider.toString() !== device.providerUrl || !new RegExp(`^mimi://${provider.hostname.replace(/[.]/g, '\\.')}/r/vault-[A-Za-z0-9_-]{43}$`).test(device.roomId)) {
    throw new Error('Wallet MIMI Vault pointer does not match this Biset provider')
  }
  const signaturePublicKey = ed25519.getPublicKey(device.signaturePrivateKey)
  if (device.credential.identityId !== device.did || !device.credential.signaturePublicKey.every((byte, index) => signaturePublicKey[index] === byte)) {
    throw new Error('Wallet MIMI Vault device credential does not match this browser key')
  }
  const transport = new MimiClientTransport({ normalBaseUrl: mimiSelfBaseUrl, anonBaseUrl: mimiSelfBaseUrl, selfBaseUrl: mimiSelfBaseUrl, fetch: defaultFetch() })
  const selfGroupId = 'mimi-vault'
  const create = () => createMimiVaultRoom({
    identityId: device.did, deviceId: device.credential.deviceKid, selfGroupId, roomId: device.roomId,
    credential: device.credential, signaturePrivateKey: device.signaturePrivateKey, transport, stateStore: selfGroupStore,
    providerHost: provider.hostname,
  })
  const join = () => joinMimiVaultRoom({
    identityId: device.did, deviceId: device.credential.deviceKid, selfGroupId, roomId: device.roomId,
    credential: device.credential, signaturePrivateKey: device.signaturePrivateKey, transport, stateStore: selfGroupStore,
  })
  let room = await selfGroupStore.loadMimiVault(device.did)
  if (room && room.roomId !== device.roomId) throw new Error('This browser has a different local MIMI Vault room; disconnect and clear its Biset device data before reconnecting')
  if (!room && device.createRoom) {
    try {
      await create()
    } catch (createError) {
      // The provider may have accepted the first commit while this browser
      // crashed before IndexedDB saved its state. Retrying a create would be
      // wrong; an external join is the safe recovery path for the same
      // Wallet-authorized leaf. If the room genuinely was never created,
      // join fails too and the original create failure remains visible.
      try {
        await join()
      } catch { throw createError }
    }
    room = await selfGroupStore.loadMimiVault(device.did)
  } else if (!room) {
    try {
      await join()
    } catch (joinError) {
      // Wallet publishes the room pointer as part of approval, before Biset
      // has created the initial MLS room. If that first browser is interrupted
      // (for example by a blocked Safari popup), a later authorization sees
      // the pointer and would otherwise only attempt this failing join.
      if (!(joinError instanceof Error) || joinError.message !== 'MIMI Vault external join GroupInfo failed: noSuchRoom') throw joinError
      try {
        await create()
      } catch (createError) {
        // A sibling may have created the room after our noSuchRoom response.
        // In that race, joining is the only safe recovery; otherwise preserve
        // the create error rather than masking a genuine provider failure.
        try { await join() } catch { throw createError }
      }
    }
    room = await selfGroupStore.loadMimiVault(device.did)
  }
  if (!room) throw new Error('Wallet MIMI Vault room initialization did not persist')
  const storedCredential = ownMlsDeviceCredential(room.state)
  if (storedCredential.deviceKid !== device.credential.deviceKid) throw new Error('Wallet MIMI Vault stored state belongs to another device')
  return { credential: storedCredential, signaturePrivateKey: ownSignaturePrivateKey(room.state), selfGroupId, room, transport, provider }
}

/**
 * `VaultBackedLocalJmapMutationSink` needs `nextActorSeq()`/`initialParents()`
 * from every caller, and until now every one has been a test's own trivial
 * in-memory counter starting at zero. That's wrong for a real device across
 * page reloads: `actorSeq` feeds the reducer's LWW tie-break
 * (local-jmap/reducer.ts's `compareEvents`), so starting from zero again
 * risks colliding with sequences this device already used in a past
 * session. Seeds from this device's own actual vault history instead.
 *
 * `parents` is populated with a real value (the latest event, if any) but
 * costs nothing to get slightly wrong -- `VaultEventV1.parents` is signed
 * but confirmed unused by any reader anywhere in this codebase (PLAN.md's
 * own progress log), so no causal-ordering correctness rides on it.
 */
export async function buildActorSequencer(
  records: VaultRecordReader,
  identityId: string,
  deviceId: string,
): Promise<{ nextActorSeq(): Promise<number>; initialParents(): Promise<VaultEventId[]> }> {
  const events = await records.readVaultEvents(identityId)
  const mine = events.filter(event => event.actorDeviceId === deviceId)
  let seq = 0
  let latest: VaultEventId | undefined
  for (const event of mine) if (event.actorSeq >= seq) { seq = event.actorSeq; latest = event.id }
  return {
    async nextActorSeq() { seq += 1; return seq },
    async initialParents() { return latest ? [latest] : [] },
  }
}
