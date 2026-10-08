// One generic implementation of the vault's private-credential read and
// write paths. The credential families (relationship-seed,
// openpgp-credential) differ only in their event kind, their record codec,
// and the noun used in error messages -- everything else (event
// verification, segment key resolution and zeroing, the atomic local
// commit) lives here once, so a fix can never reach only one copy.
import type { LocalJmapSnapshot } from '../projection/gateway.ts'
import type { LocalVaultMutationCommitter } from '../projection/vault-mutation-sink.ts'
import type { DeviceId, IdentityId, SegmentId, VaultEventId } from '../../../protocol/ids.ts'
import type { VaultEventKind, VaultEventV1, VaultObjectV1 } from '../../../protocol/vault.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from './active-segment.ts'
import { buildVaultCommit } from './commit.ts'
import { verifyVaultEvent, type VaultEventAuthor } from './events.ts'
import { decryptVaultObject } from './objects.ts'
import type { SegmentKeyResolver } from './segment-key-resolver.ts'
import type { VaultEventRecord, VaultObjectReader } from './store.ts'

/** Identical across every credential family; each family re-exports its own alias. */
interface VaultCredentialBuildContext {
  identityId: IdentityId
  actorDeviceId: DeviceId
  actorSeq: number
  parents: VaultEventId[]
  segmentId: SegmentId
  segmentKey: Uint8Array
}

/** The signed envelope plus ciphertext a credential build produces. */
interface VaultCredentialBuildResult {
  object: VaultObjectV1
  event: VaultEventV1
}

/**
 * Everything that distinguishes one credential family from another.
 * `E` is the store interface the family's events come from.
 */
export interface VaultCredentialKind<T, E> {
  eventKind: VaultEventKind
  /** Error-message noun, e.g. `contact key` in `contact key sink identity is required`. */
  label: string
  /** `assertActiveVaultSegment` purpose string; deliberately separate from `label`. */
  segmentLabel: string
  readEvents(source: E, identityId: IdentityId): Promise<VaultEventRecord[]>
  assert(event: VaultEventV1, object: VaultObjectV1, plaintext: Uint8Array): T
  build(value: T, context: VaultCredentialBuildContext, signer: VaultEventAuthor): Promise<VaultCredentialBuildResult>
  createdAtOf(value: T): string
  /** Deep copy, including the family's own secret byte fields. */
  copy(value: T): T
}

export interface VaultCredentialReaderOptions<E> {
  identityId: IdentityId
  objects: VaultObjectReader
  events: E
  segmentKeys: SegmentKeyResolver
}

/**
 * Endpoint-only reader for one credential family. It does not add
 * credentials to the JMAP projection and it never exposes a VEK: segment
 * keys are resolved lazily, cached for the duration of one read, and zeroed
 * before returning.
 */
export class VaultCredentialReader<T, E> {
  constructor(
    private readonly kind: VaultCredentialKind<T, E>,
    private readonly options: VaultCredentialReaderOptions<E>,
  ) {
    if (!options.identityId) throw new TypeError(`${kind.label} reader identity is required`)
  }

  /** Returns every verified record, including historical ones superseded by a rotation. */
  async readAll(): Promise<T[]> {
    const events = await this.kind.readEvents(this.options.events, this.options.identityId)
    const keys = new Map<SegmentId, Uint8Array>()
    try {
      const values: T[] = []
      for (const event of events) {
        if (event.kind !== this.kind.eventKind) continue
        if (!verifyVaultEvent(event)) throw new TypeError(`${this.kind.label} event is not intact`)
        if (event.objectRefs.length !== 1) throw new TypeError(`${this.kind.label} event must reference exactly one object`)
        const object = await this.options.objects.readObject(this.options.identityId, event.objectRefs[0])
        if (!object) throw new Error(`${this.kind.label} object is unavailable; restore is required`)
        let segmentKey = keys.get(object.segmentId)
        if (!segmentKey) {
          segmentKey = await this.options.segmentKeys.resolveSegmentKey(this.options.identityId, object.segmentId)
          keys.set(object.segmentId, segmentKey)
        }
        const plaintext = await decryptVaultObject(segmentKey, object)
        const value = readableCredential(this.kind.label, event.id, () => this.kind.assert(event, object, plaintext))
        if (value !== undefined) values.push(value)
      }
      return values
    } finally {
      for (const key of keys.values()) key.fill(0)
    }
  }
}

/** A credential record's content, or undefined when it is intact but in a
 * shape this version no longer reads (written before a format change -- no
 * backward compatibility is kept). Such a record is absent, not fatal: one
 * would otherwise stop every credential of its family, or every projection
 * rebuild, from completing. Tampering is still fatal: the event and object
 * integrity checks run before this. The one rule for every reader of
 * credential records (this reader, mutation-records.ts). */
export function readableCredential<T>(label: string, eventId: string, assert: () => T): T | undefined {
  try { return assert() } catch (error) {
    // Every read meets the same old records again: say so once per record.
    if (!reportedUnreadable.has(eventId)) {
      reportedUnreadable.add(eventId)
      console.warn(`[vault] skipping a ${label} record in a format this version does not read (${eventId}):`, error instanceof Error ? error.message : error)
    }
    return undefined
  }
}

const reportedUnreadable = new Set<string>()

export interface VaultCredentialSinkOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  nextActorSeq(): Promise<number>
  initialParents(): Promise<VaultEventId[]>
  activeSegment(): Promise<ActiveVaultSegment>
  currentSnapshot(): Promise<LocalJmapSnapshot>
  signer: VaultEventAuthor
  committer: LocalVaultMutationCommitter
  onCommitted?(event: VaultEventV1): Promise<void>
}

export interface VaultCredentialStoreResult {
  result: 'committed' | 'already-committed'
  event: VaultEventV1
}

/**
 * Writes a newly generated or rotated credential through the same atomic
 * local-vault and shared-delivery outbox path as normal vault changes, so
 * every other trusted device eventually sees it too. It deliberately leaves
 * the user-visible JMAP projection unchanged.
 */
export class VaultCredentialSink<T> {
  constructor(
    private readonly kind: VaultCredentialKind<T, unknown>,
    private readonly options: VaultCredentialSinkOptions,
  ) {
    if (!options.identityId || !options.actorDeviceId) throw new TypeError(`${kind.label} sink identity is required`)
  }

  async store(value: T): Promise<VaultCredentialStoreResult> {
    const segment = await this.options.activeSegment()
    assertActiveVaultSegment(this.options.identityId, segment, this.kind.segmentLabel)
    const record = await this.kind.build(value, {
      identityId: this.options.identityId,
      actorDeviceId: this.options.actorDeviceId,
      actorSeq: await this.options.nextActorSeq(),
      parents: await this.options.initialParents(),
      segmentId: segment.segmentId,
      segmentKey: segment.segmentKey,
    } satisfies VaultCredentialBuildContext, this.options.signer)
    // No `reduce`: a private credential is deliberately invisible to the
    // user-facing JMAP projection, so the snapshot passes through untouched.
    const commit = buildVaultCommit({
      identityId: this.options.identityId,
      objects: [record.object],
      events: [record.event],
      snapshot: await this.options.currentSnapshot(),
    })
    const result = await this.options.committer.commitLocalMutation({ identityId: this.options.identityId, ...commit })
    if (result === 'committed') await this.options.onCommitted?.(record.event)
    return { result, event: record.event }
  }
}
