// One generic implementation of the vault's private-credential read and
// write paths. The four credential families (contact-key,
// didcomm-credential, didcomm-device-key, openpgp-credential) differ only in
// their event kind, their record codec, and the noun used in error
// messages -- everything else (signature verification, segment key
// resolution and zeroing, the atomic local-commit plus shared-delivery
// outbox entry) was previously hand-copied four times, so a fix applied to
// one copy silently left the other three wrong.
import type { LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import type { LocalVaultMutationCommitter } from '../local-jmap/vault-mutation-sink.ts'
import type { DeviceId, IdentityId, SegmentId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventKind, VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from './active-segment.ts'
import { buildVaultCommit } from './commit.ts'
import { verifyVaultEvent, type VaultEventSigner, type VaultEventVerifier } from './events.ts'
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
 *
 * `E` is the store interface the family's events come from: three families
 * use the narrow local credential index (`VaultCredentialEventReader`),
 * while didcomm-device-key reads the full event log (`VaultRecordReader`).
 */
export interface VaultCredentialKind<T, E> {
  eventKind: VaultEventKind
  /** Error-message noun, e.g. `contact key` in `contact key sink identity is required`. */
  label: string
  /** `assertActiveVaultSegment` purpose string; deliberately separate from `label`. */
  segmentLabel: string
  readEvents(source: E, identityId: IdentityId): Promise<VaultEventRecord[]>
  assert(event: VaultEventV1, object: VaultObjectV1, plaintext: Uint8Array): T
  build(value: T, context: VaultCredentialBuildContext, signer: VaultEventSigner): Promise<VaultCredentialBuildResult>
  createdAtOf(value: T): string
  /** Deep copy, including the family's own secret byte fields. */
  copy(value: T): T
}

export interface VaultCredentialReaderOptions<E> {
  identityId: IdentityId
  objects: VaultObjectReader
  events: E
  segmentKeys: SegmentKeyResolver
  verifier: VaultEventVerifier
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
        if (!(await verifyVaultEvent(event, this.options.verifier))) throw new TypeError(`${this.kind.label} event signature is invalid`)
        if (event.objectRefs.length !== 1) throw new TypeError(`${this.kind.label} event must reference exactly one object`)
        const object = await this.options.objects.readObject(this.options.identityId, event.objectRefs[0])
        if (!object) throw new Error(`${this.kind.label} object is unavailable; restore is required`)
        let segmentKey = keys.get(object.segmentId)
        if (!segmentKey) {
          segmentKey = await this.options.segmentKeys.resolveSegmentKey(this.options.identityId, object.segmentId)
          keys.set(object.segmentId, segmentKey)
        }
        values.push(this.kind.assert(event, object, await decryptVaultObject(segmentKey, object)))
      }
      return values
    } finally {
      for (const key of keys.values()) key.fill(0)
    }
  }
}

export interface SelectUnsupersededSpec<T> {
  kidOf(value: T): string
  supersededKidOf(value: T): string | undefined
  duplicateMessage: string
  ambiguousMessage: string
}

/**
 * Selects the unique unsuperseded generation. If two generations are
 * independently introduced (e.g. two devices raced to mint one before either
 * had synced the other's), fail closed and require an explicit rotation
 * decision instead of silently picking one by local clock order.
 */
export function selectUnsuperseded<T>(values: readonly T[], spec: SelectUnsupersededSpec<T>): T {
  const byKid = new Map<string, T>()
  const superseded = new Set<string>()
  for (const value of values) {
    const kid = spec.kidOf(value)
    if (byKid.has(kid)) throw new TypeError(spec.duplicateMessage)
    byKid.set(kid, value)
    const supersedes = spec.supersededKidOf(value)
    if (supersedes) superseded.add(supersedes)
  }
  const current = values.filter(value => !superseded.has(spec.kidOf(value)))
  if (current.length !== 1) throw new Error(spec.ambiguousMessage)
  return current[0]!
}

export interface VaultCredentialSinkOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  nextActorSeq(): Promise<number>
  initialParents(): Promise<VaultEventId[]>
  activeSegment(): Promise<ActiveVaultSegment>
  currentSnapshot(): Promise<LocalJmapSnapshot>
  signer: VaultEventSigner
  committer: LocalVaultMutationCommitter
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
      keyWraps: segment.keyWraps,
      createdAt: this.kind.createdAtOf(value),
      snapshot: await this.options.currentSnapshot(),
    })
    const result = await this.options.committer.commitLocalMutation({ identityId: this.options.identityId, ...commit })
    return { result, event: record.event }
  }
}
