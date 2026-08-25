// Identity bootstrap, end to end: this device's own MLS leaf key registered
// as a verificationMethod, self-group membership, roster reflection, and
// KeyPackage pool top-up — everything Vault Core's identity bootstrap needs
// before any vault content can be read or written (PLAN.md §4.1's
// roster/VEK boundary). Two entry points share that machinery
// (`registerDeviceAndJoinSelfGroup`, below): `createNewIdentity` for a
// brand-new identity (root key generated fresh, did:webvh genesis), and
// `restoreIdentity` for an ADDITIONAL device of an identity that already
// exists (root key re-derived from a recovery phrase, no genesis — the DID
// is instead read off the identity's own did.jsonl).
//
// Ported at the flow level from src.bak/ui/account-create.ts's submit
// handler (both its signup and its logInExistingAddress branches) and
// src.bak/did/index.ts's initDidWebvh/localDidRecord, trimmed to what this
// rewrite actually carries forward: no mail/AP relay provisioning, no
// DIDComm mediator registration, no PGP — all relay-adapter or
// DIDComm-adapter concerns this rewrite does not have yet (PLAN.md §6).
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { deriveRootKey } from './keys.ts'
import { mnemonicToSeed } from './seed.ts'
import { createGenesis } from './webvh/create-genesis.ts'
import { addDeviceVerificationMethod } from './webvh/add-device-verification-method.ts'
import { resolveByDomain } from './webvh/resolver.ts'
import { parseWebvhDid } from './webvh/identifier.ts'
import { decodeMultikey, encodeMultikey } from './webvh/multikey.ts'
import type { IdentityRecord, IdentityRecordStore } from './record-store.ts'
import { epochOf, exportSecret, generateOwnKeyPackage, ownSignaturePrivateKey, setMlsAuthService } from '../mls/group.ts'
import { webvhAuthenticationService } from '../mls/webvh-authentication-service.ts'
import { ensureSelfGroupWithRosterInstall, reflectPendingSelfGroupCommits, selfGroupIdHex, type SelfGroupSigner } from '../mls/self-group.ts'
import { ensureKeyPackagePool } from '../mls/key-package-pool.ts'
import { CoreMlsDeliveryTransport } from '../mls/core-mls-delivery-transport.ts'
import { CoreRosterInstallTransport } from '../mls/core-roster-install-transport.ts'
import { CoreVaultDeliveryTransport } from '../vault/core-delivery-transport.ts'
import { StoredSegmentKeyResolver, type SegmentKeyResolver } from '../vault/segment-key-resolver.ts'
import { ActiveVaultSegmentManager, type ActiveVaultSegment } from '../vault/active-segment.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter } from '../vault/store.ts'
import { deriveVaultEpochKey, MlsVaultEpochKeyResolver } from '../mls/vault-epoch.ts'
import { MlsMembershipSegmentKeyWrapSigner, MlsMembershipSegmentKeyWrapVerifier } from '../mls/segment-key-membership.ts'
import { StoredMlsSelfGroupProvider, type MlsSelfGroupStateStore } from '../mls/store.ts'
import type { MlsKeyPackageStore } from '../mls/keypackage-store.ts'
import { deviceKidFragment } from '../didcomm/devicekid.ts'
import { publishRoutingPointer } from '../didcomm/webvh-routing-pointer.ts'
import { buildRoutingDoc, putRouting } from '../didcomm/webvh-routing.ts'
import { createSegmentKeyWrap, segmentKeyWrapSigningBytes, unwrapSegmentKey } from '../vault/crypto.ts'
import type { RestoreTransferSource, RestoreTransferVerifier } from '../vault/restore-transfer.ts'
import { buildVaultManifest } from '../vault/manifest.ts'
import type { VaultObjectReader, VaultProjectionReader, VaultProjectionWriter, VaultRecordReader } from '../vault/store.ts'
import { VaultDeliveryProjector } from '../vault/delivery-projector.ts'
import { rebuildLocalJmapProjection } from '../vault/projection-rebuild.ts'
import { VaultObjectBlobReader } from '../vault/blob-reader.ts'
import type { LocalJmapProjectionV1, LocalJmapReadModel, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import { IndexedDbLocalJmapReadModel, type LocalVaultBlobReader } from '../local-jmap/indexeddb.ts'
import { equalBytes } from '../protocol/canonical.ts'
import { deliverySeq, mlsEpoch, type DeliverySeq, type VaultEventId } from '../protocol/ids.ts'
import { mailSubmissionSigningBytes, vaultDeliveryPullSigningBytes } from '../protocol/signing.ts'
import type { VaultDeliveryPullV1 } from '../protocol/vault.ts'
import type { MailSubmissionResultV1 } from '../protocol/mail-submission.ts'
import { CoreMailSubmissionTransport } from '../vault/mail-submission-transport.ts'
import type { VaultBackedLocalJmapMutationSink } from '../local-jmap/vault-mutation-sink.ts'
import type { VaultMutationIntent } from '../local-jmap/mutations.ts'
import type { ClientState } from '../mls/vendor/index.ts'

/**
 * Asks core's own bounded delivery store what its CURRENT `latestSeq` is,
 * for `deliveryFloorForNewDevice` — the seq a newly-trusted device should
 * start pulling from (PLAN.md §2.3: never a past one, or it would be
 * retroactively handed history it never should have received). `after: 0`
 * throws away whatever `items` comes back with; only `latestSeq` is wanted
 * here. Requires `deviceKid` to already be a trusted device for
 * `identityId` — an untrusted device's own pull is refused
 * (`rosterBackedVaultDeliveryAuthorizer`), which is why this is called from
 * `maintainSelfGroup` (an EXISTING member reflecting a new one), never from
 * `restoreIdentity`/`createNewIdentity` (where the calling device is not yet
 * trusted, or — for genesis — there is no vault content yet for `0` to be
 * wrong about).
 */
async function currentVaultDeliveryLatestSeq(
  coreBaseUrl: string,
  identityId: string,
  deviceKid: string,
  sign: SelfGroupSigner,
  fetchImpl: typeof fetch | undefined,
  now: () => Date,
): Promise<DeliverySeq> {
  const transport = new CoreVaultDeliveryTransport({ baseUrl: coreBaseUrl, fetch: fetchImpl })
  const pull: Omit<VaultDeliveryPullV1, 'signature'> = {
    version: 1, identityId, recipientDeviceId: deviceKid, after: deliverySeq(0n), requestedAt: now().toISOString(),
  }
  const result = await transport.pull({ ...pull, signature: await sign(vaultDeliveryPullSigningBytes(pull)) })
  return result.latestSeq
}

let authServiceInstalled = false
/** Idempotent: `setMlsAuthService` is one global (group.ts's own note on
 * why), so calling this more than once across a session's several
 * `createNewIdentity`/future-login calls must be harmless. */
function ensureMlsAuthServiceInstalled(): void {
  if (authServiceInstalled) return
  setMlsAuthService(webvhAuthenticationService)
  authServiceInstalled = true
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

function randomFragment(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8))
  return `device-${toHex(bytes)}`
}

export interface CreateNewIdentityOptions {
  /** This identity's own subdomain (`y.biset.md`) — used unchanged for both
   * did:webvh (identifier.ts's subdomain form) and the did:web mirror. */
  domain: string
  /** Where the self-group DS/roster narrow HTTP API lives (`core/app.ts`'s
   * deployment) — a separate concern from `domain`, which only names the
   * did:webvh/did:web genesis location. */
  coreBaseUrl: string
  /** Generated if omitted — the only reason to pass one in is a test. */
  masterSeed?: Uint8Array
  didWebMirror?: boolean
  fetch?: typeof fetch
  now?: () => Date
}

export interface CreatedIdentity {
  record: IdentityRecord
  masterSeed: Uint8Array
  selfGroupState: ClientState
}

interface RegisterDeviceOptions {
  coreBaseUrl: string
  didWebMirror?: boolean
  fetch?: typeof fetch
  now: () => Date
  deliveryFloorForNewDevice: () => Promise<DeliverySeq>
}

/**
 * The machinery `createNewIdentity` and `restoreIdentity` share once a DID
 * and its root key are in hand: mint this device's own MLS leaf key,
 * register it as a verificationMethod, join the self group (creating it if
 * this is the genesis device, external-joining otherwise —
 * `ensureSelfGroupWithRosterInstall` decides which), and top up the
 * KeyPackage pool.
 */
async function registerDeviceAndJoinSelfGroup(
  did: string,
  rootPrivateKey: Uint8Array,
  rootPublicKey: Uint8Array,
  selfGroupStore: MlsSelfGroupStateStore,
  keyStore: MlsKeyPackageStore,
  opts: RegisterDeviceOptions,
): Promise<{ deviceKid: string; selfGroupState: ClientState }> {
  ensureMlsAuthServiceInstalled()

  const fragment = randomFragment()
  const deviceKid = `${did}#${fragment}`
  const kp = await generateOwnKeyPackage(deviceKid)
  await addDeviceVerificationMethod({
    did, fragment, devicePublicKey: kp.publicPackage.leafNode.signaturePublicKey,
    signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey,
    didWebMirror: opts.didWebMirror, fetch: opts.fetch,
  })

  const sign: SelfGroupSigner = bytes => ed25519.sign(bytes, kp.privatePackage.signaturePrivateKey)
  const mlsTransport = new CoreMlsDeliveryTransport({ baseUrl: opts.coreBaseUrl, fetch: opts.fetch })
  const rosterTransport = new CoreRosterInstallTransport({ baseUrl: opts.coreBaseUrl, fetch: opts.fetch })

  const selfGroupState = await ensureSelfGroupWithRosterInstall(
    selfGroupStore, mlsTransport, rosterTransport, did, deviceKid, kp, sign, opts.deliveryFloorForNewDevice, opts.now,
  )
  if (!selfGroupState) throw new Error('registerDeviceAndJoinSelfGroup: self-group bootstrap did not produce a state')

  await ensureKeyPackagePool(mlsTransport, keyStore, did, deviceKid, sign, undefined, opts.now)

  return { deviceKid, selfGroupState }
}

/**
 * Creates a brand-new identity: did:webvh genesis, this device registered as
 * its first verificationMethod (also its first — and, for now, only — self
 * group member), and the identity persisted locally. Throws if the identity
 * anchor (genesis PUT) or the core self-group API is unreachable — same
 * fail-fast rule the pre-rewrite signup form used.
 *
 * `selfGroupStore`/`keyStore` are injected (rather than this module picking
 * `IndexedDbMlsSelfGroupStore`/`IndexedDbMlsKeyPackageStore` itself) so this
 * whole flow can run end to end against in-memory fakes outside a browser —
 * the real caller passes the IndexedDB-backed stores.
 */
export async function createNewIdentity(
  recordStore: IdentityRecordStore,
  selfGroupStore: MlsSelfGroupStateStore,
  keyStore: MlsKeyPackageStore,
  opts: CreateNewIdentityOptions,
): Promise<CreatedIdentity> {
  const now = opts.now ?? (() => new Date())

  const masterSeed = opts.masterSeed ?? crypto.getRandomValues(new Uint8Array(32))
  const root = deriveRootKey(masterSeed)
  const { did } = await createGenesis({
    domain: opts.domain, rootPrivateKey: root.privateKey, rootPublicKey: root.publicKey,
    didWebMirror: opts.didWebMirror, fetch: opts.fetch,
  })

  // The genesis device is the roster's own first (and, at this point, only)
  // trusted device — it starts pulling vault delivery from whatever the
  // CURRENT latestSeq is, which for a brand-new identity is the beginning.
  const { deviceKid, selfGroupState } = await registerDeviceAndJoinSelfGroup(did, root.privateKey, root.publicKey, selfGroupStore, keyStore, {
    coreBaseUrl: opts.coreBaseUrl, didWebMirror: opts.didWebMirror, fetch: opts.fetch, now,
    deliveryFloorForNewDevice: async () => deliverySeq(0n),
  })

  const record: IdentityRecord = {
    did, masterSeed: toHex(masterSeed), rootPublicKey: toHex(root.publicKey), rootPrivateKey: toHex(root.privateKey), deviceKid,
  }
  await recordStore.put(record)

  return { record, masterSeed, selfGroupState }
}

export interface MaintainSelfGroupOptions {
  coreBaseUrl: string
  /** This identity's own segment stores — needed only for the self-grant
   * sweep below (a device with no vault content yet may omit both and just
   * get the plain catch-up/KeyPackage-topup behavior). */
  wraps?: SegmentKeyWrapReader & SegmentKeyWrapWriter
  segments?: ActiveVaultSegmentStore
  fetch?: typeof fetch
  now?: () => Date
}

/**
 * Routine upkeep for an identity this device already belongs to — run once
 * at boot (`main.ts`'s `bootClient`) rather than at any particular user
 * action, since neither half needs one: `reflectPendingSelfGroupCommits`
 * catches this device up on other devices' self-group commits and reflects
 * the roster once it does (the "existing member notices and reflects" half
 * `installCurrentRosterProjection`'s own doc comment describes), and
 * `ensureKeyPackagePool` tops up whatever the DS has run down. A no-op
 * (returns undefined) when this device has no self-group state at all yet —
 * that is `registerDeviceAndJoinSelfGroup`'s job, not this one's.
 *
 * Reconstructs this device's own `SelfGroupSigner` straight from the stored
 * `ClientState` (`ownSignaturePrivateKey`) rather than requiring the
 * original `OwnKeyPackage` to still be in memory — the whole point of this
 * running at boot, long after whatever call created or restored the
 * identity has returned.
 *
 * When `reflectPendingSelfGroupCommits` actually advances this device's own
 * epoch, runs `selfGrantSegmentRewraps` before anything else touches the new
 * state: the just-superseded `ClientState` (`oldState`, still in memory
 * right here) is the ONLY place its exporter secret will ever exist again
 * (MLS forward secrecy, RFC 9420 §8.5) — there is no "catch up later" for
 * this step, unlike the roster/KeyPackage upkeep around it.
 */
export async function maintainSelfGroup(
  selfGroupStore: MlsSelfGroupStateStore,
  keyStore: MlsKeyPackageStore,
  record: IdentityRecord,
  opts: MaintainSelfGroupOptions,
): Promise<ClientState | undefined> {
  if (!record.deviceKid) return undefined
  const stored = await selfGroupStore.load(record.did)
  if (!stored) return undefined

  const now = opts.now ?? (() => new Date())
  const oldState = stored.state
  const sign: SelfGroupSigner = bytes => ed25519.sign(bytes, ownSignaturePrivateKey(oldState))
  const mlsTransport = new CoreMlsDeliveryTransport({ baseUrl: opts.coreBaseUrl, fetch: opts.fetch })
  const rosterTransport = new CoreRosterInstallTransport({ baseUrl: opts.coreBaseUrl, fetch: opts.fetch })

  const deliveryFloorForNewDevice = () => currentVaultDeliveryLatestSeq(opts.coreBaseUrl, record.did, record.deviceKid!, sign, opts.fetch, now)
  const state = await reflectPendingSelfGroupCommits(
    selfGroupStore, mlsTransport, rosterTransport, record.did, record.deviceKid, sign, deliveryFloorForNewDevice, now,
  )

  if (state && opts.wraps && opts.segments && epochOf(state) !== epochOf(oldState)) {
    await selfGrantSegmentRewraps(opts.segments, opts.wraps, record.did, stored.selfGroupId, record.deviceKid, oldState, state, now)
  }

  await ensureKeyPackagePool(mlsTransport, keyStore, record.did, record.deviceKid, sign, undefined, now)

  return state
}

/**
 * PLAN.md §4.2's self-grant: re-wrap every one of this identity's OWN
 * segments still on `oldState`'s epoch for `newState`'s epoch, the moment
 * `maintainSelfGroup` sees the two differ. A segment with no wrap for
 * `oldEpoch` (e.g. one only ever wrapped for an even earlier epoch that a
 * prior boot's self-grant sweep never reached) is left alone rather than
 * guessed at — the same "unreadable until something re-wraps it" state
 * `store.ts`'s own `VaultSegmentRecord.epoch` doc comment describes, just
 * not solved by this particular pass.
 */
async function selfGrantSegmentRewraps(
  segments: ActiveVaultSegmentStore,
  wraps: SegmentKeyWrapReader & SegmentKeyWrapWriter,
  identityId: IdentityRecord['did'],
  selfGroupId: string,
  deviceKid: string,
  oldState: ClientState,
  newState: ClientState,
  now: () => Date,
): Promise<void> {
  const oldEpoch = mlsEpoch(epochOf(oldState))
  const newEpoch = mlsEpoch(epochOf(newState))
  const pending = (await segments.allSegments(identityId)).filter(segment => segment.epoch === oldEpoch)
  if (pending.length === 0) return

  const oldVerifier = new MlsMembershipSegmentKeyWrapVerifier(async () => oldState)
  const newSigner = new MlsMembershipSegmentKeyWrapSigner(deviceKid, async () => newState)
  const grantedAt = now().toISOString()

  for (const segment of pending) {
    const wrap = await wraps.readSegmentKeyWrap(identityId, segment.segmentId, oldEpoch)
    if (!wrap) continue
    const oldVek = await deriveVaultEpochKey({ selfGroupId, epoch: oldEpoch, exportSecret: (label, context, length) => exportSecret(oldState, label, context, length) })
    try {
      const segmentKey = await unwrapSegmentKey(oldVek, wrap, oldVerifier)
      try {
        const newVek = await deriveVaultEpochKey({ selfGroupId, epoch: newEpoch, exportSecret: (label, context, length) => exportSecret(newState, label, context, length) })
        try {
          const rewrapped = await createSegmentKeyWrap(newVek, segmentKey, {
            identityId,
            selfGroupId,
            segmentId: segment.segmentId,
            sourceEpoch: oldEpoch,
            recipientEpoch: newEpoch,
            grantorDeviceId: deviceKid,
            grantedAt,
          }, newSigner)
          await wraps.writeSegmentKeyWrap(rewrapped)
          await segments.recordSegmentRewrapped(identityId, segment.segmentId, newEpoch)
        } finally {
          newVek.fill(0)
        }
      } finally {
        segmentKey.fill(0)
      }
    } finally {
      oldVek.fill(0)
    }
  }
}

export interface RestoreIdentityOptions {
  /** The identity's own subdomain — same value `createNewIdentity` was
   * originally called with for it. */
  domain: string
  coreBaseUrl: string
  /** The 24-word BIP39 recovery phrase (identity/seed.ts). */
  mnemonic: string
  /**
   * The vault-delivery seq THIS DEVICE should start pulling from — must be
   * the CURRENT `latestSeq`, never a past one (PLAN.md §2.3: a new device is
   * never retroactively added as a pending recipient of history it never
   * should have received). Vault delivery's own pull API is not wired up to
   * this module yet, so the caller must supply it; there is no safe default
   * here the way genesis's `0` is, since an existing identity may already
   * have real vault content.
   */
  deliveryFloorForNewDevice: () => Promise<DeliverySeq>
  didWebMirror?: boolean
  fetch?: typeof fetch
  now?: () => Date
}

/**
 * Adds THIS DEVICE to an identity that already exists, from its recovery
 * phrase — the `logInExistingAddress` half of the pre-rewrite signup form,
 * minus the DNS-anchor lookup (this rewrite has no restore/login UI to feed
 * it a DID yet) and minus mail/AP/PGP. The DID itself is read off the
 * identity's own did.jsonl (`resolveByDomain`), not derived from the
 * phrase — a did:webvh's SCID depends on genesis TIME, not just the root
 * key, so the DID cannot be recomputed offline (`create-genesis.ts`'s own
 * note). The resolved document's root key (`verificationMethod[0]` —
 * `add-device-verification-method.ts` only ever appends, so this stays the
 * one this identity's genesis minted) is checked against the phrase's own
 * derived key before anything else happens: a wrong phrase, or someone
 * else's identity, must never register a device or touch the self group.
 */
export async function restoreIdentity(
  recordStore: IdentityRecordStore,
  selfGroupStore: MlsSelfGroupStateStore,
  keyStore: MlsKeyPackageStore,
  opts: RestoreIdentityOptions,
): Promise<CreatedIdentity> {
  const now = opts.now ?? (() => new Date())

  const masterSeed = mnemonicToSeed(opts.mnemonic)
  const root = deriveRootKey(masterSeed)

  const doc = await resolveByDomain(opts.domain)
  if (!doc) throw new Error('restoreIdentity: no identity found at this domain')
  const rootVm = doc.verificationMethod[0]
  if (!rootVm) throw new Error('restoreIdentity: resolved document has no verificationMethod')
  if (!equalBytes(decodeMultikey(rootVm.publicKeyMultibase), root.publicKey)) {
    throw new Error('restoreIdentity: this recovery phrase does not control the identity at this domain')
  }
  const did = doc.id

  const { deviceKid, selfGroupState } = await registerDeviceAndJoinSelfGroup(did, root.privateKey, root.publicKey, selfGroupStore, keyStore, {
    coreBaseUrl: opts.coreBaseUrl, didWebMirror: opts.didWebMirror, fetch: opts.fetch, now,
    deliveryFloorForNewDevice: opts.deliveryFloorForNewDevice,
  })

  const record: IdentityRecord = {
    did, masterSeed: toHex(masterSeed), rootPublicKey: toHex(root.publicKey), rootPrivateKey: toHex(root.privateKey), deviceKid,
  }
  await recordStore.put(record)

  return { record, masterSeed, selfGroupState }
}

export interface VaultCryptoBoundary {
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
 * Wires PLAN.md §4.2's "actual MLS VEK derivation / membership signer" —
 * the one piece `vault/segment-key-resolver.ts`, `vault/crypto.ts`, and
 * `vault/active-segment.ts` were built to receive but never got — to this
 * identity's actual self-group state. Local JMAP Gateway / vault mutation
 * code calls this once it has `record`/`selfGroupStore` in hand (the same
 * two `maintainSelfGroup` already needs) to get a `SegmentKeyResolver` for
 * decrypting vault objects, a signer for wrapping new ones, and an
 * `activeSegment()` for `VaultBackedLocalJmapMutationSink`.
 *
 * Reads the self-group `ClientState` fresh on every resolve/sign/verify
 * call (via `selfGroupStore.load`) rather than once at construction — MLS
 * state is immutable and wholesale-replaced on every commit, so a boundary
 * built once at boot must keep tracking the CURRENT epoch and CURRENT
 * membership, not the snapshot that existed when this was called.
 */
export function buildVaultCryptoBoundary(
  wraps: SegmentKeyWrapReader & SegmentKeyWrapWriter,
  segments: ActiveVaultSegmentStore,
  selfGroupStore: MlsSelfGroupStateStore,
  record: IdentityRecord,
): VaultCryptoBoundary {
  if (!record.deviceKid) throw new Error('buildVaultCryptoBoundary: identity has no deviceKid yet')
  const deviceKid = record.deviceKid
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(record.did)
    if (!stored) throw new Error('buildVaultCryptoBoundary: no self-group state for this identity')
    return stored.state
  }

  const epochs = new MlsVaultEpochKeyResolver(new StoredMlsSelfGroupProvider(selfGroupStore))
  const signer = new MlsMembershipSegmentKeyWrapSigner(deviceKid, loadState)
  const resolver = new StoredSegmentKeyResolver(wraps, epochs, signer)
  const segmentManager = new ActiveVaultSegmentManager({ identityId: record.did, segments, wraps, epochs, signer })

  return { resolver, signer, activeSegment: () => segmentManager.activeSegment() }
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
export function buildRestoreTransferVerifier(selfGroupStore: MlsSelfGroupStateStore, identityId: string): RestoreTransferVerifier {
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(identityId)
    if (!stored) throw new Error('buildRestoreTransferVerifier: no self-group state for this identity')
    return stored.state
  }
  const verifier = new MlsMembershipSegmentKeyWrapVerifier(loadState)
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
  record: IdentityRecord,
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

/**
 * PLAN.md §6.2's outbound send: given an already-locally-committed "outbox"
 * email's raw blob and recipients, signs and submits it for delivery through
 * the authenticated device -> core narrow API (CoreMailSubmissionTransport),
 * then records the outcome as an ordinary local vault commit through
 * VaultBackedLocalJmapMutationSink.commitIntents -- a `transport.result`
 * event always, plus a `mailbox.set` moving the email out of "outbox" only
 * when delivery actually succeeded. A temporary-failure leaves it in outbox
 * for a later retry; there is no scheduler here yet, matching the inbound
 * side's own deferred DSN handling.
 *
 * `mailFrom` is derived, not stored: an identity's DID domain IS its own
 * subdomain (identity/webvh/identifier.ts's subdomain-per-identity
 * convention -- the same one mail-recipient-resolver.ts uses server-side to
 * go the other direction), so `{username}@mail.{apexDomain}` falls out of
 * the identity's own DID with no new field needed on IdentityRecord.
 */
export function buildMailSubmitter(
  vault: VaultObjectReader & SegmentKeyWrapReader,
  selfGroupStore: MlsSelfGroupStateStore,
  record: IdentityRecord,
  mutationSink: VaultBackedLocalJmapMutationSink,
  apexDomain: string,
  coreBaseUrl: string,
): {
  submit(emailId: string, blobId: string, rcptTo: string[], snapshot: LocalJmapSnapshot): Promise<MailSubmissionResultV1>
  submitMail(arguments_: Record<string, unknown>, snapshot: LocalJmapSnapshot): Promise<Record<string, unknown>>
} {
  if (!record.deviceKid) throw new Error('buildMailSubmitter: identity has no deviceKid yet')
  const deviceKid = record.deviceKid
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(record.did)
    if (!stored) throw new Error('buildMailSubmitter: no self-group state for this identity')
    return stored.state
  }
  const signer = new MlsMembershipSegmentKeyWrapSigner(deviceKid, loadState)
  const blobs = buildVaultBlobReader(vault, vault, selfGroupStore, record.did)
  const transport = new CoreMailSubmissionTransport({ baseUrl: coreBaseUrl })
  const mailFrom = mailFromForIdentity(record.did, apexDomain)

  return {
    async submit(emailId, blobId, rcptTo, snapshot) {
      const rawRfc5322 = await blobs.download(record.did, blobId)
      const unsigned = { version: 1 as const, identityId: record.did, deviceId: deviceKid, mailFrom, rcptTo, rawRfc5322, submittedAt: new Date().toISOString() }
      const signature = await signer.sign(mailSubmissionSigningBytes(unsigned))
      const result = await transport.submit({ ...unsigned, signature })

      const intents: VaultMutationIntent[] = [{
        kind: 'transport.result',
        targetIds: [emailId],
        payload: { emailId, status: result.status, occurredAt: result.occurredAt, ...(result.detail === undefined ? {} : { detail: result.detail }) },
      }]
      if (result.status === 'accepted') {
        intents.push({ kind: 'mailbox.set', targetIds: [emailId], payload: { emailId, mailboxIds: { sent: true } } })
      }
      await mutationSink.commitIntents(intents, snapshot)
      return result
    },

    /**
     * PLAN.md §6.2's minimal EmailSubmission/set: `{create: {creationId:
     * {emailId}}}`, a single submission, no update/destroy, no
     * onSuccessUpdateEmail hooks. Blocks until delivery completes and
     * returns synchronously (the same "narrow API, do the real work now"
     * shape this codebase already uses elsewhere) rather than adding an
     * async EmailSubmission/get polling model.
     */
    async submitMail(arguments_, snapshot) {
      const create = arguments_.create
      if (create === null || typeof create !== 'object' || Array.isArray(create)) throw new TypeError('EmailSubmission/set requires create')
      const entries = Object.entries(create as Record<string, unknown>)
      if (entries.length !== 1) throw new TypeError('EmailSubmission/set supports exactly one creation per call')
      const [creationId, spec] = entries[0]!
      if (spec === null || typeof spec !== 'object' || Array.isArray(spec)) throw new TypeError('EmailSubmission/set creation must be an object')
      const emailId = (spec as Record<string, unknown>).emailId
      if (typeof emailId !== 'string' || !emailId) throw new TypeError('EmailSubmission/set creation requires emailId')
      const email = snapshot.emails.find(candidate => candidate.id === emailId)
      if (!email) return { notCreated: { [creationId]: { type: 'invalidProperties', description: 'no such email' } } }
      if (email.mailboxIds.outbox !== true) return { notCreated: { [creationId]: { type: 'invalidProperties', description: 'email is not in the outbox' } } }
      if (!email.blobId) return { notCreated: { [creationId]: { type: 'invalidProperties', description: 'email has no content' } } }
      const rcptTo = (email.to ?? []).map(address => address.email).filter((value): value is string => !!value)
      if (rcptTo.length === 0) return { notCreated: { [creationId]: { type: 'invalidProperties', description: 'email has no recipients' } } }
      const result = await this.submit(emailId, email.blobId, rcptTo, snapshot)
      return { created: { [creationId]: { id: `${emailId}-submission`, emailId, sendAt: result.occurredAt, undoStatus: result.status === 'accepted' ? 'final' : 'pending' } } }
    },
  }
}

export function mailFromForIdentity(identityId: string, apexDomain: string): string {
  const { domain } = parseWebvhDid(identityId)
  const suffix = `.${apexDomain}`
  if (!domain.endsWith(suffix)) throw new Error(`buildMailSubmitter: identity domain ${domain} is not a subdomain of ${apexDomain}`)
  const username = domain.slice(0, domain.length - suffix.length)
  if (!username) throw new Error('buildMailSubmitter: identity domain has no username segment')
  return `${username}@mail.${apexDomain}`
}

export interface EnableDidCommOptions {
  /** Where the DIDComm ingress endpoint lives (`core/adapters/didcomm-http.ts`'s
   * deployment) -- POST /v1/didcomm/ingress under this origin becomes the
   * routing.json service descriptor's serviceEndpoint. */
  coreBaseUrl: string
  fetch?: typeof fetch
}

/**
 * Opt-in DIDComm provisioning (PLAN.md §6.1's last checkbox) -- deliberately
 * NOT part of createNewIdentity/restoreIdentity: this rewrite's DIDComm
 * scope (external ingress/OOB/bootstrap/control plus 1:1 chat, confirmed
 * with the user) is not something every identity needs by default, unlike
 * the MLS self-group registration every device requires just to have a
 * vault at all.
 *
 * Generates a fresh X25519 keypair, derives its kid the same way
 * didcomm/devicekid.ts always does (deviceKidFragment -- deliberately NOT
 * `record.deviceKid`, which names a different key: the MLS leaf credential,
 * not this one), publishes the signed `#routing` log pointer once
 * (webvh-routing-pointer.ts) and this device's keyAgreement entry +
 * DIDCommMessaging service descriptor in routing.json (webvh-routing.ts),
 * then persists the new key on the identity record. Idempotent: a record
 * that already has `didCommKid` is returned unchanged, nothing republished.
 */
export async function enableDidComm(recordStore: IdentityRecordStore, record: IdentityRecord, opts: EnableDidCommOptions): Promise<IdentityRecord> {
  if (record.didCommKid) return record
  const x25519PrivateKey = x25519.utils.randomSecretKey()
  const x25519PublicKey = x25519.getPublicKey(x25519PrivateKey)
  const didCommKid = `${record.did}${deviceKidFragment(x25519PublicKey)}`
  const rootPrivateKey = fromHex(record.rootPrivateKey)
  const rootPublicKey = fromHex(record.rootPublicKey)

  await publishRoutingPointer({ did: record.did, signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey, fetch: opts.fetch })
  const doc = buildRoutingDoc(record.did, {
    didCommEndpoint: `${opts.coreBaseUrl.replace(/\/$/, '')}/v1/didcomm/ingress`,
    keyAgreementKeys: [{ kid: didCommKid, publicKey: x25519PublicKey }],
  })
  await putRouting(record.did, doc, { updateKey: encodeMultikey(rootPublicKey), privateKey: rootPrivateKey }, opts.fetch ?? fetch)

  const updated: IdentityRecord = { ...record, didCommKid, didCommX25519PrivateKey: toHex(x25519PrivateKey) }
  await recordStore.put(updated)
  return updated
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
