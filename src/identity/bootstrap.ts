// Identity bootstrap, end to end: this device's Root-signed MLS credential,
// self-group membership, roster reflection, and
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
import { resolveByDomain } from './webvh/resolver.ts'
import { mailFromForIdentity } from './webvh/identifier.ts'
import { decodeMultikey, encodeMultikey } from './webvh/multikey.ts'
import { multikeyHashBase58 } from './webvh/hash.ts'
import { fetchCurrentLog } from './webvh/log-io.ts'
import type { IdentityRecord, IdentityRecordStore } from './record-store.ts'
import { epochOf, exportSecret, generateOwnKeyPackage, ownMlsDeviceCredential, ownSignaturePrivateKey, setMlsAuthService } from '../mls/group.ts'
import { createMlsDeviceCredential, encodeMlsDeviceCredential } from '../mls/device-credential.ts'
import { webvhAuthenticationService } from '../mls/webvh-authentication-service.ts'
import { ensureSelfGroupWithRosterInstall, installCurrentRosterProjection, reflectPendingSelfGroupCommits, selfGroupIdHex, type SelfGroupSigner } from '../mls/self-group.ts'
import { ensureKeyPackagePool } from '../mls/key-package-pool.ts'
import { CoordinatorMlsDeliveryTransport } from '../mls/coordinator-mls-delivery-transport.ts'
import { CoreRosterInstallTransport } from '../mls/core-roster-install-transport.ts'
import { CoreVaultDeliveryTransport } from '../vault/core-delivery-transport.ts'
import { StoredSegmentKeyResolver, type SegmentKeyResolver, type VaultEpochKeyResolver } from '../vault/segment-key-resolver.ts'
import { ActiveVaultSegmentManager, type ActiveVaultSegment } from '../vault/active-segment.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter } from '../vault/store.ts'
import { deriveVaultEpochKey, MlsVaultEpochKeyResolver } from '../mls/vault-epoch.ts'
import { MlsMembershipSegmentKeyWrapSigner, MlsMembershipSegmentKeyWrapVerifier } from '../mls/segment-key-membership.ts'
import { StoredMlsSelfGroupProvider, type MlsSelfGroupStateStore } from '../mls/store.ts'
import type { MlsKeyPackageStore } from '../mls/keypackage-store.ts'
import { deviceKidFragment } from '../didcomm/devicekid.ts'
import { publishRoutingPointer } from '../didcomm/webvh-routing-pointer.ts'
import { buildRoutingDoc, fetchRouting, putRouting, type RoutingDoc, type MediatorRegistration } from '../didcomm/webvh-routing.ts'
import { registerWithMediator } from '../didcomm/mediator-sync.ts'
import { DidCommCredentialReader } from '../vault/didcomm-credential-reader.ts'
import { DidCommCredentialVaultSink } from '../vault/didcomm-credential-sink.ts'
import type { DidCommPrivateCredentialV1 } from '../vault/didcomm-credential.ts'
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
import type { MailSubmissionRequestV1, MailSubmissionResultV1 } from '../protocol/mail-submission.ts'
import { CoreMailSubmissionTransport } from '../vault/mail-submission-transport.ts'
import type { VaultBackedLocalJmapMutationSink } from '../local-jmap/vault-mutation-sink.ts'
import type { VaultMutationIntent } from '../local-jmap/mutations.ts'
import type { ClientState } from '../mls/vendor/index.ts'
import { deriveVaultStorageKek, VAULT_STORAGE_EPOCH, VAULT_STORAGE_GROUP_ID } from '../vault/storage-root.ts'

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

export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

export interface CreateNewIdentityOptions {
  /** This identity's own subdomain (`y.biset.md`) — used unchanged for both
   * did:webvh (identifier.ts's subdomain form) and the did:web mirror. */
  domain: string
  /** Where the self-group DS/roster narrow HTTP API lives (`core/app.ts`'s
   * deployment) — a separate concern from `domain`, which only names the
   * did:webvh/did:web genesis location. */
  coreBaseUrl: string
  /** Coordinator-hosted RFC 9750 Delivery Service. */
  mlsDeliveryBaseUrl: string
  /** Generated if omitted — the only reason to pass one in is a test. */
  masterSeed?: Uint8Array
  /** Independent first Spare Key seed; generated when omitted. */
  spareSeed?: Uint8Array
  didWebMirror?: boolean
  fetch?: typeof fetch
  now?: () => Date
}

export interface CreatedIdentity {
  record: IdentityRecord
  masterSeed: Uint8Array
  /** Creation-only; never persisted in IdentityRecord. */
  spareSeed?: Uint8Array
  selfGroupState: ClientState
}

interface RegisterDeviceOptions {
  coreBaseUrl: string
  mlsDeliveryBaseUrl: string
  didWebMirror?: boolean
  fetch?: typeof fetch
  now: () => Date
  deliveryFloorForNewDevice: () => Promise<DeliverySeq>
}

/**
 * The machinery `createNewIdentity` and `restoreIdentity` share once a DID
 * and its Root Key are in hand: mint this device's MLS leaf key and
 * Root-signed credential, join the self group (creating it if
 * this is the genesis device, external-joining otherwise —
 * `ensureSelfGroupWithRosterInstall` decides which), and top up the
 * KeyPackage pool.
 */
async function registerDeviceAndJoinSelfGroup(
  did: string,
  rootPrivateKey: Uint8Array,
  signPrivateKey: Uint8Array,
  generation: string,
  selfGroupStore: MlsSelfGroupStateStore,
  keyStore: MlsKeyPackageStore,
  opts: RegisterDeviceOptions,
): Promise<{ deviceKid: string; selfGroupState: ClientState }> {
  ensureMlsAuthServiceInstalled()

  const deviceSignaturePrivateKey = ed25519.utils.randomSecretKey()
  const deviceCredential = createMlsDeviceCredential(did, generation, ed25519.getPublicKey(deviceSignaturePrivateKey), rootPrivateKey, signPrivateKey)
  const deviceKid = deviceCredential.deviceKid
  const kp = await generateOwnKeyPackage(deviceCredential, deviceSignaturePrivateKey)

  const sign: SelfGroupSigner = bytes => ed25519.sign(bytes, kp.privatePackage.signaturePrivateKey)
  const mlsTransport = new CoordinatorMlsDeliveryTransport({ baseUrl: opts.mlsDeliveryBaseUrl, deviceCredential: encodeMlsDeviceCredential(deviceCredential), fetch: opts.fetch })
  const rosterTransport = new CoreRosterInstallTransport({ baseUrl: opts.coreBaseUrl, fetch: opts.fetch })

  const selfGroupState = await ensureSelfGroupWithRosterInstall(
    selfGroupStore, mlsTransport, rosterTransport, did, deviceKid, kp, sign, opts.deliveryFloorForNewDevice, opts.now,
  )
  if (!selfGroupState) throw new Error('registerDeviceAndJoinSelfGroup: self-group bootstrap did not produce a state')

  await ensureKeyPackagePool(mlsTransport, keyStore, did, deviceKid, deviceCredential, deviceSignaturePrivateKey, sign, undefined, opts.now)

  return { deviceKid, selfGroupState }
}

/**
 * Creates a brand-new identity: did:webvh genesis, this device authorized by
 * a Root-signed credential as the first self-group member, and the identity
 * persisted locally. Throws if the identity
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
  const spareSeed = opts.spareSeed ?? crypto.getRandomValues(new Uint8Array(32))
  const nextKeyHash = multikeyHashBase58(encodeMultikey(ed25519.getPublicKey(spareSeed)))
  const { did, versionId } = await createGenesis({
    domain: opts.domain, rootPrivateKey: root.privateKey, rootPublicKey: root.publicKey,
    nextKeyHash,
    didWebMirror: opts.didWebMirror, fetch: opts.fetch,
  })

  // The genesis device is the roster's own first (and, at this point, only)
  // trusted device — it starts pulling vault delivery from whatever the
  // CURRENT latestSeq is, which for a brand-new identity is the beginning.
  const { deviceKid, selfGroupState } = await registerDeviceAndJoinSelfGroup(did, root.privateKey, root.privateKey, versionId, selfGroupStore, keyStore, {
    coreBaseUrl: opts.coreBaseUrl, mlsDeliveryBaseUrl: opts.mlsDeliveryBaseUrl, didWebMirror: opts.didWebMirror, fetch: opts.fetch, now,
    deliveryFloorForNewDevice: async () => deliverySeq(0n),
  })

  const record: IdentityRecord = {
    did, masterSeed: toHex(masterSeed), rootPublicKey: toHex(root.publicKey), rootPrivateKey: toHex(root.privateKey),
    signPublicKey: toHex(root.publicKey), signPrivateKey: toHex(root.privateKey), generation: versionId, deviceKid,
  }
  await recordStore.put(record)

  return { record, masterSeed, spareSeed, selfGroupState }
}

export interface MaintainSelfGroupOptions {
  coreBaseUrl: string
  mlsDeliveryBaseUrl: string
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
  const deviceCredential = ownMlsDeviceCredential(oldState)
  const mlsTransport = new CoordinatorMlsDeliveryTransport({ baseUrl: opts.mlsDeliveryBaseUrl, deviceCredential: encodeMlsDeviceCredential(deviceCredential), fetch: opts.fetch })
  const rosterTransport = new CoreRosterInstallTransport({ baseUrl: opts.coreBaseUrl, fetch: opts.fetch })

  const deliveryFloorForNewDevice = () => currentVaultDeliveryLatestSeq(opts.coreBaseUrl, record.did, record.deviceKid!, sign, opts.fetch, now)
  const state = await reflectPendingSelfGroupCommits(
    selfGroupStore, mlsTransport, rosterTransport, record.did, record.deviceKid, sign, deliveryFloorForNewDevice, now,
  )

  // A transient or version-skew failure during genesis can leave the local
  // self group durable while core has no roster at all. There is then no MLS
  // epoch transition for the normal reflection path to notice on the next
  // boot. Repair that exact missing-genesis case idempotently. A zero floor is
  // correct here: without an installed roster core could not have accepted
  // any vault delivery for this identity yet.
  if (!(await rosterTransport.fetchProjection(record.did))) {
    await installCurrentRosterProjection(
      rosterTransport, record.did, record.deviceKid, state ?? oldState, sign,
      async () => deliverySeq(0n), now,
    )
  }

  if (state && opts.wraps && opts.segments && epochOf(state) !== epochOf(oldState)) {
    await selfGrantSegmentRewraps(opts.segments, opts.wraps, record.did, stored.selfGroupId, record.deviceKid, oldState, state, now)
  }

  await ensureKeyPackagePool(mlsTransport, keyStore, record.did, record.deviceKid, deviceCredential, ownSignaturePrivateKey(state ?? oldState), sign, undefined, now)

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
  const pending = (await segments.allSegments(identityId)).filter(segment => segment.selfGroupId !== VAULT_STORAGE_GROUP_ID && segment.epoch === oldEpoch)
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
export async function repairCurrentLocalSegmentKeyWraps(
  selfGroupStore: MlsSelfGroupStateStore,
  segments: ActiveVaultSegmentStore,
  wraps: SegmentKeyWrapReader & SegmentKeyWrapWriter,
  record: IdentityRecord,
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

export interface RestoreIdentityOptions {
  /** The identity's own subdomain — same value `createNewIdentity` was
   * originally called with for it. */
  domain: string
  coreBaseUrl: string
  mlsDeliveryBaseUrl: string
  /** The 24-word BIP39 recovery phrase (identity/seed.ts). */
  mnemonic: string
  /** Current Sign phrase. Initially this is the same phrase as Root. */
  signMnemonic: string
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

  const { last } = await fetchCurrentLog(did, opts.fetch)
  const updateKeys = last.parameters.updateKeys ?? []
  if (updateKeys.length !== 1 || (last.parameters.nextKeyHashes?.length ?? 0) !== 1) {
    throw new Error('restoreIdentity: identity does not satisfy permanent pre-rotation invariants')
  }
  const normalizedRoot = opts.mnemonic.trim().toLowerCase().replace(/\s+/g, ' ')
  const normalizedSign = opts.signMnemonic.trim().toLowerCase().replace(/\s+/g, ' ')
  const signSeed = mnemonicToSeed(normalizedSign)
  const signPrivateKey = normalizedSign === normalizedRoot ? deriveRootKey(signSeed).privateKey : signSeed
  const signPublicKey = ed25519.getPublicKey(signPrivateKey)
  if (encodeMultikey(signPublicKey) !== updateKeys[0]) throw new Error('restoreIdentity: Sign Key phrase is not current for this identity')

  const { deviceKid, selfGroupState } = await registerDeviceAndJoinSelfGroup(did, root.privateKey, signPrivateKey, last.versionId, selfGroupStore, keyStore, {
    coreBaseUrl: opts.coreBaseUrl, mlsDeliveryBaseUrl: opts.mlsDeliveryBaseUrl, didWebMirror: opts.didWebMirror, fetch: opts.fetch, now,
    deliveryFloorForNewDevice: opts.deliveryFloorForNewDevice,
  })

  const record: IdentityRecord = {
    did, masterSeed: toHex(masterSeed), rootPublicKey: toHex(root.publicKey), rootPrivateKey: toHex(root.privateKey),
    signPublicKey: toHex(signPublicKey), signPrivateKey: toHex(signPrivateKey), generation: last.versionId, deviceKid,
  }
  await recordStore.put(record)

  return { record, masterSeed, selfGroupState }
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
  const storageKek = record.masterSeed ? deriveVaultStorageKek(fromHex(record.masterSeed)) : undefined
  const resolver = new StoredSegmentKeyResolver(wraps, epochs, signer, storageKek)
  const segmentManager = new ActiveVaultSegmentManager({ identityId: record.did, segments, wraps, epochs, signer, storageKek })

  return { epochs, resolver, signer, activeSegment: () => segmentManager.activeSegment() }
}

/** One-time, additive migration: wraps every locally known random SegmentKey
 * under the stable root-derived storage KEK. Ciphertexts are untouched. */
export async function migrateLocalSegmentKeysToStorageRoot(
  segments: ActiveVaultSegmentStore,
  wraps: SegmentKeyWrapReader & SegmentKeyWrapWriter,
  record: IdentityRecord,
  selfGroupStore: MlsSelfGroupStateStore,
): Promise<void> {
  if (!record.masterSeed || !record.deviceKid) return
  const stored = await selfGroupStore.load(record.did)
  if (!stored) throw new Error('Vault storage migration requires Self Group state')
  const signer = new MlsMembershipSegmentKeyWrapSigner(record.deviceKid, async () => stored.state)
  const kek = deriveVaultStorageKek(fromHex(record.masterSeed))
  try {
    for (const segment of await segments.allSegments(record.did)) {
      if (await wraps.readSegmentKeyWrap(record.did, segment.segmentId, VAULT_STORAGE_EPOCH)) continue
      const wrap = await createSegmentKeyWrap(kek, segment.segmentKey, { identityId: record.did, selfGroupId: VAULT_STORAGE_GROUP_ID, segmentId: segment.segmentId, sourceEpoch: VAULT_STORAGE_EPOCH, recipientEpoch: VAULT_STORAGE_EPOCH, grantorDeviceId: record.deviceKid, grantedAt: new Date().toISOString() }, signer)
      await wraps.writeSegmentKeyWrap(wrap)
      await segments.recordSegmentRewrapped(record.did, segment.segmentId, VAULT_STORAGE_EPOCH, VAULT_STORAGE_GROUP_ID)
    }
  } finally { kek.fill(0) }
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
  masterSeedHex?: string,
): VaultDeliveryProjector {
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(identityId)
    if (!stored) throw new Error('buildVaultDeliveryProjector: no self-group state for this identity')
    return stored.state
  }
  const epochs = new MlsVaultEpochKeyResolver(new StoredMlsSelfGroupProvider(selfGroupStore))
  const rootPublicKey = masterSeedHex ? deriveRootKey(fromHex(masterSeedHex)).publicKey : undefined
  const verifier = new MlsMembershipSegmentKeyWrapVerifier(loadState, rootPublicKey)
  return new VaultDeliveryProjector({ identityId, currentSnapshot, epochs, verifier, ...(masterSeedHex ? { storageKek: deriveVaultStorageKek(fromHex(masterSeedHex)) } : {}) })
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
  masterSeedHex?: string,
): () => Promise<LocalJmapProjectionV1> {
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(identityId)
    if (!stored) throw new Error('buildLocalJmapProjectionRebuild: no self-group state for this identity')
    return stored.state
  }
  const epochs = new MlsVaultEpochKeyResolver(new StoredMlsSelfGroupProvider(selfGroupStore))
  const rootPublicKey = masterSeedHex ? deriveRootKey(fromHex(masterSeedHex)).publicKey : undefined
  const verifier = new MlsMembershipSegmentKeyWrapVerifier(loadState, rootPublicKey)
  return async () => {
    const projection = await rebuildLocalJmapProjection({ identityId, records, wraps, epochs, verifier, ...(masterSeedHex ? { storageKek: deriveVaultStorageKek(fromHex(masterSeedHex)) } : {}) })
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
  masterSeedHex?: string,
): LocalVaultBlobReader {
  const loadState = async (): Promise<ClientState> => {
    const stored = await selfGroupStore.load(identityId)
    if (!stored) throw new Error('buildVaultBlobReader: no self-group state for this identity')
    return stored.state
  }
  const epochs = new MlsVaultEpochKeyResolver(new StoredMlsSelfGroupProvider(selfGroupStore))
  const verifier = new MlsMembershipSegmentKeyWrapVerifier(loadState)
  const resolver = new StoredSegmentKeyResolver(wraps, epochs, verifier, masterSeedHex ? deriveVaultStorageKek(fromHex(masterSeedHex)) : undefined)
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
  masterSeedHex?: string,
): LocalJmapReadModel {
  const blobs = buildVaultBlobReader(vault, vault, selfGroupStore, identityId, masterSeedHex)
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
export interface MailSubmissionTransport {
  submit(request: MailSubmissionRequestV1): Promise<MailSubmissionResultV1>
}

export function buildMailSubmitter(
  vault: VaultObjectReader & SegmentKeyWrapReader,
  selfGroupStore: MlsSelfGroupStateStore,
  record: IdentityRecord,
  mutationSink: VaultBackedLocalJmapMutationSink,
  apexDomain: string,
  coreBaseUrl: string,
  /** Overrides the default core-HTTP submission path -- everything else
   * (signing, emailId, mailbox transitions) is unchanged, since this only
   * decides WHERE the signed request goes. */
  transportOverride?: MailSubmissionTransport,
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
  const blobs = buildVaultBlobReader(vault, vault, selfGroupStore, record.did, record.masterSeed)
  const transport = transportOverride ?? new CoreMailSubmissionTransport({ baseUrl: coreBaseUrl })
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

export { mailFromForIdentity }

export interface EnableDidCommOptions {
  /** Where the DIDComm ingress endpoint lives (`core/adapters/didcomm-http.ts`'s
   * deployment) -- POST /v1/didcomm/ingress under this origin becomes the
   * routing.json service descriptor's serviceEndpoint. Used only as the
   * FALLBACK: superseded by `mediatorUrls` when at least one registration
   * there succeeds, and as the last resort when every one of them fails. */
  coreBaseUrl: string
  /** Independent, blind mediators to register this identity's shared
   * DIDComm kid with at provisioning time (ARC.md's 2026-08-27 redesign) --
   * each successfully-registered one becomes a routing.json
   * DIDCommMessaging entry with `routingKeys` naming it (webvh-routing.ts),
   * superseding the legacy direct `coreBaseUrl` endpoint. Registration
   * failures are logged and skipped, never fatal to provisioning: a
   * mediator being briefly unreachable at signup must not block account
   * creation. Empty/omitted keeps today's exact behavior (the legacy
   * direct model, no mediator involved). */
  mediatorUrls?: string[]
  /** When given, this identity's derived mail address (mailFromForIdentity)
   * is published into routing.json's `alsoKnownAs` -- otherwise nothing
   * anywhere ever asserts the DID<->mail link (found live, 2026-08-26: a
   * resolved document's alsoKnownAs was always empty). Optional because a
   * caller with no apexDomain configured has no mail address to derive at
   * all (main.ts's own read-only-UI fallback). */
  apexDomain?: string
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
 * The DIDComm keyAgreement key is IDENTITY-shared, not per-device (2026-08-27
 * redesign, ARC.md's DIDComm mediator section) -- same shape as
 * vault/openpgp-credential.ts's mail credential, for the same reason: any of
 * this identity's trusted devices needs to be able to decrypt the SAME
 * incoming ciphertext, which sharing the actual private key (synced via the
 * ordinary vault delivery pipeline, `reader`/`sink` below) gets for free,
 * unlike the earlier per-device scheme where a sender had to guess which of
 * several published keys some device might be listening on. `reader.readCurrent()`
 * finds an already-synced credential from another device first; only the
 * device that happens to reach this point before any sibling ever has does
 * `sink.store()` mint a fresh one.
 *
 * Derives the kid the same way didcomm/devicekid.ts always did
 * (deviceKidFragment -- deliberately NOT `record.deviceKid`, which names a
 * different key: the MLS leaf credential, not this one), publishes the
 * signed `#routing` log pointer once (webvh-routing-pointer.ts) and the
 * identity's ONE keyAgreement entry + DIDCommMessaging service descriptor in
 * routing.json (webvh-routing.ts), then persists the key on this device's
 * own identity record. Idempotent on the KEY setup: a record that already
 * has `didCommKid` skips straight to ensureAlsoKnownAsPublished below --
 * still runs every boot (main.ts calls this unconditionally whenever a core
 * is configured) so an identity provisioned before alsoKnownAs existed
 * picks it up on its next boot rather than staying stuck without it forever.
 *
 * Fetch-merge-put against routing.json, not build-from-scratch-and-replace,
 * so mlkem/alsoKnownAs/name/openpgp fields already published by something
 * else survive -- the keyAgreement entry itself is a single-element array
 * now (REPLACED wholesale, not merged): there is only ever one, identity-wide.
 */
export async function enableDidComm(
  recordStore: IdentityRecordStore,
  record: IdentityRecord,
  reader: DidCommCredentialReader,
  sink: DidCommCredentialVaultSink,
  opts: EnableDidCommOptions,
): Promise<IdentityRecord> {
  if (record.didCommKid) {
    await ensureAlsoKnownAsPublished(record, opts).catch(e => console.warn('[enableDidComm] alsoKnownAs backfill failed:', e instanceof Error ? e.message : e))
    return record
  }

  let credential: DidCommPrivateCredentialV1
  try {
    credential = await reader.readCurrent()
  } catch (e) {
    if (!(e instanceof Error) || e.message !== 'no DIDComm credential is available') throw e
    const x25519PrivateKey = x25519.utils.randomSecretKey()
    const didCommKid = `${record.did}${deviceKidFragment(x25519.getPublicKey(x25519PrivateKey))}`
    credential = { version: 1, kind: 'credential.didcomm.private', identityId: record.did, didCommKid, privateKey: x25519PrivateKey, createdAt: new Date().toISOString() }
    await sink.store(credential)
  }

  const didCommKid = credential.didCommKid
  const x25519PublicKey = x25519.getPublicKey(credential.privateKey)
  const signPrivateKey = fromHex(record.signPrivateKey)
  const signPublicKey = fromHex(record.signPublicKey)

  await publishRoutingPointer({ did: record.did, signingPrivateKey: signPrivateKey, signingPublicKey: signPublicKey, fetch: opts.fetch })

  const fetchImpl = opts.fetch ?? fetch
  const current = await fetchRouting(record.did, fetchImpl).catch(() => null)
  if (current?.keyAgreementVerificationMethod?.some(method => method.id === didCommKid)) {
    const updated: IdentityRecord = { ...record, didCommKid, didCommX25519PrivateKey: toHex(credential.privateKey) }
    await recordStore.put(updated)
    return updated
  }
  let alsoKnownAs = current?.alsoKnownAs ? [...current.alsoKnownAs] : undefined
  if (opts.apexDomain) {
    try { alsoKnownAs = [...new Set([...(alsoKnownAs ?? []), mailFromForIdentity(record.did, opts.apexDomain)])] }
    catch { /* identity's domain isn't a subdomain of apexDomain -- nothing to assert */ }
  }
  const buildDoc = (service: ReturnType<typeof buildRoutingDoc>): RoutingDoc => ({
    service: service.service,
    keyAgreementVerificationMethod: service.keyAgreementVerificationMethod!,
    ...(current?.mlkemVerificationMethod?.length ? { mlkemVerificationMethod: current.mlkemVerificationMethod } : {}),
    ...(alsoKnownAs?.length ? { alsoKnownAs } : {}),
    ...(current?.name ? { name: current.name } : {}),
    ...(current?.openpgpPublicKey ? { openpgpPublicKey: current.openpgpPublicKey } : {}),
  })
  const signing = { updateKey: encodeMultikey(signPublicKey), privateKey: signPrivateKey }
  const keyAgreementKeys = [{ kid: didCommKid, publicKey: x25519PublicKey }]

  // Publish the keyAgreement key FIRST, via the legacy endpoint shape --
  // registerWithMediator below sends a mediate-request the mediator must
  // authenticate by resolving THIS identity's own published keyAgreement
  // entry, so it has to already be live before any registration can
  // possibly succeed (a chicken-and-egg a did:dht-era identity never had:
  // its keyAgreement key rode in the DID document itself, published at
  // genesis, not in a separately-provisioned routing.json).
  await putRouting(record.did, buildDoc(buildRoutingDoc(record.did, {
    didCommEndpoint: `${opts.coreBaseUrl.replace(/\/$/, '')}/v1/didcomm/ingress`,
    keyAgreementKeys,
  })), signing, fetchImpl)

  // Best-effort: register with each configured mediator, keeping only the
  // ones that actually succeeded. A mediator down at signup time must not
  // block account creation -- the legacy publish above already stands as
  // the fallback when this ends up empty.
  const mediators: MediatorRegistration[] = []
  for (const url of opts.mediatorUrls ?? []) {
    try {
      const info = await registerWithMediator(url, { did: record.did, xKid: didCommKid, xPriv: credential.privateKey }, fetchImpl)
      mediators.push({ url, routingKid: info.xKid })
    } catch (e) {
      console.warn(`[enableDidComm] could not register with mediator ${url}:`, e instanceof Error ? e.message : e)
    }
  }

  if (mediators.length) {
    await putRouting(record.did, buildDoc(buildRoutingDoc(record.did, { mediators, keyAgreementKeys })), signing, fetchImpl)
  }

  const updated: IdentityRecord = { ...record, didCommKid, didCommX25519PrivateKey: toHex(credential.privateKey) }
  await recordStore.put(updated)
  return updated
}

/** Backfills routing.json's alsoKnownAs with this identity's derived mail
 * address for an identity that already has a didCommKid (so enableDidComm's
 * own main path above won't touch routing.json again) -- a fetch-modify-put
 * on the JSON directly, same shape as webvh-routing.ts's own setRoutingName,
 * so an already-set self-asserted `name` survives untouched. No-op when
 * there's no apexDomain to derive a mail address from, or the address is
 * already listed (the common case on every boot after the first). */
async function ensureAlsoKnownAsPublished(record: IdentityRecord, opts: EnableDidCommOptions): Promise<void> {
  if (!opts.apexDomain) return
  let mailFrom: string
  try { mailFrom = mailFromForIdentity(record.did, opts.apexDomain) }
  catch { return }
  const fetchImpl = opts.fetch ?? fetch
  const current = await fetchRouting(record.did, fetchImpl)
  if (!current || current.alsoKnownAs?.includes(mailFrom)) return
  const signPrivateKey = fromHex(record.signPrivateKey)
  const signPublicKey = fromHex(record.signPublicKey)
  const alsoKnownAs = [...new Set([...(current.alsoKnownAs ?? []), mailFrom])]
  await putRouting(record.did, { ...current, alsoKnownAs }, { updateKey: encodeMultikey(signPublicKey), privateKey: signPrivateKey }, fetchImpl)
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
