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
import { ed25519 } from '@noble/curves/ed25519.js'
import { deriveRootKey } from './keys.ts'
import { mnemonicToSeed } from './seed.ts'
import { createGenesis } from './webvh/create-genesis.ts'
import { addDeviceVerificationMethod } from './webvh/add-device-verification-method.ts'
import { resolveByDomain } from './webvh/resolver.ts'
import { decodeMultikey } from './webvh/multikey.ts'
import type { IdentityRecord, IdentityRecordStore } from './record-store.ts'
import { generateOwnKeyPackage, ownSignaturePrivateKey, setMlsAuthService } from '../mls/group.ts'
import { webvhAuthenticationService } from '../mls/webvh-authentication-service.ts'
import { ensureSelfGroupWithRosterInstall, reflectPendingSelfGroupCommits, type SelfGroupSigner } from '../mls/self-group.ts'
import { ensureKeyPackagePool } from '../mls/key-package-pool.ts'
import { CoreMlsDeliveryTransport } from '../mls/core-mls-delivery-transport.ts'
import { CoreRosterInstallTransport } from '../mls/core-roster-install-transport.ts'
import { CoreVaultDeliveryTransport } from '../vault/core-delivery-transport.ts'
import { StoredSegmentKeyResolver, type SegmentKeyResolver } from '../vault/segment-key-resolver.ts'
import { ActiveVaultSegmentManager, type ActiveVaultSegment } from '../vault/active-segment.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter } from '../vault/store.ts'
import { MlsVaultEpochKeyResolver } from '../mls/vault-epoch.ts'
import { MlsMembershipSegmentKeyWrapSigner, MlsMembershipSegmentKeyWrapVerifier } from '../mls/segment-key-membership.ts'
import { StoredMlsSelfGroupProvider, type MlsSelfGroupStateStore } from '../mls/store.ts'
import type { MlsKeyPackageStore } from '../mls/keypackage-store.ts'
import { segmentKeyWrapSigningBytes } from '../vault/crypto.ts'
import type { RestoreTransferVerifier } from '../vault/restore-transfer.ts'
import { equalBytes } from '../protocol/canonical.ts'
import { deliverySeq, type DeliverySeq } from '../protocol/ids.ts'
import { vaultDeliveryPullSigningBytes } from '../protocol/signing.ts'
import type { VaultDeliveryPullV1 } from '../protocol/vault.ts'
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
  const sign: SelfGroupSigner = bytes => ed25519.sign(bytes, ownSignaturePrivateKey(stored.state))
  const mlsTransport = new CoreMlsDeliveryTransport({ baseUrl: opts.coreBaseUrl, fetch: opts.fetch })
  const rosterTransport = new CoreRosterInstallTransport({ baseUrl: opts.coreBaseUrl, fetch: opts.fetch })

  const deliveryFloorForNewDevice = () => currentVaultDeliveryLatestSeq(opts.coreBaseUrl, record.did, record.deviceKid!, sign, opts.fetch, now)
  const state = await reflectPendingSelfGroupCommits(
    selfGroupStore, mlsTransport, rosterTransport, record.did, record.deviceKid, sign, deliveryFloorForNewDevice, now,
  )

  await ensureKeyPackagePool(mlsTransport, keyStore, record.did, record.deviceKid, sign, undefined, now)

  return state
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
