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
import { generateOwnKeyPackage } from '../mls/group.ts'
import { setMlsAuthService } from '../mls/group.ts'
import { webvhAuthenticationService } from '../mls/webvh-authentication-service.ts'
import { ensureSelfGroupWithRosterInstall, type SelfGroupSigner } from '../mls/self-group.ts'
import { ensureKeyPackagePool } from '../mls/key-package-pool.ts'
import { CoreMlsDeliveryTransport } from '../mls/core-mls-delivery-transport.ts'
import { CoreRosterInstallTransport } from '../mls/core-roster-install-transport.ts'
import type { MlsSelfGroupStateStore } from '../mls/store.ts'
import type { MlsKeyPackageStore } from '../mls/keypackage-store.ts'
import { equalBytes } from '../protocol/canonical.ts'
import { deliverySeq, type DeliverySeq } from '../protocol/ids.ts'
import type { ClientState } from '../mls/vendor/index.ts'

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
