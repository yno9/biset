// New-identity creation, end to end: root key derivation, did:webvh genesis,
// this device's own MLS leaf key registered as a verificationMethod, and
// this device's self-group membership + roster reflection + KeyPackage pool
// — everything Vault Core's identity bootstrap needs before any vault
// content can be read or written (PLAN.md §4.1's roster/VEK boundary).
//
// Ported at the flow level from src.bak/ui/account-create.ts's submit
// handler and src.bak/did/index.ts's initDidWebvh/localDidRecord, trimmed to
// what this rewrite actually carries forward: no mail/AP relay provisioning,
// no DIDComm mediator registration, no PGP — all relay-adapter or
// DIDComm-adapter concerns this rewrite does not have yet (PLAN.md §6).
// Login/restore from an existing mnemonic (src.bak/did/restore.ts) is not
// ported either; this module only creates BRAND NEW identities.
import { ed25519 } from '@noble/curves/ed25519.js'
import { deriveRootKey } from './keys.ts'
import { createGenesis } from './webvh/create-genesis.ts'
import { addDeviceVerificationMethod } from './webvh/add-device-verification-method.ts'
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
  ensureMlsAuthServiceInstalled()
  const now = opts.now ?? (() => new Date())

  const masterSeed = opts.masterSeed ?? crypto.getRandomValues(new Uint8Array(32))
  const root = deriveRootKey(masterSeed)
  const { did } = await createGenesis({
    domain: opts.domain, rootPrivateKey: root.privateKey, rootPublicKey: root.publicKey,
    didWebMirror: opts.didWebMirror, fetch: opts.fetch,
  })

  const fragment = randomFragment()
  const deviceKid = `${did}#${fragment}`
  const kp = await generateOwnKeyPackage(deviceKid)
  await addDeviceVerificationMethod({
    did, fragment, devicePublicKey: kp.publicPackage.leafNode.signaturePublicKey,
    signingPrivateKey: root.privateKey, signingPublicKey: root.publicKey,
    didWebMirror: opts.didWebMirror, fetch: opts.fetch,
  })

  const sign: SelfGroupSigner = bytes => ed25519.sign(bytes, kp.privatePackage.signaturePrivateKey)
  const mlsTransport = new CoreMlsDeliveryTransport({ baseUrl: opts.coreBaseUrl, fetch: opts.fetch })
  const rosterTransport = new CoreRosterInstallTransport({ baseUrl: opts.coreBaseUrl, fetch: opts.fetch })

  // The genesis device is the roster's own first (and, at this point, only)
  // trusted device — it starts pulling vault delivery from whatever the
  // CURRENT latestSeq is, which for a brand-new identity is the beginning.
  const deliveryFloorForNewDevice = async (): Promise<DeliverySeq> => deliverySeq(0n)
  const selfGroupState = await ensureSelfGroupWithRosterInstall(
    selfGroupStore, mlsTransport, rosterTransport, did, deviceKid, kp, sign, deliveryFloorForNewDevice, now,
  )
  if (!selfGroupState) throw new Error('createNewIdentity: self-group bootstrap did not produce a state')

  await ensureKeyPackagePool(mlsTransport, keyStore, did, deviceKid, sign, undefined, now)

  const record: IdentityRecord = {
    did, masterSeed: toHex(masterSeed), rootPublicKey: toHex(root.publicKey), rootPrivateKey: toHex(root.privateKey), deviceKid,
  }
  await recordStore.put(record)

  return { record, masterSeed, selfGroupState }
}
