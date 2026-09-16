// The Vault-side identity boundary: VCK-derived key resolution, SegmentKey
// wraps, and the Local JMAP read model.
//
// Everything here is now driven by a Wallet-authorized device -- a public
// DID plus this browser's own MLS leaf. The seed side of this file
// (`createNewIdentity`, `restoreIdentity`, `registerDevice`, the
// Master-derived storage KEK boundary, mail submission, `enableDidComm` and
// `ensureMimiVaultRoom`) was removed in N1 (2026-09-05): biset no longer
// issues or restores an identity of its own, so no Root, Sign, Spare or
// Master material is representable in this module at all.
import { ed25519 } from '@noble/curves/ed25519.js'
import { decodeMlsDeviceCredential, encodeMlsDeviceCredential, verifyMlsDeviceCredentialRoot, type MlsDeviceCredentialV2 } from '../mls/device-credential.ts'
import { StoredSegmentKeyResolver, type SegmentKeyResolver, type VaultEpochKeyResolver } from '../store/vault/segment-key-resolver.ts'
import { ActiveVaultSegmentManager, type ActiveVaultSegment } from '../store/vault/active-segment.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter } from '../store/vault/store.ts'
import type { SegmentGrantor } from '../store/vault/crypto.ts'
import type { ActorSequenceStore, VaultObjectReader, VaultProjectionReader, VaultRecordReader } from '../store/vault/store.ts'
import { VaultObjectBlobReader } from '../store/vault/blob-reader.ts'
import type { LocalJmapReadModel } from '../store/projection/gateway.ts'
import { IndexedDbLocalJmapReadModel } from '../store/projection/indexeddb.ts'
import { type VaultEventId } from '../../protocol/ids.ts'
import { WalletDerivedVaultKeyResolver, type VaultContentKeyProvider } from '../store/vault/vault-content-key.ts'
import type { VaultEventSigner } from '../store/vault/events.ts'

export interface VaultCryptoBoundary {
  /** Resolves the current Vault-content-key generation. */
  epochs: VaultEpochKeyResolver
  /** Resolves a SegmentKey for reading an already-encrypted vault object. */
  resolver: SegmentKeyResolver
  /** Signs new Vault events, and identifies this device as the grantor on
   * SegmentKeyWraps it creates — `createSegmentKeyWrap` (vault/crypto.ts)
   * takes this directly. A wrap's trust rests on decrypting under the
   * current VCK, not on a signature over `grantorDeviceId`. */
  signer: SegmentGrantor & VaultEventSigner
  /** `vault-mutation-sink.ts`'s `activeSegment()` option. */
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
  signaturePrivateKey: Uint8Array
  credential: MlsDeviceCredentialV2
  /** Wallet's stable Root public key. Verifies a PAST device's own
   * `actorCredential` (below) so a re-login that regenerates this device's
   * signaturePrivateKey -- and therefore its deviceKid -- does not orphan
   * every Vault event that device already signed. */
  rootPublicKey: Uint8Array
}

class WalletDeviceVaultSigner implements SegmentGrantor, VaultEventSigner {
  readonly deviceId: string
  private readonly publicKey: Uint8Array
  constructor(private readonly identity: Required<Pick<WalletVaultIdentity, 'did' | 'deviceKid' | 'signaturePrivateKey' | 'credential' | 'rootPublicKey'>>) {
    this.deviceId = identity.deviceKid
    this.publicKey = identity.credential.signaturePublicKey.slice()
  }
  async sign(bytes: Uint8Array): Promise<Uint8Array> { return ed25519.sign(bytes, this.identity.signaturePrivateKey) }
  async deviceCredential(): Promise<Uint8Array> { return encodeMlsDeviceCredential(this.identity.credential) }
  /**
   * This device's own signing key verifies directly. Any OTHER deviceId --
   * most commonly THIS SAME BROWSER under a past login's now-regenerated
   * signaturePrivateKey (a fresh `beginDidMdWalletLogin` mints a new one
   * every time), but just as well a genuine sibling device -- verifies only
   * via its own `actorCredential`: a Root-signed binding between that
   * deviceKid and the leaf key the event was actually signed with. Without
   * this fallback, every Vault event signed before the most recent re-login
   * becomes permanently unverifiable the moment the signing key rotates --
   * "contact key event signature is invalid" (found live, 2026-09-15),
   * the VaultEvent counterpart to the SegmentKeyWrap incident this same day.
   */
  async verify(deviceId: string, bytes: Uint8Array, signature: Uint8Array, deviceCredential?: Uint8Array): Promise<boolean> {
    if (deviceId === this.deviceId) return signature.length === 64 && ed25519.verify(signature, bytes, this.publicKey)
    if (!deviceCredential) return false
    try {
      const credential = decodeMlsDeviceCredential(deviceCredential)
      return credential.identityId === this.identity.did && credential.deviceKid === deviceId
        && verifyMlsDeviceCredentialRoot(credential, this.identity.rootPublicKey)
        && signature.length === 64 && ed25519.verify(signature, bytes, credential.signaturePublicKey)
    } catch {
      return false
    }
  }
}

export function buildWalletVaultCryptoBoundary(
  wraps: SegmentKeyWrapReader & SegmentKeyWrapWriter,
  segments: ActiveVaultSegmentStore,
  identity: WalletVaultIdentity,
  vaultContentKeys: VaultContentKeyProvider,
): VaultCryptoBoundary {
  if (!identity.did || !identity.deviceKid) throw new Error('buildWalletVaultCryptoBoundary: Wallet device is incomplete')
  const epochs: VaultEpochKeyResolver = new WalletDerivedVaultKeyResolver(vaultContentKeys)
  const signer: SegmentGrantor & VaultEventSigner = new WalletDeviceVaultSigner(identity)
  const resolver = new StoredSegmentKeyResolver(wraps, epochs)
  const segmentManager = new ActiveVaultSegmentManager({ identityId: identity.did, segments, wraps, epochs, signer })
  return { epochs, resolver, signer, activeSegment: () => segmentManager.activeSegment() }
}
/** Opens local Vault blobs with VCK-wrapped SegmentKeys. */
export function buildLocalJmapReadModel(
  vault: VaultProjectionReader & VaultObjectReader & SegmentKeyWrapReader,
  identityId: string,
  vaultContentKeys: VaultContentKeyProvider,
): LocalJmapReadModel {
  const resolver = new StoredSegmentKeyResolver(vault, new WalletDerivedVaultKeyResolver(vaultContentKeys))
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
