// did:webvh identity move orchestration (PLANWEBVH.md §5.1/§9): the
// high-level operation moveDidToNewDomain (webvh/publish.ts) is just one
// piece of — building the from_prior JWT and persisting the new identity's
// DidRecord are the rest. Kept out of webvh/publish.ts to avoid a dependency
// on store.ts/didcomm/rotation.ts from that lower-level module, and out of
// didcomm-devices.ts because a domain move is an identity-lifecycle
// operation, not a device-registration one (DIDComm re-registration under
// the new DID is the caller's job, via didcomm-devices.ts's
// registerWithMediator — not duplicated here).
import { getDidRecord, storeDidRecord, deleteDidRecord, type DidRecord } from '../store.ts'
import { hexToBytes, bytesToHex } from '../../utils.ts'
import { moveDidToNewDomain, type BisetRelay } from './publish.ts'
import { buildFromPrior } from '../didcomm/rotation.ts'

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000

export interface MoveWebvhIdentityOptions {
  oldDid: string
  newDomain: string
  newUsername: string
  relays: BisetRelay[]
  addresses: string | string[]
  /** How long outgoing messages keep attaching the from_prior header
   * (PLANWEBVH.md §5.1's 30-day default) — a peer that re-resolves within
   * this window learns of the move either way; this is purely for one that
   * doesn't. */
  fromPriorWindowMs?: number
  /** Required when pre-rotation is active for this identity — a move is a
   * log entry like any other, and resolver.ts forbids appending one while
   * pre-rotation is active without a key matching the current commitment
   * (migrate.ts's own note). Omit when pre-rotation is off: the Root Key
   * signs as it always has, unchanged. The caller (ui/edit-identity.ts)
   * gets this the same way Rotate/Deactivate/Revoke do — prompting for the
   * current Spare Key phrase and generating a fresh one for the next round
   * (ui/prerotation.ts's revealAndVerify/generateSpareKeypair). */
  spareKeyOverride?: { privateKey: Uint8Array; publicKey: Uint8Array; nextKeyHash: string }
}

/** Moves an identity to a new domain via did:webvh's portability mechanism
 * (**same SCID**, same root key — webvh/publish.ts's moveDidToNewDomain),
 * signs a from_prior JWT with the identity's root key, and persists a new
 * DidRecord for the new DID string carrying that JWT for outgoing messages
 * to attach.
 *
 * from_prior is still built even though the move is now SCID-preserving:
 * portability is the "re-resolve and you'll find me" path, from_prior the
 * "know immediately, without resolving" path — complementary, not
 * alternatives (PLANWEBVH.md §4.1).
 *
 * Does NOT re-register DIDComm under the new DID — the caller does that
 * (didcomm-devices.ts's registerWithMediator) once this returns, same as any
 * other newly-created identity would. */
export async function moveWebvhIdentity(opts: MoveWebvhIdentityOptions): Promise<DidRecord> {
  const oldRec = await getDidRecord(opts.oldDid)
  if (!oldRec) throw new Error('moveWebvhIdentity: no local record for the DID being moved')
  const rootPriv = hexToBytes(oldRec.rootPrivateKey)
  const rootPub = hexToBytes(oldRec.rootPublicKey)
  const signingPriv = opts.spareKeyOverride?.privateKey ?? rootPriv
  const signingPub = opts.spareKeyOverride?.publicKey ?? rootPub

  const { newDid } = await moveDidToNewDomain({
    oldDid: opts.oldDid, newDomain: opts.newDomain, newUsername: opts.newUsername,
    identityPublicKey: rootPub, signingPrivateKey: signingPriv, signingPublicKey: signingPub,
    nextKeyHash: opts.spareKeyOverride?.nextKeyHash,
    relays: opts.relays, addresses: opts.addresses,
  })

  // Signed by the OLD identity's own root key at its `#key-1` verification
  // method — the kid a receiver's verifyFromPrior resolves against the PRIOR
  // DID's document (rotation.ts's own contract).
  const iat = Math.floor(Date.now() / 1000)
  const jwt = buildFromPrior(opts.oldDid, newDid, { kid: `${opts.oldDid}#key-1`, edPrivateKey: rootPriv }, iat)

  const newRec: DidRecord = {
    ...oldRec,
    did: newDid,
    movedFromJwt: jwt,
    movedFromExpiresAt: Date.now() + (opts.fromPriorWindowMs ?? THIRTY_DAYS_MS),
    // The just-consumed Spare Key is now the current Sign Key — same
    // caching ui/prerotation.ts's cacheSigningKey does after a rotate, so a
    // later Sync/publish on this device doesn't need to re-prompt for what
    // this move already revealed. Untouched (carried via the spread above)
    // when pre-rotation was off — the Root Key still signs.
    ...(opts.spareKeyOverride
      ? {
        signingPrivateKey: bytesToHex(opts.spareKeyOverride.privateKey),
        signingPublicKey: bytesToHex(opts.spareKeyOverride.publicKey),
      }
      : {}),
  }
  // Device DIDComm registration is scoped to the OLD document's kid/slot —
  // does not carry over. The new identity registers fresh, exactly like any
  // newly-created one (didcomm-devices.ts's ensureDeviceKey mints a new key
  // the first time it's asked, same as it would for a brand-new identity).
  delete newRec.didCommOwnKid
  delete newRec.didCommPublicKey
  delete newRec.didCommPrivateKey
  delete newRec.didCommSiblingKeys
  delete newRec.didCommMediatorUrl
  delete newRec.didCommRoutingKey

  await storeDidRecord(newRec)
  // One identity, one record (PLANWEBVH.md §3.1): the IndexedDB key is the
  // CURRENT DID string, so writing the post-move record leaves the pre-move
  // one behind under its old key — two records for what is, by the stable
  // key, a single identity. Dropping it keeps every "which identities do I
  // have" enumeration honest, and getDidRecord's stable-key fallback means
  // callers still holding the old DID string resolve to the surviving record
  // rather than a stale duplicate carrying superseded DIDComm state.
  await deleteDidRecord(opts.oldDid)
  return newRec
}
