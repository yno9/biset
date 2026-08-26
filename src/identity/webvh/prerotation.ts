// did:webvh v1.0 pre-rotation (spec "Pre-Rotation Key Hash Generation and
// Verification") — what makes a stolen ACTIVE update key powerless rather
// than an outright takeover. Plain rotation (there is no plain-rotation
// write path in this rewrite either, only genesis's own initial updateKeys)
// does not protect against a compromised key: whoever holds it can rotate to
// a key of THEIR choosing and lock the real owner out, because nothing in
// the log distinguishes "the owner rotating" from "an attacker who copied
// the same bits rotating." Pre-rotation closes that gap by committing to the
// NEXT key's HASH one entry ahead of time — revealing and using that key
// later proves nothing was guessed or stolen just now, since the commitment
// predates the reveal. See resolver.ts's own note on the verification side
// of this (the entry that activates pre-rotation is the LAST thing the
// current key will ever be able to author for this DID) — that side was
// never lost; only this write side was, as collateral damage of an
// unrelated cleanup (a copied-but-unwired src.bak/did/webvh/prerotation.ts
// got deleted alongside genuinely dead files, 2026-08-25).
//
// Ported from src.bak/did/webvh/prerotation.ts with one real fix, not just a
// rename: src.bak's log was "minimal" (only #key-1 + authentication, every
// device key lived in routing.json instead — see webvh-routing.ts's own
// header on why THIS rewrite doesn't follow that anymore:
// add-device-verification-method.ts puts device keys directly in the signed
// log's own verificationMethod). That means the old
// buildBisetWebvhState(did, identityPublicKey) — which rebuilds `state` from
// scratch with nothing but #key-1 — would silently WIPE every already-
// registered device's verificationMethod out of the document on every
// prerotation operation. None of these three operations touch document
// content at all, only `parameters`, so the fix is simpler than the
// original: reuse `last.state` verbatim.
//
// Three operations, three functions:
//   activatePreRotation   — turns the feature on. Signed normally by the
//     CURRENT key (pre-rotation isn't active yet going into this entry), so
//     this is the one operation that still works exactly like plain
//     rotation. Everything after this must go through the other two.
//   rotateToPreRotatedKey — reveals the committed key, uses it to become the
//     new updateKeys, and commits a FRESH hash so pre-rotation stays active.
//   deactivatePreRotation — same mechanics as rotateToPreRotatedKey, but
//     commits nothing further (`nextKeyHashes: []`), turning the feature
//     back off. Still requires the revealed key, same as rotating — once
//     pre-rotation is active, the CURRENT key has no authority left at all,
//     not even to turn the feature off (losing the pre-rotation phrase is as
//     final as losing the root recovery phrase).
import { defaultFetch } from '../../net-fetch.ts'
import { encodeMultikey } from './multikey.ts'
import { multikeyHashBase58 } from './hash.ts'
import { generateEntryHash, entryVersionNumber, resolveParameters, parametersToWrite, type LogEntry, type LogParameters } from './log.ts'
import { buildProof } from './proof.ts'
import type { SignedWebvhState } from './document.ts'
import { fetchCurrentLog, putLog, nowVersionTime } from './log-io.ts'

/** Whether this identity currently has an outstanding pre-rotation
 * commitment — a config UI's "Key rotation" toggle reads this to decide
 * whether to render itself on or off. `parameters.nextKeyHashes` lives in
 * the LOG, not the resolved DID document, so this reads the log directly
 * rather than going through resolver.ts's resolve(). */
export async function isPreRotationActive(did: string, fetch?: typeof globalThis.fetch): Promise<boolean> {
  return (await currentNextKeyHashes(did, fetch)).length > 0
}

/** The identity's currently outstanding pre-rotation commitment, or an
 * empty array if pre-rotation isn't active — lets a Spare Key prompt show
 * live feedback matching a typed phrase against the real commitment before
 * ever attempting to sign with it. */
export async function currentNextKeyHashes(did: string, fetch?: typeof globalThis.fetch): Promise<string[]> {
  const { last } = await fetchCurrentLog(did, fetch ?? defaultFetch())
  return last.parameters.nextKeyHashes ?? []
}

export interface ActivatePreRotationOptions {
  did: string
  /** Whichever key currently holds updateKeys authority for this DID. On a
   * first-ever activation that's the original root key; on a re-activation
   * after this identity has already been through a rotate/deactivate cycle,
   * updateKeys has moved to whatever key that cycle last revealed (see
   * rotateOrDeactivate below), and THAT key must sign here instead. */
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  /** hash(encodeMultikey(nextPublicKey)) — computed by the caller via
   * multikeyHashBase58. The matching private key is never passed here: this
   * function only ever sees and publishes the hash, never the key it
   * commits to. */
  nextKeyHash: string
  fetch?: typeof globalThis.fetch
}

/** Turns pre-rotation on. Signed by whichever key currently holds updateKeys
 * authority under the ORDINARY (non-pre-rotation) rule, since pre-rotation
 * is not active going into this entry — the last time that key's signature
 * will mean anything for this DID (resolver.ts's own note). */
export async function activatePreRotation(opts: ActivatePreRotationOptions): Promise<void> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  const { url, entries, last } = await fetchCurrentLog(opts.did, fetchImpl)

  const updateKey = encodeMultikey(opts.signingPublicKey)
  if (!(last.parameters.updateKeys ?? []).includes(updateKey)) {
    throw new Error('activatePreRotation: local signing key is not authorized by the document\'s current updateKeys (rotated elsewhere) — restore with the current Root Key phrase/DID to get back in sync')
  }
  if ((last.parameters.nextKeyHashes?.length ?? 0) > 0) {
    throw new Error('activatePreRotation: pre-rotation is already active for this identity')
  }

  const versionTime = nowVersionTime()
  const parameters = parametersToWrite(last.parameters, resolveParameters(last.parameters, { nextKeyHashes: [opts.nextKeyHash] }))
  const state = last.state as SignedWebvhState

  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${updateKey}#${updateKey}`, privateKey: opts.signingPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  await putLog(url, [...entries, entry], [entry], fetchImpl)
}

export interface RotateToPreRotatedKeyOptions {
  did: string
  /** The key committed by the CURRENT log entry's nextKeyHashes, revealed
   * now — becomes the new updateKeys AND signs this very entry (safe only
   * because its hash was committed one entry earlier — see this file's
   * header). */
  revealedPrivateKey: Uint8Array
  revealedPublicKey: Uint8Array
  /** The identity's Root Key — never touched by this operation directly,
   * only needed as the restoration target when deactivating (see
   * rotateOrDeactivate below). Pass it even for a plain rotate; it is simply
   * unused there. */
  identityPublicKey: Uint8Array
  /** hash(encodeMultikey(nextPublicKey)) for the FOLLOWING round — provide
   * to keep pre-rotation active, omit to deactivate (deactivatePreRotation
   * below is this same function with it left out). */
  nextKeyHash?: string
  fetch?: typeof globalThis.fetch
}

/** Core of both `rotateToPreRotatedKey` and `deactivatePreRotation`.
 *
 * A normal rotation consumes the committed key and commits another one. A
 * deactivation consumes the committed key, clears that commitment, THEN
 * returns update authority to the identity's Root Key. The latter has to be
 * a second entry: while pre-rotation is active, the resolver correctly
 * rejects an updateKeys value that was not committed one entry earlier. Both
 * entries are appended in one request, so observers never see the temporary
 * "off, but still Sign-Key-controlled" state. */
async function rotateOrDeactivate(opts: RotateToPreRotatedKeyOptions): Promise<void> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  const { url, entries, last } = await fetchCurrentLog(opts.did, fetchImpl)

  if ((last.parameters.nextKeyHashes?.length ?? 0) === 0) {
    throw new Error('rotateToPreRotatedKey: pre-rotation is not active for this identity')
  }
  const revealedKey = encodeMultikey(opts.revealedPublicKey)
  if (!(last.parameters.nextKeyHashes ?? []).includes(multikeyHashBase58(revealedKey))) {
    throw new Error('rotateToPreRotatedKey: this key does not match the identity\'s current pre-rotation commitment — wrong Spare Key phrase, or someone else already rotated')
  }

  const versionTime = nowVersionTime()
  // updateKeys/nextKeyHashes are forced explicit here rather than left to
  // parametersToWrite's usual diff — resolver.ts's own rule is that NEITHER
  // may be inherited while pre-rotation is active, regardless of whether
  // either happens to end up equal to what inheritance would have produced.
  const restParameters = parametersToWrite(last.parameters, resolveParameters(last.parameters, {}))
  const parameters: LogParameters = { ...restParameters, updateKeys: [revealedKey], nextKeyHashes: opts.nextKeyHash ? [opts.nextKeyHash] : [] }
  const state = last.state as SignedWebvhState

  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${revealedKey}#${revealedKey}`, privateKey: opts.revealedPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  if (opts.nextKeyHash) {
    await putLog(url, [...entries, entry], [entry], fetchImpl)
    return
  }

  // Pre-rotation is now OFF in `entry`, so the just-revealed key is the
  // previous/current update key permitted to authorize this ordinary rotation
  // back to Root Key. `identityPublicKey` is always #key-1 (the Root Key),
  // distinct from the Sign/Spare Key that signs this transition.
  const rootUpdateKey = encodeMultikey(opts.identityPublicKey)
  const rootVersionTime = nowVersionTime()
  const rootParameters = parametersToWrite(parameters, resolveParameters(parameters, { updateKeys: [rootUpdateKey] }))
  const rootState = state
  const rootEntryHash = generateEntryHash(entry.versionId, rootVersionTime, rootParameters, rootState)
  const rootVersionId = `${entryVersionNumber(entry.versionId) + 1}-${rootEntryHash}`
  const rootUnsigned = { versionId: rootVersionId, versionTime: rootVersionTime, parameters: rootParameters, state: rootState }
  const rootProof = buildProof(rootUnsigned, { verificationMethod: `did:key:${revealedKey}#${revealedKey}`, privateKey: opts.revealedPrivateKey, created: rootVersionTime })
  const rootEntry: LogEntry = { ...rootUnsigned, proof: [rootProof] }

  await putLog(url, [...entries, entry, rootEntry], [entry, rootEntry], fetchImpl)
}

export async function rotateToPreRotatedKey(opts: RotateToPreRotatedKeyOptions & { nextKeyHash: string }): Promise<void> {
  await rotateOrDeactivate(opts)
}

/** Disables pre-rotation and restores the Root Key as the sole current
 * update key. The one batched append is required by the pre-rotation rule
 * (see rotateOrDeactivate): the Root Key is not committed as the next key,
 * so it cannot appear in the consuming entry itself. */
export async function deactivatePreRotation(opts: Omit<RotateToPreRotatedKeyOptions, 'nextKeyHash'>): Promise<void> {
  await rotateOrDeactivate(opts)
}
