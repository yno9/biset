// did:webvh v1.0 pre-rotation (spec "Pre-Rotation Key Hash Generation and
// Verification") — what makes a stolen ACTIVE update key powerless rather
// than an outright takeover. Plain rotateUpdateKeys (publish.ts) does not
// protect against a compromised key: whoever holds it can rotate to a key
// of THEIR choosing and lock the real owner out, because nothing in the log
// distinguishes "the owner rotating" from "an attacker who copied the same
// bits rotating." Pre-rotation closes that gap by committing to the NEXT
// key's HASH one entry ahead of time — revealing and using that key later
// proves nothing was guessed or stolen just now, since the commitment
// predates the reveal. See resolver.ts's own note on the verification side
// of this (the entry that activates pre-rotation is the LAST thing the
// current key will ever be able to author for this DID).
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
//     not even to turn the feature off (ui/prerotation.ts's own note has the
//     UX consequence: losing the pre-rotation phrase is as final as losing
//     the root recovery phrase).
import { encodeMultikey } from './multikey.ts'
import { multikeyHashBase58 } from './hash.ts'
import { generateEntryHash, entryVersionNumber, resolveParameters, parametersToWrite, type LogEntry, type LogParameters } from './log.ts'
import { buildProof } from './proof.ts'
import { buildBisetWebvhState } from './document.ts'
import { fetchCurrentLog, putLog, nowVersionTime } from './log-io.ts'

/** Whether this identity currently has an outstanding pre-rotation
 * commitment — ui/prerotation.ts's config toggle reads this to decide
 * whether to render itself on or off. `parameters.nextKeyHashes` lives in
 * the LOG, not the resolved DIDDoc, so this reads the log directly rather
 * than going through resolver.ts's resolve(). */
export async function isPreRotationActive(did: string): Promise<boolean> {
  const { last } = await fetchCurrentLog(did)
  return (last.parameters.nextKeyHashes?.length ?? 0) > 0
}

export interface ActivatePreRotationOptions {
  did: string
  /** Whichever key currently holds updateKeys authority for this DID. On a
   * first-ever activation that's the original root key; on a re-activation
   * after this identity has already been through a rotate/deactivate cycle,
   * updateKeys has moved to whatever key that cycle last revealed (see
   * rotateOrDeactivate below), and THAT key must sign here instead —
   * ui/prerotation.ts's runActivatePreRotation is what tells the two cases
   * apart and prompts for the right phrase.
   */
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  /** #key-1, the document's own identity key. Independent of updateKeys and
   * never touched by any pre-rotation operation (same convention as
   * rotateOrDeactivate's separate `identityPublicKey`) — always the
   * identity's original root public key, signing key or not. */
  identityPublicKey: Uint8Array
  /** hash(encodeMultikey(nextPublicKey)) — computed by the caller
   * (ui/prerotation.ts) via multikeyHashBase58. The matching private key is
   * never passed here: this function only ever sees and publishes the hash,
   * never the key it commits to. */
  nextKeyHash: string
}

/** Turns pre-rotation on. Signed by whichever key currently holds updateKeys
 * authority under the ORDINARY (non-pre-rotation) rule, since pre-rotation
 * is not active going into this entry — the last time that key's signature
 * will mean anything for this DID (resolver.ts's own note). */
export async function activatePreRotation(opts: ActivatePreRotationOptions): Promise<void> {
  const { url, entries, last } = await fetchCurrentLog(opts.did)

  const updateKey = encodeMultikey(opts.signingPublicKey)
  if (!(last.parameters.updateKeys ?? []).includes(updateKey)) {
    throw new Error('activatePreRotation: local signing key is not authorized by the document\'s current updateKeys (rotated elsewhere) — restore with the current Root Key phrase/DID to get back in sync')
  }
  if ((last.parameters.nextKeyHashes?.length ?? 0) > 0) {
    throw new Error('activatePreRotation: pre-rotation is already active for this identity')
  }

  const versionTime = nowVersionTime()
  const parameters = parametersToWrite(last.parameters, resolveParameters(last.parameters, { nextKeyHashes: [opts.nextKeyHash] }))
  const state = buildBisetWebvhState(opts.did, opts.identityPublicKey)

  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${updateKey}#${updateKey}`, privateKey: opts.signingPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  await putLog(url, [...entries, entry], [entry])
}

export interface RotateToPreRotatedKeyOptions {
  did: string
  /** The key committed by the CURRENT log entry's nextKeyHashes, revealed
   * now — becomes the new updateKeys AND signs this very entry (safe only
   * because its hash was committed one entry earlier — see this file's
   * header). */
  revealedPrivateKey: Uint8Array
  revealedPublicKey: Uint8Array
  /** The document's OWN identity key (`#key-1`) — independent of updateKeys,
   * same convention as publish.ts's rotateUpdateKeys. Pass the existing one
   * unchanged unless this rotation should also change it. */
  identityPublicKey: Uint8Array
  /** hash(encodeMultikey(nextPublicKey)) for the FOLLOWING round — provide
   * to keep pre-rotation active, omit to deactivate (deactivatePreRotation
   * below is this same function with it left out). */
  nextKeyHash?: string
}

/** Core of both `rotateToPreRotatedKey` and `deactivatePreRotation` — the
 * only difference between them is whether a further commitment is made. */
async function rotateOrDeactivate(opts: RotateToPreRotatedKeyOptions): Promise<void> {
  const { url, entries, last } = await fetchCurrentLog(opts.did)

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
  const state = buildBisetWebvhState(opts.did, opts.identityPublicKey)

  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${revealedKey}#${revealedKey}`, privateKey: opts.revealedPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  await putLog(url, [...entries, entry], [entry])
}

export async function rotateToPreRotatedKey(opts: RotateToPreRotatedKeyOptions & { nextKeyHash: string }): Promise<void> {
  await rotateOrDeactivate(opts)
}

export async function deactivatePreRotation(opts: Omit<RotateToPreRotatedKeyOptions, 'nextKeyHash'>): Promise<void> {
  await rotateOrDeactivate(opts)
}
