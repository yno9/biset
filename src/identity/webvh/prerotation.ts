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
// Biset identities have pre-rotation active from genesis and never turn it
// off. Rotation promotes the committed Spare Key to Sign Key and commits a
// fresh Spare hash in the same entry.
import { defaultFetch } from '../../net-fetch.ts'
import { encodeMultikey } from './multikey.ts'
import { multikeyHashBase58 } from './hash.ts'
import { generateEntryHash, entryVersionNumber, resolveParameters, parametersToWrite, type LogEntry, type LogParameters } from './log.ts'
import { buildProof } from './proof.ts'
import type { SignedWebvhState } from './document.ts'
import { fetchCurrentLog, putLog, nowVersionTime } from './log-io.ts'

/** The identity's current Spare commitment. An empty or multi-value result
 * violates Biset's permanent pre-rotation invariant. This lets the UI show
 * live feedback matching a typed phrase against the real commitment before
 * ever attempting to sign with it. */
export async function currentNextKeyHashes(did: string, fetch?: typeof globalThis.fetch): Promise<string[]> {
  const { last } = await fetchCurrentLog(did, fetch ?? defaultFetch())
  return last.parameters.nextKeyHashes ?? []
}

export interface RotateToPreRotatedKeyOptions {
  did: string
  /** The key committed by the CURRENT log entry's nextKeyHashes, revealed
   * now — becomes the new updateKeys AND signs this very entry (safe only
   * because its hash was committed one entry earlier — see this file's
   * header). */
  revealedPrivateKey: Uint8Array
  revealedPublicKey: Uint8Array
  /** hash(encodeMultikey(nextPublicKey)) for the following round. */
  nextKeyHash: string
  fetch?: typeof globalThis.fetch
}

/** Consumes the current Spare commitment and installs its replacement in
 * one entry, so nextKeyHashes is never empty. */
export async function rotateToPreRotatedKey(opts: RotateToPreRotatedKeyOptions): Promise<string> {
  if (!opts.nextKeyHash) throw new TypeError('rotateToPreRotatedKey: next Spare Key commitment is required')
  const fetchImpl = opts.fetch ?? defaultFetch()
  const { url, entries, last } = await fetchCurrentLog(opts.did, fetchImpl)

  if ((last.parameters.nextKeyHashes?.length ?? 0) !== 1) {
    throw new Error('rotateToPreRotatedKey: identity does not satisfy permanent pre-rotation invariants')
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
  const parameters: LogParameters = { ...restParameters, updateKeys: [revealedKey], nextKeyHashes: [opts.nextKeyHash] }
  const state = last.state as SignedWebvhState

  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${revealedKey}#${revealedKey}`, privateKey: opts.revealedPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  await putLog(url, [...entries, entry], [entry], fetchImpl)
  return versionId
}
