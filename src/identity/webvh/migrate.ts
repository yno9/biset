// Abstract, interoperable did:webvh location migration — the protocol-level
// half of a domain move, independent of what the document's `state` actually
// carries. It only knows the one rule did:webvh v1.0's `portable` mechanism
// actually specifies: append one log entry whose `state.id` (and everything
// else that embeds the DID as a prefix — verificationMethod/service/
// keyAgreement ids) names a new location, write that one log to both
// locations, done.
//
// Any did:webvh identity can migrate through this — a biset one, a
// stranger's hand-rolled document, an identity minted by a wholly different
// implementation — as long as its host serves the plain GET/PUT/POST
// did.jsonl contract (anchor/webvh/did-web-http.ts's routing is one such
// host, not the only one that could be).
//
// Ported verbatim from src.bak/did/webvh/migrate.ts — the string-
// substitution approach already carries every existing verificationMethod
// entry forward untouched (including device keys this rewrite's
// add-device-verification-method.ts adds to the signed log, unlike
// src.bak's own minimal log), so unlike prerotation.ts's port this one
// needed no fix for that.
import { buildWebvhDid, parseWebvhDid, didToHttpsUrl } from './identifier.ts'
import { generateEntryHash, entryVersionNumber, resolveParameters, parametersToWrite, type LogEntry } from './log.ts'
import { buildProof } from './proof.ts'
import { encodeMultikey } from './multikey.ts'
import { multikeyHashBase58 } from './hash.ts'
import type { WebvhDidDocument } from './document.ts'
import { fetchCurrentLog, putLog, nowVersionTime } from './log-io.ts'
import { defaultFetch } from '../../net-fetch.ts'

export interface MigrateLocationOptions {
  oldDid: string
  newDomain: string
  newPort?: number
  /** Whichever key currently holds updateKeys authority: the Root Key when
   * pre-rotation has never diverged updateKeys from it (the common case,
   * checked below against the log's CURRENT updateKeys), or — while
   * pre-rotation is ACTIVE — the just-revealed Spare Key committed in the
   * current entry's nextKeyHashes. There is no third option: resolver.ts's
   * active-pre-rotation rule forbids inheriting updateKeys at all, so any
   * OTHER key is rejected below before ever reaching the network. */
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  /** Required, and ONLY valid, while pre-rotation is active — the hash of a
   * FRESH Spare Key to commit for the FOLLOWING round, since inheriting the
   * old commitment is forbidden the same as inheriting updateKeys (this
   * migration entry has to explicitly restate both, exactly like
   * prerotation.ts's rotateOrDeactivate does for an ordinary rotate). Omit
   * when pre-rotation is off — the moved entry simply carries the same
   * (empty) nextKeyHashes forward. */
  nextKeyHash?: string
  /** Runs AFTER the automatic old-DID→new-DID string substitution that
   * carries every id (verificationMethod/service/keyAgreement) forward
   * byte-for-byte. Most callers should leave this unset — the whole point of
   * a location-only migration is to change WHERE the document lives, not
   * what it says. */
  buildState?: (carriedState: WebvhDidDocument, newDid: string) => object
  /** Runs after the NEW location's did.jsonl is written but BEFORE the OLD
   * location is told about the move (the second `putLog` below) — the one
   * point where a caller can still back out cleanly. identity/webvh/move.ts
   * uses this to seed the new location's routing.json: that write can only
   * succeed once the new location's did.jsonl already exists (the anchor's
   * own auth check reads it to find the current updateKeys), so it cannot
   * happen any earlier — and if it fails, throwing here skips the
   * old-location append entirely, so the OLD DID keeps resolving to the
   * pre-move document exactly as before, never advertising a move to a
   * location that isn't fully live yet. */
  afterNewLocationWritten?: (newDid: string) => Promise<void>
  fetch?: typeof globalThis.fetch
}

/** Migrates a portable did:webvh identity to a new domain, preserving its
 * SCID (did:webvh v1.0's own portability mechanism — not a new genesis).
 * Mechanically: fetch the current log, append one entry whose state is the
 * current one with every embedded DID reference rewritten to the new
 * location, and write the resulting log to both the new location (full PUT,
 * nothing there yet) and the old one (append, so a peer holding only the old
 * DID string keeps resolving and lands on the new state). */
export async function migrateWebvhLocation(opts: MigrateLocationOptions): Promise<{ newDid: string; scid: string; versionId: string }> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  const { entries, last } = await fetchCurrentLog(opts.oldDid, fetchImpl)

  // did:webvh v1.0 permits a location change only for a portable DID, and
  // `portable` can only ever have been set in the genesis entry. A log that
  // moves a non-portable DID is append-only garbage the moment it lands —
  // every future resolve of it fails forever — so this is checked here
  // rather than left to the resolver.
  if (!last.parameters.portable) {
    throw new Error('migrateWebvhLocation: this DID was not created portable — its location cannot be changed')
  }

  const updateKey = encodeMultikey(opts.signingPublicKey)
  const preRotationActive = (last.parameters.nextKeyHashes?.length ?? 0) > 0
  if (preRotationActive) {
    if (!opts.nextKeyHash) {
      throw new Error('migrateWebvhLocation: pre-rotation is active for this identity — a fresh Spare Key commitment (nextKeyHash) is required to append any entry, including a move')
    }
    const committed = new Set(last.parameters.nextKeyHashes ?? [])
    if (!committed.has(multikeyHashBase58(updateKey))) {
      throw new Error('migrateWebvhLocation: this key does not match the identity\'s current pre-rotation commitment — wrong Spare Key phrase, or someone else already rotated')
    }
  } else if (!(last.parameters.updateKeys ?? []).includes(updateKey)) {
    throw new Error('migrateWebvhLocation: local signing key is not authorized by the document\'s current updateKeys (rotated elsewhere) — restore with the current Root Key phrase/DID to get back in sync')
  }

  const { scid } = parseWebvhDid(opts.oldDid)
  const newDid = buildWebvhDid({ scid, domain: opts.newDomain, port: opts.newPort })

  // Pure whole-document string substitution — the same technique
  // createGenesis.ts uses for its SCID placeholder swap. Every id in the
  // document embeds the DID as a prefix, so replacing the DID string
  // wholesale rewrites all of them consistently without this function
  // needing to know what any of those fields mean.
  const carried = JSON.parse(JSON.stringify(last.state).split(opts.oldDid).join(newDid)) as WebvhDidDocument
  const state: object = { ...(opts.buildState ? opts.buildState(carried, newDid) : carried), id: newDid }

  const versionTime = nowVersionTime()
  // No inheritance permitted while pre-rotation is active (resolver.ts's own
  // rule, this file's header) — updateKeys/nextKeyHashes are forced explicit
  // here rather than left to parametersToWrite's usual diff, same as
  // prerotation.ts's rotateOrDeactivate does for an ordinary rotate. Off:
  // unchanged from before, plain inheritance via resolveParameters.
  const restParameters = parametersToWrite(last.parameters, resolveParameters(last.parameters, {}))
  const parameters = preRotationActive
    ? { ...restParameters, updateKeys: [updateKey], nextKeyHashes: [opts.nextKeyHash!] }
    : restParameters
  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${updateKey}#${updateKey}`, privateKey: opts.signingPrivateKey, created: versionTime })
  const moved = [...entries, { ...unsigned, proof: [proof] } as LogEntry]

  // NEW location first. If it fails, the old location is untouched and the
  // identity is still wholly intact where it was — whereas repointing the
  // old location first and then failing would leave the DID resolvable only
  // to a location serving nothing.
  await putLog(didToHttpsUrl(newDid), moved, undefined, fetchImpl)
  // See afterNewLocationWritten's own note: this must run, and must succeed,
  // strictly between the two putLog calls.
  if (opts.afterNewLocationWritten) await opts.afterNewLocationWritten(newDid)
  await putLog(didToHttpsUrl(opts.oldDid), moved, [moved[moved.length - 1]!], fetchImpl)

  return { newDid, scid, versionId }
}
