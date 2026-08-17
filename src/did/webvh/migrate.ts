// Abstract, interoperable did:webvh location migration — the protocol-level
// half of a domain move, independent of what the document's `state` actually
// carries. Unlike publish.ts's biset-specific moveDidToNewDomain (relays,
// addresses, JMAPRelay services...), this file knows nothing about what any
// field in `state` MEANS. It only knows the one rule did:webvh v1.0's
// `portable` mechanism actually specifies: append one log entry whose
// `state.id` (and everything else that embeds the DID as a prefix —
// verificationMethod/service/keyAgreement ids) names a new location, write
// that one log to both locations, done.
//
// Any did:webvh identity can migrate through this — a biset one, a stranger's
// hand-rolled document, an identity minted by a wholly different
// implementation — as long as its host serves the plain GET/PUT/POST
// did.jsonl contract (anchor/server.ts's handleWebvh is one such host, not
// the only one that could be).
import { buildWebvhDid, parseWebvhDid } from './identifier.ts'
import { generateEntryHash, entryVersionNumber, resolveParameters, parametersToWrite, type LogEntry } from './log.ts'
import { buildProof } from './proof.ts'
import { encodeMultikey } from './multikey.ts'
import type { WebvhDidDocument } from './document.ts'
import { fetchCurrentLog, putLog, nowVersionTime } from './log-io.ts'
import { didToHttpsUrl } from './identifier.ts'

export interface MigrateLocationOptions {
  oldDid: string
  newDomain: string
  newPort?: number
  /** Omitted (or empty) targets the domain apex (`.well-known/did.jsonl`) —
   * same convention didToHttpsUrl already uses. */
  newPathSegments?: string[]
  rootPrivateKey: Uint8Array
  rootPublicKey: Uint8Array
  /** Runs AFTER the automatic old-DID→new-DID string substitution that
   * carries every id (verificationMethod/service/keyAgreement) forward
   * byte-for-byte. Most callers should leave this unset — the whole point of
   * a location-only migration is to change WHERE the document lives, not
   * what it says. A caller that also wants to change content in the SAME
   * entry (biset's relay-list swap on move, publish.ts's moveDidToNewDomain)
   * can do so here; `state.id` is re-applied afterward regardless, so this
   * hook cannot accidentally leave the document pointing at the old
   * location. */
  buildState?: (carriedState: WebvhDidDocument, newDid: string) => object
  /** Runs after the NEW location's did.jsonl is written but BEFORE the OLD
   * location is told about the move (the second `putLog` below) — the one
   * point where a caller can still back out cleanly. biset's
   * moveDidToNewDomain (webvh/publish.ts) uses this to seed the new
   * location's routing.json: that write can only succeed once the new
   * location's did.jsonl already exists (the anchor's own auth check reads
   * it to find the current updateKeys), so it cannot happen any earlier —
   * and if it fails, throwing here skips the old-location append entirely,
   * so the OLD DID keeps resolving to the pre-move document exactly as
   * before, never advertising a move to a location that isn't fully live
   * yet. Without this hook, a routing.json failure AFTER the move was
   * already announced to both locations would leave the new DID resolvable
   * but without any connectivity info until a caller retried it. */
  afterNewLocationWritten?: (newDid: string) => Promise<void>
}

/** Migrates a portable did:webvh identity to a new domain/path, preserving
 * its SCID (did:webvh v1.0's own portability mechanism — not a new genesis).
 * Mechanically: fetch the current log, append one entry whose state is the
 * current one with every embedded DID reference rewritten to the new
 * location, and write the resulting log to both the new location (full PUT,
 * nothing there yet) and the old one (append, so a peer holding only the old
 * DID string keeps resolving and lands on the new state). */
export async function migrateWebvhLocation(opts: MigrateLocationOptions): Promise<{ newDid: string; scid: string }> {
  const { url: oldUrl, entries, last } = await fetchCurrentLog(opts.oldDid)

  // did:webvh v1.0 permits a location change only for a portable DID, and
  // `portable` can only ever have been set in the genesis entry. A log that
  // moves a non-portable DID is append-only garbage the moment it lands —
  // every future resolve of it fails forever — so this is checked here
  // rather than left to the resolver.
  if (!last.parameters.portable) {
    throw new Error('migrateWebvhLocation: this DID was not created portable — its location cannot be changed')
  }

  const updateKey = encodeMultikey(opts.rootPublicKey)
  if (!(last.parameters.updateKeys ?? []).includes(updateKey)) {
    throw new Error('migrateWebvhLocation: local signing key is not authorized by the document\'s current updateKeys (rotated elsewhere) — restore with the current Root Key phrase/DID to get back in sync')
  }

  const { scid } = parseWebvhDid(opts.oldDid)
  const newDid = buildWebvhDid({ scid, domain: opts.newDomain, port: opts.newPort, pathSegments: opts.newPathSegments })

  // Pure whole-document string substitution — the same technique
  // createGenesis uses for its SCID placeholder swap. Every id in the
  // document embeds the DID as a prefix, so replacing the DID string
  // wholesale rewrites all of them consistently without this function
  // needing to know what any of those fields mean. This is what makes the
  // migration "abstract": it works identically whether `state` carries
  // biset's JMAPRelay services, a stranger's ActivityPub actor, or nothing
  // at all beyond the bare verificationMethod every did:webvh document must
  // have.
  const carried = JSON.parse(JSON.stringify(last.state).split(opts.oldDid).join(newDid)) as WebvhDidDocument
  const state: object = { ...(opts.buildState ? opts.buildState(carried, newDid) : carried), id: newDid }

  const versionTime = nowVersionTime()
  const parameters = parametersToWrite(last.parameters, resolveParameters(last.parameters, {}))
  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${updateKey}#${updateKey}`, privateKey: opts.rootPrivateKey, created: versionTime })
  const moved = [...entries, { ...unsigned, proof: [proof] } as LogEntry]

  // NEW location first. If it fails, the old location is untouched and the
  // identity is still wholly intact where it was — whereas repointing the old
  // location first and then failing would leave the DID resolvable only to a
  // location serving nothing.
  await putLog(didToHttpsUrl(newDid), moved)
  // See afterNewLocationWritten's own note: this must run, and must succeed,
  // strictly between the two putLog calls — after the new location exists
  // (a dependency, not just an ordering preference) and before the old
  // location is told to point at it (so a failure here never leaves the
  // move half-announced).
  if (opts.afterNewLocationWritten) await opts.afterNewLocationWritten(newDid)
  await putLog(oldUrl, moved, [moved[moved.length - 1]!])

  return { newDid, scid }
}
