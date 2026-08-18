// did:webvh resolution (DIDWEBVHFEAT.md §8.2, did:webvh v1.0 spec "Read
// (Resolve)"). Fetches the log directly from the URL the DID's own domain
// segment names (didToHttpsUrl) — no separate "anchor" concept needed on the
// client side; routing biset.md/t.biset.md's /dids path to the anchor
// service is an infra concern (PLANWEBVH.md §6), not a client one.
import { didToHttpsUrl, parseWebvhDid } from './identifier.ts'
import {
  parseLog, verifyEntryHash, entryVersionNumber, resolveParameters,
  isVersionTimeMonotonic, isVersionTimeNotTooFarInFuture,
  type LogEntry, type LogParameters,
} from './log.ts'
import { verifyScid } from './scid.ts'
import { verifyProof } from './proof.ts'
import { decodeMultikey } from './multikey.ts'
import { multikeyHashBase58 } from './hash.ts'
import type { WebvhDidDocument } from './document.ts'
import { fetchRouting, type RoutingDoc } from './routing.ts'

export class WebvhResolutionError extends Error {}

// did:key method spec: a verificationMethod id is the full DID URL
// `did:key:{mb}#{mb}` (fragment repeats the same multibase value) —
// verified against didwebvh-rs (the DIF reference implementation), which
// rejects anything else. publish.ts's buildProof now always emits that
// form; the two shorter forms below stay accepted here for reading log
// entries this repo itself signed BEFORE that fix (a resolver, unlike a
// publisher, can't retroactively rewrite an already-published log).
function findSigningKey(proof: LogEntry['proof'][number], candidateKeys: string[]): string | undefined {
  return candidateKeys.find(k =>
    proof.verificationMethod === `did:key:${k}#${k}` ||
    proof.verificationMethod === `did:key:${k}` ||
    proof.verificationMethod === k,
  )
}

/** Resolves a did:webvh identifier: fetches its log and verifies every entry
 * in order — SCID (first entry), entryHash chain, versionTime monotonicity,
 * and a Data Integrity proof valid against the updateKeys the PRIOR entry
 * authorized (the genesis entry authorizes itself). Returns the latest
 * non-deactivated state, or null if the DID has no log / is deactivated.
 *
 * `service`/`keyAgreement`/`name`/`alsoKnownAs` in the returned document all
 * come from routing.json, not the log — document.ts's buildBisetWebvhState
 * writes only `id`/verificationMethod[0]/authentication into the signed
 * state now (that file's own header explains why: none of the rest proves
 * "same identity"), so this merge is what makes every existing reader of a
 * resolved document keep working unchanged, oblivious to where each field
 * actually came from. Fetched from `doc.id`, NOT the `did` argument: after a
 * portable move (webvh/publish.ts's moveDidToNewDomain) the two can differ —
 * resolving the OLD DID string still returns the NEW state.id, and both
 * locations serve the identical log, so resolving either string must land
 * on byte-identical output for did:webvh's portability guarantee to hold.
 * Reading routing.json from the DID string passed in (rather than where the
 * log says the identity actually lives now) would fetch the OLD location's
 * stale routing.json and break that convergence. Best-effort: a routing.json
 * fetch failure degrades to "no extra info" rather than failing the whole
 * resolve — the identity itself (id, root key) is still valid even if its
 * operational data is temporarily unreachable, the same fail-soft stance
 * every reader of `service` already takes for a missing entry. */
export async function resolve(did: string, init?: RequestInit): Promise<WebvhDidDocument | null> {
  const url = didToHttpsUrl(did)
  const resp = await fetch(url, init)
  if (resp.status === 404) return null
  if (!resp.ok) throw new WebvhResolutionError(`resolve: HTTP ${resp.status} fetching ${url}`)
  const doc = resolveEntries(did, parseLog(await resp.text()))
  if (!doc) return null
  const routing = await fetchRouting(doc.id, init).catch(() => null)
  return mergeRouting(doc, routing)
}

/** Splices routing.json's keyAgreement/service/name/alsoKnownAs into a
 * document resolved from the signed log alone. Shared by resolve() (client,
 * fetches routing.json itself) and the anchor's own server-side resolver
 * (anchor/webvh-resolve.ts's resolveWebvhDocumentWithRouting, which reads
 * its own store's routing.json directly, no HTTP round trip) — both need
 * the exact same merge, just from a different-shaped `routing` source.
 *
 * `routing === null` means "no routing.json exists for this identity" —
 * genuinely ambiguous between two very different situations, resolved in
 * favor of the safe one: either a brand-new identity that hasn't published
 * anything yet (nothing to merge, `doc` alone is already complete), OR —
 * the case that matters — an identity that predates routing.ts entirely and
 * still carries its service/keyAgreement/alsoKnownAs/name INLINE in `doc`
 * (document.ts's buildBisetWebvhState used to write them there directly).
 * Discarding those here on a null routing.json, on the theory that "no
 * routing.json = nothing to show", would make every not-yet-republished
 * identity instantly unreachable the moment this merge starts running —
 * service and keyAgreement both wiped even though the exact same data is
 * still sitting right there in `doc`. Returning `doc` untouched in that case
 * costs nothing (a genuinely empty old document stays genuinely empty) and
 * is what actually preserves both situations correctly: nothing to add for
 * the new-and-empty case, nothing lost for the old-and-populated one. Once
 * that identity republishes even once, routing.json starts existing and
 * this function takes the merge branch from then on, same as any other. */
export function mergeRouting(doc: WebvhDidDocument, routing: RoutingDoc | null): WebvhDidDocument {
  if (!routing) return doc
  const kaVms = routing.keyAgreementVerificationMethod ?? []
  const mlkemVms = routing.mlkemVerificationMethod ?? []
  return {
    ...doc,
    verificationMethod: [...doc.verificationMethod, ...kaVms, ...mlkemVms],
    ...(kaVms.length ? { keyAgreement: kaVms.map(vm => vm.id) } : {}),
    // Concatenated, not replaced: `doc.service` from a current-format
    // document is just the one constant `#routing` pointer entry
    // (document.ts's buildBisetWebvhState) — routing.json's own entries add
    // to it rather than overwriting it, so that pointer survives every
    // resolve instead of being wiped out by the same merge that's supposed
    // to be adding MORE service info, not deleting the one entry that says
    // where to find it. (An old-format document's `doc.service` already had
    // its real entries here too, before this pointer scheme existed — same
    // reasoning, concatenation just never had anything to add on top of.)
    service: [...doc.service, ...routing.service],
    alsoKnownAs: routing.alsoKnownAs ?? [],
    ...(routing.name ? { name: routing.name } : {}),
  }
}

/** The verification core of resolve(), split out so a caller that already
 * has the log bytes (the anchor itself, serving its own webvh store —
 * anchor/index.ts's resolveDidWebvh) can verify without an HTTP round trip
 * back to itself — same reasoning as resolveDidDht preferring the anchor's
 * own DHT node over a public gateway. */
export function resolveEntries(did: string, entries: LogEntry[]): WebvhDidDocument | null {
  if (entries.length === 0) throw new WebvhResolutionError('resolve: empty log')

  const { scid: expectedScid } = parseWebvhDid(did)

  let predecessorVersionId = ''
  let previousParameters: LogParameters = {}
  let previousVersionTime = ''
  let previousState: object | null = null
  let latestState: object | null = null
  let matched = false

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!
    if (entryVersionNumber(entry.versionId) !== i + 1) {
      throw new WebvhResolutionError(`resolve: versionId gap at entry ${i + 1} (got ${entry.versionId})`)
    }

    if (i === 0) {
      if (entry.parameters.scid !== expectedScid) throw new WebvhResolutionError('resolve: scid in log does not match DID')
      if (!verifyScid(entry)) throw new WebvhResolutionError('resolve: SCID verification failed')
      predecessorVersionId = entry.parameters.scid!
    } else {
      if (entry.parameters.scid !== undefined) throw new WebvhResolutionError('resolve: scid must only appear in the first entry')
      if (!isVersionTimeMonotonic(previousVersionTime, entry.versionTime)) {
        throw new WebvhResolutionError(`resolve: versionTime not monotonic at entry ${i + 1}`)
      }
    }
    if (!isVersionTimeNotTooFarInFuture(entry.versionTime)) {
      throw new WebvhResolutionError(`resolve: versionTime too far in the future at entry ${i + 1}`)
    }
    if (!verifyEntryHash(entry, predecessorVersionId)) {
      throw new WebvhResolutionError(`resolve: entryHash mismatch at entry ${i + 1}`)
    }

    const parameters = resolveParameters(previousParameters, entry.parameters)

    // The genesis entry authorizes itself (its own updateKeys); every later
    // entry must be signed by a key the PREVIOUS entry authorized, never its
    // own new updateKeys — otherwise a stolen signing key could rotate keys
    // and vouch for its own rotation in the same breath.
    //
    // Pre-rotation (did:webvh v1.0 "Pre-Rotation Key Hash Generation and
    // Verification") inverts this for exactly one step at a time: once an
    // entry commits a non-empty `nextKeyHashes`, the NEXT entry is signed by
    // ITS OWN updateKeys instead of the previous entry's — but only keys
    // whose hash was already committed in that previous entry are allowed
    // there, so revealing+using one now is safe precisely because the
    // commitment happened one entry earlier, before this key was ever
    // exposed. This is what makes a stolen ACTIVE key powerless the moment
    // pre-rotation is active: that key's only remaining authority was
    // spent authoring the entry that committed to a successor it does not
    // control — it can never author anything after that, not even turning
    // pre-rotation back off (deactivation is itself governed by these same
    // rules, since it's just an entry whose new `nextKeyHashes` is `[]`).
    const preRotationActive = i > 0 && (previousParameters.nextKeyHashes?.length ?? 0) > 0
    let signingKeys: string[] | undefined
    if (i === 0) {
      signingKeys = parameters.updateKeys
    } else if (preRotationActive) {
      // No inheritance permitted while pre-rotation is active (spec's own
      // words: "that bypass would defeat the pre-rotation commitment") — an
      // entry that omits either field while the previous entry left
      // pre-rotation active is invalid, not silently carried forward.
      if (entry.parameters.updateKeys === undefined) {
        throw new WebvhResolutionError(`resolve: entry ${i + 1} must explicitly restate updateKeys — pre-rotation is active, inheritance is not permitted`)
      }
      if (entry.parameters.nextKeyHashes === undefined) {
        throw new WebvhResolutionError(`resolve: entry ${i + 1} must explicitly restate nextKeyHashes — pre-rotation is active, inheritance is not permitted`)
      }
      const committed = new Set(previousParameters.nextKeyHashes ?? [])
      for (const key of parameters.updateKeys ?? []) {
        if (!committed.has(multikeyHashBase58(key))) {
          throw new WebvhResolutionError(`resolve: entry ${i + 1}'s updateKeys includes a key not committed in the previous entry's nextKeyHashes`)
        }
      }
      signingKeys = parameters.updateKeys
    } else {
      signingKeys = previousParameters.updateKeys
    }
    if (!signingKeys?.length) throw new WebvhResolutionError(`resolve: no updateKeys to verify entry ${i + 1} against`)
    const { proof, ...unsigned } = entry
    const verified = proof.some(p => {
      const key = findSigningKey(p, signingKeys)
      if (!key) return false
      try { return verifyProof(unsigned, p, decodeMultikey(key)) } catch { return false }
    })
    if (!verified) throw new WebvhResolutionError(`resolve: no valid proof on entry ${i + 1}`)

    // did:webvh v1.0 permits an entry to change the DID's location (its
    // domain/path segments, SCID unchanged — webvh/publish.ts's
    // moveDidToNewDomain) ONLY while the DID is portable. Without this check
    // any holder of the current update key could silently relocate a DID that
    // was never published as portable, which is exactly the guarantee
    // `portable: false` is supposed to make. Compared against the PREVIOUS
    // entry's resolved parameters — the same "authorized by what came before,
    // not by itself" rule the proof check above uses — since `portable` is
    // genesis-only and can never be re-asserted later anyway.
    const previousId = (previousState as { id?: string } | null)?.id
    const currentId = (entry.state as { id?: string }).id
    if (i > 0 && previousId && currentId && currentId !== previousId && !previousParameters.portable) {
      throw new WebvhResolutionError(`resolve: entry ${i + 1} changes the DID's location but the DID is not portable`)
    }

    latestState = parameters.deactivated ? null : entry.state
    if (currentId === did) matched = true

    predecessorVersionId = entry.versionId
    previousParameters = parameters
    previousVersionTime = entry.versionTime
    previousState = entry.state
  }

  if (!matched) throw new WebvhResolutionError('resolve: no entry state.id matches the requested DID')
  return latestState as WebvhDidDocument | null
}
