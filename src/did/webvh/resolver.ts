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
import type { WebvhDidDocument } from './document.ts'

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
 * non-deactivated state, or null if the DID has no log / is deactivated. */
export async function resolve(did: string): Promise<WebvhDidDocument | null> {
  const url = didToHttpsUrl(did)
  const resp = await fetch(url)
  if (resp.status === 404) return null
  if (!resp.ok) throw new WebvhResolutionError(`resolve: HTTP ${resp.status} fetching ${url}`)
  return resolveEntries(did, parseLog(await resp.text()))
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
    const signingKeys = i === 0 ? parameters.updateKeys : previousParameters.updateKeys
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
