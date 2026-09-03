// did:webvh resolution (DIDWEBVHFEAT.md §8.2, did:webvh v1.0 spec "Read
// (Resolve)"). Fetches the log directly from the URL the DID's own domain
// segment names — no separate "anchor" concept needed on the client side.
//
// Read-only subset of biset's original resolver (src.bak/did/webvh/resolver.ts):
// this module exists to answer one question — "what Ed25519 keys does this
// DID currently list in verificationMethod?" — for MLS's Authentication
// Service role (PLANMLSARCH.md §3) and for the roster's
// DeviceSigningPublicKeyResolver (PLAN.md §2.2). It does not merge
// routing.json (keyAgreement/service/alsoKnownAs/name are biset-specific
// operational data the signed log never carries — see the original
// document.ts's header); a resolved document here therefore has an empty
// `service`/`alsoKnownAs` and no `keyAgreement`, which is correct for
// verificationMethod-only callers and wrong for anything that needs DIDComm
// routing data.
import { didToHttpsUrl, domainDidJsonlUrl, parseWebvhDid } from './identifier.ts'
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

export class WebvhResolutionError extends Error {}

// did:key method spec: a verificationMethod id is the full DID URL
// `did:key:{mb}#{mb}` (fragment repeats the same multibase value) —
// verified against didwebvh-rs (the DIF reference implementation), which
// rejects anything else. The two shorter forms below stay accepted here for
// reading log entries signed before biset's publisher settled on that form.
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
export async function resolve(did: string, init?: RequestInit): Promise<WebvhDidDocument | null> {
  const url = didToHttpsUrl(did)
  const resp = await fetch(url, init)
  if (resp.status === 404) return null
  if (!resp.ok) throw new WebvhResolutionError(`resolve: HTTP ${resp.status} fetching ${url}`)
  return resolveEntries(did, parseLog(await resp.text()))
}

/** Resolves an identity's CURRENT did:webvh update keys -- the same
 * authority a routing.json/did.jsonl update itself must sign with (Root, or
 * its post-rotation successor). Reuses `resolveEntries`'s own full verified
 * walk (SCID, entryHash chain, proof-against-predecessor-authorized-keys)
 * so this carries the identical trust `resolve()` itself does; the only
 * difference is what gets returned -- `resolveEntries` computes and then
 * discards the final `parameters.updateKeys` on its way to building a
 * WebvhDidDocument, so this re-walks the SAME already-parsed, already-
 * verified entries with the cheap, non-cryptographic `resolveParameters`
 * merge (no separate trust decision, just reading back a value the prior
 * call already established was authentic). Used by a caller that needs to
 * verify a signature was made by "whoever currently controls this
 * identity" without needing a full WebvhDidDocument (mail-plugin's outbound
 * submission auth: see mediator/mail-plugin/mail-submission-http.ts). */
export async function resolveCurrentUpdateKeys(did: string, init?: RequestInit): Promise<string[]> {
  const url = didToHttpsUrl(did)
  const resp = await fetch(url, init)
  if (resp.status === 404) return []
  if (!resp.ok) throw new WebvhResolutionError(`resolveCurrentUpdateKeys: HTTP ${resp.status} fetching ${url}`)
  const entries = parseLog(await resp.text())
  if (!resolveEntries(did, entries)) return [] // deactivated -- anything else invalid already threw
  let resolved: LogParameters = {}
  for (const entry of entries) resolved = resolveParameters(resolved, entry.parameters)
  return resolved.updateKeys ?? []
}

/** Resolves a subdomain-per-identity did:webvh (no `pathSegments`) from its
 * bare domain alone, with no DID string needed up front — the caller reads
 * `state.id` off the fetched genesis entry to learn the DID and its SCID,
 * same trust boundary as `resolve()` since `resolveEntries` still verifies
 * every entry against ITS OWN embedded `scid`. This is what a
 * recovery-phrase login uses: the phrase alone re-derives the root key, not
 * the DID string (`identity/bootstrap.ts`'s `restoreIdentity`). */
export async function resolveByDomain(domain: string, port?: number, init?: RequestInit): Promise<WebvhDidDocument | null> {
  const url = domainDidJsonlUrl(domain, port)
  const resp = await fetch(url, init)
  if (resp.status === 404) return null
  if (!resp.ok) throw new WebvhResolutionError(`resolveByDomain: HTTP ${resp.status} fetching ${url}`)
  const entries = parseLog(await resp.text())
  if (entries.length === 0) throw new WebvhResolutionError('resolveByDomain: empty log')
  const did = (entries[0]!.state as { id?: string }).id
  if (!did) throw new WebvhResolutionError('resolveByDomain: genesis entry has no state.id')
  return resolveEntries(did, entries)
}

/** The verification core of resolve(), split out so a caller that already
 * has the log bytes can verify without an HTTP round trip. */
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
    // and vouch for its own rotation in the same breath. Pre-rotation
    // inverts this for exactly one step once an entry commits a non-empty
    // `nextKeyHashes` — see RFC and the original resolver for the full
    // reasoning; this port keeps the same rule.
    const preRotationActive = i > 0 && (previousParameters.nextKeyHashes?.length ?? 0) > 0
    let signingKeys: string[] | undefined
    if (i === 0) {
      signingKeys = parameters.updateKeys
    } else if (preRotationActive) {
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

    // did:webvh v1.0 permits an entry to change the DID's location only
    // while the DID is portable. Compared against the PREVIOUS entry's
    // resolved parameters, since `portable` is genesis-only.
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
  if (latestState === null) return null
  const state = latestState as Partial<WebvhDidDocument>
  return {
    '@context': state['@context'] ?? [],
    id: (state as { id: string }).id,
    verificationMethod: state.verificationMethod ?? [],
    authentication: state.authentication ?? [],
    ...(state.keyAgreement ? { keyAgreement: state.keyAgreement } : {}),
    service: state.service ?? [],
    alsoKnownAs: state.alsoKnownAs ?? [],
    ...(state.name ? { name: state.name } : {}),
  }
}
