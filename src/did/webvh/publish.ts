// did:webvh create/update against the URL the DID's domain segment names
// (routed to the anchor by infra — PLANWEBVH.md §6). Mirrors dht/publish.ts's
// role — build + sign a document and send it — but for webvh that means
// appending a new DID Log entry rather than replacing a BEP44 record.
import { ed25519 } from '@noble/curves/ed25519.js'
import { didToHttpsUrl, buildBisetWebvhDid, parseWebvhDid } from './identifier.ts'
import { generateScid, SCID_PLACEHOLDER } from './scid.ts'
import { generateEntryHash, serializeLog, parseLog, entryVersionNumber, resolveParameters, parametersToWrite, type LogEntry, type LogParameters } from './log.ts'
import { buildProof } from './proof.ts'
import { encodeMultikey } from './multikey.ts'
import { buildBisetWebvhState, keyAgreementKeysFromWebvhState, mlkemKeyAgreementKeysFromWebvhState, type WebvhDidDocument, type BuildWebvhStateOpts } from './document.ts'
import { canonicalize } from './jcs.ts'

// Strictly increasing even across back-to-back calls within the same
// process (found live in testing: two updates issued within the same
// second produced an identical versionTime, which resolver.ts's
// monotonicity check then rejects outright — same failure shape
// dht/resolver.ts's nextSafeSeq exists to prevent for BEP44 seq). The +1s
// bump (not wall-clock waiting) covers back-to-back calls without slowing
// anything down — this is a monotonic counter, not a claim about real
// elapsed time, same reasoning dht's seq numbers already lean on.
//
// Whole-seconds precision, NOT milliseconds (2026-07-28, corrected after an
// interop check against didwebvh-rs, the DIF reference implementation, via
// its resolve_file() test entrypoint): didwebvh-rs re-serializes versionTime
// through `DateTime<FixedOffset>` + `to_rfc3339_opts(SecondsFormat::Secs, true)`
// before re-hashing it as part of proof verification (log_entry/mod.rs's
// format_version_time) — millisecond precision survives parsing but is
// always DROPPED on that re-serialize, so a proof signed over a
// millisecond-precision versionTime can never re-hash to the same bytes a
// spec-compliant verifier computes. did:webvh v1.0 itself only requires
// ISO8601 and doesn't forbid fractional seconds, but this asymmetry (kept
// by the signer, discarded by at least this verifier) makes millisecond
// precision a real interop trap in practice, not just a style choice.
let lastIssuedSec = 0
function nowVersionTime(): string {
  const sec = Math.max(Math.floor(Date.now() / 1000), lastIssuedSec + 1)
  lastIssuedSec = sec
  return new Date(sec * 1000).toISOString().replace('.000Z', 'Z')
}

export interface BisetRelay { id: string; serverUrl: string; protocol?: string; address?: string }

export interface CreateGenesisOptions {
  domain: string
  username: string
  rootPrivateKey: Uint8Array
  rootPublicKey: Uint8Array
  relays: BisetRelay[]
  addresses: string | string[]
  /** PLANWEBVH.md §2/§4.1: biset defaults new webvh identities to portable so
   * a later domain move can use the log's own portability mechanism instead
   * of a bare rotation. */
  portable?: boolean
  /** keyAgreement/DIDCommMessaging/removedKeyNs/name — same options
   * buildBisetWebvhState takes directly (didcomm-devices.ts's method-agnostic
   * multi-device logic passes these through when a device is registering
   * DIDComm alongside identity creation). */
  stateOpts?: BuildWebvhStateOpts
}

/** Creates a brand-new did:webvh identity: builds the genesis log entry
 * (placeholder SCID -> real SCID -> real DID), signs it, and PUTs it to the
 * URL the resulting DID's domain segment names. */
export async function createGenesis(opts: CreateGenesisOptions): Promise<{ did: string; scid: string }> {
  const updateKey = encodeMultikey(opts.rootPublicKey)
  const versionTime = nowVersionTime()
  const placeholderDid = buildBisetWebvhDid(SCID_PLACEHOLDER, opts.domain, opts.username)

  const parameters: LogParameters = {
    method: 'did:webvh:1.0',
    scid: SCID_PLACEHOLDER,
    updateKeys: [updateKey],
    nextKeyHashes: [],
    portable: opts.portable ?? true,
    witness: {},
    watchers: [],
    deactivated: false,
    ttl: 3600,
  }
  const state = buildBisetWebvhState(placeholderDid, opts.rootPublicKey, opts.relays, opts.addresses, opts.stateOpts)
  const preliminary = { versionId: SCID_PLACEHOLDER, versionTime, parameters, state }

  const scid = generateScid(preliminary)
  const did = buildBisetWebvhDid(scid, opts.domain, opts.username)
  // Substitute the placeholder everywhere it landed (parameters.scid,
  // state.id, state's verificationMethod/authentication/assertionMethod/
  // service ids, all of which embed the DID) via one whole-document string
  // replace, same approach as scid.ts's verifyScid.
  const real = JSON.parse(JSON.stringify({ parameters, state }).split(SCID_PLACEHOLDER).join(scid)) as {
    parameters: LogParameters
    state: WebvhDidDocument
  }

  const entryHash = generateEntryHash(scid, versionTime, real.parameters, real.state)
  const versionId = `1-${entryHash}`
  const unsigned = { versionId, versionTime, parameters: real.parameters, state: real.state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${updateKey}#${updateKey}`, privateKey: opts.rootPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  const resp = await fetch(didToHttpsUrl(did), {
    method: 'PUT',
    headers: { 'Content-Type': 'text/jsonl' },
    body: serializeLog([entry]),
  })
  if (!resp.ok) throw new Error(`createGenesis: PUT failed with HTTP ${resp.status} ${await resp.text().catch(() => '')}`)

  return { did, scid }
}

export interface UpdateOptions {
  did: string
  rootPrivateKey: Uint8Array
  rootPublicKey: Uint8Array
  relays: BisetRelay[]
  addresses: string | string[]
  stateOpts?: BuildWebvhStateOpts
}

/** Fetches the current log — the shared first half of every update
 * (content-only, key rotation, deactivate...). Exported so callers that need
 * something other than a plain content update (rotateUpdateKeys below) don't
 * duplicate the GET + validation.
 *
 * `last.parameters` is the FULLY RESOLVED value (chained through every entry
 * via resolveParameters), not the raw last entry's own `parameters` — a
 * non-genesis entry legitimately omits any field unchanged from before
 * (log.ts's parametersToWrite, the did:webvh v1.0 inheritance rule), so the
 * raw entry alone can't answer "what are the CURRENT updateKeys" the moment
 * any update has ever gone through. `entries` stays the raw array (what
 * putLog below re-serializes) — only the `last` handed back for callers to
 * READ from is resolved. */
async function fetchCurrentLog(did: string): Promise<{ url: string; entries: LogEntry[]; last: LogEntry }> {
  const url = didToHttpsUrl(did)
  const resp = await fetch(url)
  if (!resp.ok) throw new Error(`fetchCurrentLog: GET failed with HTTP ${resp.status}`)
  const entries = parseLog(await resp.text())
  const rawLast = entries[entries.length - 1]
  if (!rawLast) throw new Error('fetchCurrentLog: log is empty')
  let resolved: LogParameters = {}
  for (const entry of entries) resolved = resolveParameters(resolved, entry.parameters)
  const last: LogEntry = { ...rawLast, parameters: resolved }
  return { url, entries, last }
}

async function putLog(url: string, entries: LogEntry[]): Promise<void> {
  const resp = await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'text/jsonl' }, body: serializeLog(entries) })
  if (!resp.ok) throw new Error(`putLog: PUT failed with HTTP ${resp.status} ${await resp.text().catch(() => '')}`)
}

/** Keeps the display name the log already carries when THIS call has none of
 * its own. A publish can legitimately run from a device with no live relay
 * session for the identity (didcomm-devices.ts's liveRelayInputs returns
 * null, e.g. a DIDComm-only browser, or any device mid-logout), and the
 * document's `name` is the one field such a call has no source for. Without
 * this, every publish from that device would append an entry that DROPS the
 * name, the next publish from a device that does know it would append one
 * that puts it back, and a log that is append-only forever would accumulate
 * that flip-flop permanently.
 *
 * The trade-off is deliberate: an explicit "clear my display name" cannot
 * propagate through here (undefined reads as "I don't know", never as "unset
 * it") — a name reverting to a stale value on every republish is the worse
 * failure of the two, and clearing it still works from any device that has
 * the identity's relay session. */
function withCarriedName(stateOpts: BuildWebvhStateOpts | undefined, last: LogEntry): BuildWebvhStateOpts | undefined {
  if (stateOpts?.name !== undefined) return stateOpts
  const previous = (last.state as WebvhDidDocument | undefined)?.name
  if (!previous) return stateOpts
  return { ...(stateOpts ?? {}), name: previous }
}

/** Read-modify-write: fetches the current log, appends one new entry with an
 * updated state, and PUTs the whole log back. Not append-only PUT — the
 * anchor side is a plain file store with no append/CAS semantics of its own
 * yet (PLANWEBVH.md §6 remaining infra work), so two concurrent updates can
 * race and one can clobber the other. Acceptable for now (biset.md/t.biset.md
 * both single-writer per identity in practice); revisit if that changes.
 *
 * Content-only: the signing key and the key embedded in `state` are the SAME
 * key here (`rootPrivateKey`/`rootPublicKey`) — no key change. For rotating
 * the update key itself, see rotateUpdateKeys below (the two must NOT be
 * conflated: an entry always signs with the PREVIOUS entry's authorized key,
 * never its own new one — resolver.ts's verification rule). */
export async function updateDocument(opts: UpdateOptions): Promise<void> {
  const { url, entries, last } = await fetchCurrentLog(opts.did)

  const state = buildBisetWebvhState(opts.did, opts.rootPublicKey, opts.relays, opts.addresses, withCarriedName(opts.stateOpts, last))
  const updateKey = encodeMultikey(opts.rootPublicKey)

  // A stale local root key must never pass as a no-op success. Content-only
  // rotation (rotateUpdateKeys with the identity key left unchanged) leaves
  // `state` byte-identical to before, so the check below alone can't catch
  // it — checking authorization FIRST closes that gap: a key no longer in
  // the document's current updateKeys is rejected here, loudly, instead of
  // silently reporting success while never having actually verified it could
  // still sign anything (found investigating a live "mediator unusable after
  // rotation" bug, ARC.md 2026-07-27 — this branch used to fall through to
  // the no-op return below and never even attempt (or need) a real publish).
  if (!(last.parameters.updateKeys ?? []).includes(updateKey)) {
    throw new Error('updateDocument: local signing key is not authorized by the document\'s current updateKeys (rotated elsewhere) — restore with the current recovery phrase/DID to get back in sync')
  }

  // No-op when nothing actually changed. did:webvh's log is append-only and
  // has no decay concept at all (unlike did:dht's ~2h BEP44 TTL, the reason
  // THAT method's routine republish is expected to run unconditionally, dead
  // content and all) — calling this with identical content would just
  // permanently bloat the log with a zero-diff entry forever, un-removable.
  // JCS-canonicalize both sides (jcs.ts, the same canonicalization proof.ts
  // and the hash chain already rely on) so `state` being rebuilt fresh every
  // call — plain object, no guaranteed key order — never reads as "changed"
  // over a harmless key-ordering difference alone.
  if (canonicalize(state) === canonicalize(last.state)) return

  const versionTime = nowVersionTime()
  const parameters = parametersToWrite(last.parameters, resolveParameters(last.parameters, {}))

  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${updateKey}#${updateKey}`, privateKey: opts.rootPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  await putLog(url, [...entries, entry])
}

/** Known-issue mitigation (ARC.md "Account & relay flows", 2026-07-26):
 * account-create.ts mints a did:webvh genesis BEFORE attempting to bind its
 * home mail address (the anchor's binding verification can only resolve a
 * root key against an ALREADY-published document — genesis-before-bind is
 * the only order the current protocol supports, see that note for why
 * deferring the publish isn't possible without a deeper anchor+relay
 * redesign). If that mail bind then fails, this stamps the identity
 * deactivated rather than leaving a live, resolvable document that claims an
 * address it never actually got — the confusion two different people's
 * identities could cause if the claimed username and its real owner (if any)
 * later diverge. NOT a retraction: did:webvh logs are append-only, the
 * genesis entry itself stays in history forever — this only flips
 * `parameters.deactivated` going forward, so any future resolver sees "this
 * was never live" instead of a seemingly-valid, unbound claim. State is
 * carried over unchanged from the log's last entry (no relay/address
 * content to revise — this is a status flip, not a content update). */
export async function deactivateDocument(did: string, rootPrivateKey: Uint8Array, rootPublicKey: Uint8Array): Promise<void> {
  const { url, entries, last } = await fetchCurrentLog(did)

  const updateKey = encodeMultikey(rootPublicKey)
  const versionTime = nowVersionTime()
  const parameters = parametersToWrite(last.parameters, resolveParameters(last.parameters, { deactivated: true }))
  const state = last.state

  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${updateKey}#${updateKey}`, privateKey: rootPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  await putLog(url, [...entries, entry])
}

export interface RotateUpdateKeysOptions {
  did: string
  /** The CURRENT key — authorizes this entry (must match the previous
   * entry's updateKeys), does NOT end up in the new parameters.updateKeys. */
  oldPrivateKey: Uint8Array
  /** The NEW key — becomes the sole entry in this entry's
   * parameters.updateKeys, authorizing every SUBSEQUENT entry. Does not sign
   * this entry (DIDWEBVHFEAT.md §7: a stolen key must not be able to rotate
   * to a new key and vouch for its own rotation in the same breath). */
  newPublicKey: Uint8Array
  relays: BisetRelay[]
  addresses: string | string[]
  /** The document's OWN identity key (`state.verificationMethod[0]`, the
   * `#key-1` entry) — independent of the update-signing key rotated here.
   * Callers that also want to rotate the document's identity key pass the
   * new one; otherwise pass the same key the document already has. */
  identityPublicKey: Uint8Array
  stateOpts?: BuildWebvhStateOpts
}

/** DIDWEBVHFEAT.md §7's previously-unimplemented "key rotation body": appends
 * a log entry whose parameters.updateKeys names the NEW key, signed by the
 * OLD one. After this lands, every later update must sign with newPrivateKey
 * instead of oldPrivateKey. */
export async function rotateUpdateKeys(opts: RotateUpdateKeysOptions): Promise<void> {
  const { url, entries, last } = await fetchCurrentLog(opts.did)

  const newUpdateKey = encodeMultikey(opts.newPublicKey)
  const versionTime = nowVersionTime()
  const parameters = parametersToWrite(last.parameters, resolveParameters(last.parameters, { updateKeys: [newUpdateKey] }))
  const state = buildBisetWebvhState(opts.did, opts.identityPublicKey, opts.relays, opts.addresses, withCarriedName(opts.stateOpts, last))

  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  // Signed by the OLD key (still authorized by the previous entry) — never
  // the new one, which this very entry is what makes authorized.
  const oldUpdateKey = encodeMultikey(ed25519.getPublicKey(opts.oldPrivateKey))
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${oldUpdateKey}#${oldUpdateKey}`, privateKey: opts.oldPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  await putLog(url, [...entries, entry])
}

export interface MoveToNewDomainOptions {
  oldDid: string
  newDomain: string
  newUsername: string
  rootPrivateKey: Uint8Array
  rootPublicKey: Uint8Array
  relays: BisetRelay[]
  addresses: string | string[]
  // No `portable` here, deliberately: it is genesis-only (did:webvh v1.0
  // permits setting it in the first entry and nowhere else — log.ts's
  // parametersToWrite), so a move can only ever READ the value the identity
  // was created with, never choose one.
}

/** Domain move (PLANWEBVH.md §5.1/§9) via did:webvh v1.0's OWN portability
 * mechanism: the SCID — and with it biset's internal stable identity key
 * (PLANWEBVH.md §3.1) — is PRESERVED. Unlike rotateUpdateKeys (same DID,
 * different signing key) this changes the DID string itself, but only its
 * domain/path segments; the self-certifying part does not move.
 *
 * Mechanically this is NOT a new genesis: it appends ONE entry to the
 * EXISTING log whose `state.id` names the new location, and writes that one
 * log to BOTH locations. Consequences, all of which fall out of
 * resolver.ts's existing rules rather than needing special cases:
 *
 *  - Resolving the NEW DID fetches the new location, matches the final
 *    entry's `state.id`, and verifies the whole chain back to a genesis that
 *    still hashes to the same SCID.
 *  - Resolving the OLD DID fetches the old location, matches the GENESIS
 *    entry's `state.id`, and returns the LATEST state — i.e. a peer holding
 *    only the old DID automatically follows the move on its next resolve,
 *    with no `alsoKnownAs` pointer-chasing.
 *  - Both locations serve byte-identical logs, so the anchor's append-only
 *    check (anchor/server.ts) sees a legitimate extension at the old
 *    location and a first-ever write at the new one.
 *
 * `from_prior` (didcomm/rotation.ts) is still built by the caller
 * (webvh/move.ts) and still matters: portability is the "re-resolve and
 * you'll find me" path, from_prior the "know immediately, without
 * resolving" path (PLANWEBVH.md §4.1 — they are complementary, not
 * alternatives).
 *
 * This REPLACES an earlier new-genesis implementation that could not
 * preserve the SCID (2026-07-28). That version made the old and new DIDs
 * cryptographically unrelated identities linked only by from_prior, which
 * defeated both `portable: true`'s purpose and §3.1's stable-key design. */
export async function moveDidToNewDomain(opts: MoveToNewDomainOptions): Promise<{ newDid: string; scid: string }> {
  const { url: oldUrl, entries, last } = await fetchCurrentLog(opts.oldDid)

  // did:webvh v1.0 permits a location change only for a portable DID, and
  // `portable` can only ever have been set in the genesis entry (log.ts's
  // parametersToWrite). Checked here rather than left to the resolver: a log
  // that moves a non-portable DID is append-only garbage the moment it lands
  // — every future resolve of it fails forever (same reasoning as the
  // anchor's pre-write verification).
  if (!last.parameters.portable) {
    throw new Error('moveDidToNewDomain: this DID was not created portable — its location cannot be changed')
  }

  const updateKey = encodeMultikey(opts.rootPublicKey)
  if (!(last.parameters.updateKeys ?? []).includes(updateKey)) {
    throw new Error('moveDidToNewDomain: local signing key is not authorized by the document\'s current updateKeys (rotated elsewhere) — restore with the current recovery phrase/DID to get back in sync')
  }

  // Same SCID, new domain/path — the whole point of this operation.
  const { scid } = parseWebvhDid(opts.oldDid)
  const newDid = buildBisetWebvhDid(scid, opts.newDomain, opts.newUsername)

  // Carry the current keyAgreement/DIDComm service forward — a move must not
  // silently drop DIDComm reachability. Any from_prior-unaware peer, or
  // anyone within the from_prior window who simply hasn't re-sent yet, still
  // addresses the OLD DID until they learn otherwise, and after this move the
  // old DID resolves to THIS state; rebuilding it with an empty keyAgreement
  // would strand exactly those messages (found in the e2e test: a message
  // sent just before the move, still unacked in the mediator's queue, failed
  // to authenticate on redelivery once the keyAgreement had vanished).
  //
  // Read from the log we already hold rather than a fresh resolve() — same
  // bytes, one less round trip, and immune to the old location having already
  // been repointed by an earlier partial run.
  const currentState = last.state as WebvhDidDocument
  const currentDidCommSvc = currentState.service?.find(s => s.type === 'DIDCommMessaging')
  const didCommService = currentDidCommSvc
    ? {
      mediatorUrl: Array.isArray(currentDidCommSvc.serviceEndpoint) ? currentDidCommSvc.serviceEndpoint[0]! : currentDidCommSvc.serviceEndpoint,
      routingKey: currentDidCommSvc.routingKeys?.[0] ?? '',
    }
    : undefined

  const state = buildBisetWebvhState(newDid, opts.rootPublicKey, opts.relays, opts.addresses, {
    keyAgreementKeys: keyAgreementKeysFromWebvhState(currentState),
    // Same reasoning as keyAgreementKeys just above — a move must not
    // silently drop the identity's ML-KEM-768 hybrid capability either.
    mlkemKeyAgreementKeys: mlkemKeyAgreementKeysFromWebvhState(currentState),
    didCommService,
    // Same carry-forward reasoning as keyAgreement above, for the display
    // name: a move must not silently reset the identity's name to nothing
    // (which is what every peer's label would fall back to).
    name: currentState.name,
    // The identifier this DID used to be published under. Purely
    // informational for humans and for a peer holding the old string —
    // resolution itself never needs it (the log IS the history), unlike the
    // superseded new-genesis implementation where a pointer was the only
    // link that existed at all.
    movedFrom: opts.oldDid,
  })

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
  await putLog(oldUrl, moved)

  return { newDid, scid }
}
