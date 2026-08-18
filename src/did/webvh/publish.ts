// did:webvh create/update against the URL the DID's domain segment names
// (routed to the anchor by infra — PLANWEBVH.md §6). Mirrors dht/publish.ts's
// role — build + sign a document and send it — but for webvh that means
// appending a new DID Log entry rather than replacing a BEP44 record.
import { ed25519 } from '@noble/curves/ed25519.js'
import { didToHttpsUrl, buildBisetWebvhDid } from './identifier.ts'
import { generateScid, SCID_PLACEHOLDER } from './scid.ts'
import { generateEntryHash, entryVersionNumber, resolveParameters, parametersToWrite, serializeLog, type LogEntry, type LogParameters } from './log.ts'
import { buildProof } from './proof.ts'
import { encodeMultikey } from './multikey.ts'
import { buildBisetWebvhState, keyAgreementKeysFromWebvhState, mlkemKeyAgreementKeysFromWebvhState, type WebvhDidDocument, type DidMlkemKeyAgreement } from './document.ts'
import type { DidKeyAgreement } from '../document.ts'
import { canonicalize } from './jcs.ts'
import { firstServiceEndpoint } from '../../utils.ts'
import { fetchCurrentLog, putLog, nowVersionTime } from './log-io.ts'
import { migrateWebvhLocation } from './migrate.ts'
import { buildRoutingDoc, fetchRouting, putRouting } from './routing.ts'
import { resolve as resolveWebvh } from './resolver.ts'

export { fetchCurrentLog, putLog, nowVersionTime }

export interface BisetRelay { id: string; serverUrl: string; protocol?: string; address?: string }

/** Everything routing.ts's buildRoutingDoc needs beyond `relays`/`addresses`
 * — shared across createGenesis/updateDocument since both feed the same
 * sibling resource, never the signed log (document.ts's own header). */
export interface RoutingExtras {
  didCommService?: { mediatorUrl: string; routingKey: string }
  keyAgreementKeys?: DidKeyAgreement[]
  mlkemKeyAgreementKeys?: DidMlkemKeyAgreement[]
  name?: string
}

export interface CreateGenesisOptions extends RoutingExtras {
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
  const state = buildBisetWebvhState(placeholderDid, opts.rootPublicKey)
  const preliminary = { versionId: SCID_PLACEHOLDER, versionTime, parameters, state }

  const scid = generateScid(preliminary)
  const did = buildBisetWebvhDid(scid, opts.domain, opts.username)
  // Substitute the placeholder everywhere it landed (parameters.scid,
  // state.id, state's verificationMethod/authentication ids, all of which
  // embed the DID) via one whole-document string replace, same approach as
  // scid.ts's verifyScid.
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

  // routing.ts: everything except id/#key-1/authentication never enters the
  // signed log — seed the sibling resource right after genesis so the
  // identity is reachable immediately, not just resolvable.
  await putRouting(
    did,
    buildRoutingDoc(did, {
      relays: opts.relays, addresses: opts.addresses, didCommService: opts.didCommService,
      keyAgreementKeys: opts.keyAgreementKeys, mlkemKeyAgreementKeys: opts.mlkemKeyAgreementKeys, name: opts.name,
    }),
    { updateKey, privateKey: opts.rootPrivateKey },
  )

  return { did, scid }
}

export interface UpdateOptions extends RoutingExtras {
  did: string
  /** Whichever key currently holds updateKeys authority — signs this entry
   * (if one ends up needed) and authorizes the routing.json write. Equal to
   * identityPublicKey below for every identity that has never diverged the
   * two (the overwhelming common case: no pre-rotation, or pre-rotation
   * activated but never yet rotated) — but once pre-rotation has moved
   * updateKeys away from #key-1, THIS is the key that must be supplied, not
   * the identity's root key (webvh/method-ops.ts's publishFull always
   * defaults to rec.rootPublicKey here, which is correct until it isn't —
   * see left-pane.ts's Sync retry for the case where it no longer is). */
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  /** #key-1, the document's own identity key — independent of updateKeys,
   * same convention as prerotation.ts's activate/rotate/revoke. Always
   * rec.rootPublicKey; never the signing key when the two have diverged. */
  identityPublicKey: Uint8Array
  relays: BisetRelay[]
  addresses: string | string[]
}

/** Read-modify-write: fetches the current log, appends one new entry with an
 * updated state, and PUTs the whole log back. Not append-only PUT — the
 * anchor side is a plain file store with no append/CAS semantics of its own
 * yet (PLANWEBVH.md §6 remaining infra work), so two concurrent updates can
 * race and one can clobber the other. Acceptable for now (biset.md/t.biset.md
 * both single-writer per identity in practice); revisit if that changes.
 *
 * The signing key and the key embedded in `state` (#key-1) are independent —
 * signingPrivateKey/signingPublicKey vs identityPublicKey, see UpdateOptions.
 * For rotating the update key itself, see rotateUpdateKeys below (the two
 * must NOT be conflated there either: an entry always signs with the
 * PREVIOUS entry's authorized key, never its own new one — resolver.ts's
 * verification rule).
 *
 * In ordinary operation (identityPublicKey never itself changes) this now
 * appends NOTHING: `state` is built from just `did`/identityPublicKey
 * (document.ts's buildBisetWebvhState), so it is byte-identical to
 * `last.state` on every call that isn't an actual root-key change — meaning
 * the no-op check below fires every time, and the ONLY thing this function
 * ends up doing is the routing.json write. That is the intended effect, not
 * a bug: relay changes, device (de)registration, and display-name edits
 * used to append a log entry each; now none of them do. */
export async function updateDocument(opts: UpdateOptions): Promise<void> {
  const { url, entries, last } = await fetchCurrentLog(opts.did)

  const state = buildBisetWebvhState(opts.did, opts.identityPublicKey)
  const updateKey = encodeMultikey(opts.signingPublicKey)

  // A stale local signing key must never pass as a no-op success. Content-only
  // rotation (rotateUpdateKeys with the identity key left unchanged) leaves
  // `state` byte-identical to before, so the check below alone can't catch
  // it — checking authorization FIRST closes that gap: a key no longer in
  // the document's current updateKeys is rejected here, loudly, instead of
  // silently reporting success while never having actually verified it could
  // still sign anything (found investigating a live "mediator unusable after
  // rotation" bug, ARC.md 2026-07-27 — this branch used to fall through to
  // the no-op return below and never even attempt (or need) a real publish).
  // The same gate covers the routing.json write just below: a rotated-out
  // key must not be able to redirect this identity's mail/DIDComm delivery,
  // plant a fake device key, or rewrite its name, even though that write
  // never touches the signed log.
  if (!(last.parameters.updateKeys ?? []).includes(updateKey)) {
    throw new Error('updateDocument: local signing key is not authorized by the document\'s current updateKeys (rotated elsewhere) — restore with the current Root Key phrase/DID to get back in sync')
  }

  // Keeps the display name routing.json already carries when THIS call has
  // none of its own. A publish can legitimately run from a device with no
  // live relay session for the identity (didcomm-devices.ts's
  // liveRelayInputs returns null, e.g. a DIDComm-only browser, or any device
  // mid-logout), and `name` is the one field such a call has no source for.
  // Every OTHER field here (relays, didCommService, keyAgreementKeys) is
  // rebuilt from scratch on every call by design — an absent one IS a
  // removal (registerWithMediator's Phase 1 relies on exactly this for
  // didCommService) — name is the one deliberate exception, the same
  // reasoning as before this lived in document.ts's own state.
  const previousName = opts.name === undefined ? (await fetchRouting(opts.did).catch(() => null))?.name : undefined
  await putRouting(
    opts.did,
    buildRoutingDoc(opts.did, {
      relays: opts.relays, addresses: opts.addresses, didCommService: opts.didCommService,
      keyAgreementKeys: opts.keyAgreementKeys, mlkemKeyAgreementKeys: opts.mlkemKeyAgreementKeys,
      name: opts.name ?? previousName,
    }),
    { updateKey, privateKey: opts.signingPrivateKey },
  )

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
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${updateKey}#${updateKey}`, privateKey: opts.signingPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  await putLog(url, [...entries, entry], [entry])
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
 * carried over unchanged from the log's last entry — a status flip, not a
 * content update. */
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

  await putLog(url, [...entries, entry], [entry])
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
  /** The document's OWN identity key (`state.verificationMethod[0]`, the
   * `#key-1` entry) — independent of the update-signing key rotated here.
   * Callers that also want to rotate the document's identity key pass the
   * new one; otherwise pass the same key the document already has. */
  identityPublicKey: Uint8Array
}

/** DIDWEBVHFEAT.md §7's previously-unimplemented "key rotation body": appends
 * a log entry whose parameters.updateKeys names the NEW key, signed by the
 * OLD one. After this lands, every later update must sign with newPrivateKey
 * instead of oldPrivateKey.
 *
 * Never touches routing.json: rotation changes who is authorized to sign,
 * not the document's content, and routing.json's own signature is verified
 * against did.jsonl's CURRENT updateKeys only at write time (server.ts's
 * handleRouting), never re-checked on read — so an unrotated routing.json
 * already published under the old key stays servable exactly as before. */
export async function rotateUpdateKeys(opts: RotateUpdateKeysOptions): Promise<void> {
  const { url, entries, last } = await fetchCurrentLog(opts.did)

  const newUpdateKey = encodeMultikey(opts.newPublicKey)
  const versionTime = nowVersionTime()
  const parameters = parametersToWrite(last.parameters, resolveParameters(last.parameters, { updateKeys: [newUpdateKey] }))
  const state = buildBisetWebvhState(opts.did, opts.identityPublicKey)

  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  // Signed by the OLD key (still authorized by the previous entry) — never
  // the new one, which this very entry is what makes authorized.
  const oldUpdateKey = encodeMultikey(ed25519.getPublicKey(opts.oldPrivateKey))
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${oldUpdateKey}#${oldUpdateKey}`, privateKey: opts.oldPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  await putLog(url, [...entries, entry], [entry])
}

export interface MoveToNewDomainOptions {
  oldDid: string
  newDomain: string
  newUsername: string
  // The identity key (#key-1) — ALWAYS the Root Key, never the Spare Key,
  // even when pre-rotation is active: buildBisetWebvhState below names this
  // key as the identity's own authentication method regardless of who
  // currently signs log entries.
  identityPublicKey: Uint8Array
  // Whichever key signs THIS entry and (routing.json) the new location's
  // seed write — the Root Key when pre-rotation has never diverged from it,
  // or the just-revealed Spare Key while it's active (migrate.ts's own
  // note). Equal to identityPublicKey/rootPrivateKey in the common case.
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  // Required, and only meaningful, while pre-rotation is active — see
  // migrate.ts's MigrateLocationOptions.nextKeyHash.
  nextKeyHash?: string
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
 * Thin biset-specific wrapper around migrate.ts's migrateWebvhLocation — the
 * protocol-level "append one entry whose state.id names a new location, write
 * that one log to both locations" mechanism, which knows nothing about
 * relays, mediators, or usernames, is shared with any did:webvh identity
 * (biset's or not). The signed state itself carries nothing beyond
 * id/#key-1/authentication now, so this wrapper's own job shrinks to: seed
 * the NEW location's routing.json (relays/addresses from the caller,
 * everything else carried forward from the OLD identity's current resolved
 * state), and record `movedFrom` there instead of in the document.
 *
 * `from_prior` (didcomm/rotation.ts) is still built by the caller
 * (webvh/move.ts) and still matters: portability is the "re-resolve and
 * you'll find me" path, from_prior the "know immediately, without
 * resolving" path (PLANWEBVH.md §4.1 — they are complementary, not
 * alternatives). */
export async function moveDidToNewDomain(opts: MoveToNewDomainOptions): Promise<{ newDid: string; scid: string }> {
  // Resolved (log + routing.json merged, resolver.ts's resolve) rather than
  // read off the raw log entry: keyAgreement/DIDCommMessaging/name all live
  // in routing.json now, and resolve() already knows how to find them — a
  // move must not silently drop any of it (an e2e test once caught exactly
  // this for DIDComm reachability: a message sent just before a move, still
  // unacked in the mediator's queue, failed to authenticate on redelivery
  // once the keyAgreement had vanished).
  const resolved = await resolveWebvh(opts.oldDid).catch(() => null)
  const oldDidCommSvc = resolved?.service.find(s => s.type === 'DIDCommMessaging')
  const didCommService = oldDidCommSvc
    ? {
      // Either shape: DIDComm v2's nested object (current) or the flat form a
      // document published before that carries (document.ts's WebvhService).
      mediatorUrl: firstServiceEndpoint(oldDidCommSvc.serviceEndpoint),
      routingKey: (typeof oldDidCommSvc.serviceEndpoint === 'object' && !Array.isArray(oldDidCommSvc.serviceEndpoint)
        ? oldDidCommSvc.serviceEndpoint.routingKeys?.[0]
        : undefined) ?? oldDidCommSvc.routingKeys?.[0] ?? '',
    }
    : undefined

  const updateKey = encodeMultikey(opts.signingPublicKey)

  const result = await migrateWebvhLocation({
    oldDid: opts.oldDid,
    newDomain: opts.newDomain,
    newPathSegments: [opts.newUsername],
    signingPrivateKey: opts.signingPrivateKey,
    signingPublicKey: opts.signingPublicKey,
    nextKeyHash: opts.nextKeyHash,
    // Nothing to carry through the SIGNED state any more (it is just
    // id/#key-1/authentication) — the new location gets a fresh minimal
    // state naming the same identity key, full stop. Always the Root Key,
    // never the signer of this particular entry (opts.identityPublicKey's
    // own note above).
    buildState: (_carried, newDid) => buildBisetWebvhState(newDid, opts.identityPublicKey),
    // Seed the new location's routing.json — mediator/keyAgreement/name
    // carried forward above plus the caller's current relay list, the same
    // way createGenesis seeds a brand-new identity's — BEFORE the old
    // location is told about the move (migrate.ts's own note on this hook
    // explains why: this can only run here, never earlier, and a failure
    // here must not leave the move half-announced). If this throws, the OLD
    // DID simply keeps resolving to the pre-move document, unaware anything
    // was attempted; the caller can retry the whole moveDidToNewDomain call
    // once whatever failed (network, anchor) recovers.
    afterNewLocationWritten: async newDid => {
      await putRouting(
        newDid,
        buildRoutingDoc(newDid, {
          relays: opts.relays, addresses: opts.addresses, didCommService,
          keyAgreementKeys: resolved ? keyAgreementKeysFromWebvhState(resolved) : undefined,
          mlkemKeyAgreementKeys: resolved ? mlkemKeyAgreementKeysFromWebvhState(resolved) : undefined,
          name: resolved?.name,
          // The identifier this DID used to be published under. Purely
          // informational for humans and for a peer holding the old string —
          // resolution itself never needs it (the log IS the history),
          // unlike the superseded new-genesis implementation where a
          // pointer was the only link that existed at all.
          movedFrom: opts.oldDid,
        }),
        { updateKey, privateKey: opts.signingPrivateKey },
      )
    },
  })

  return result
}
