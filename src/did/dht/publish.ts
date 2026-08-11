// Client-side "keep my DID record alive" — build each identity's did:dht
// document (relay list + address) from its stored root key and publish it to
// that identity's own relays' gateways. Called best-effort on app start and
// after account creation: DHT records expire in hours, and the client re-put is
// the backstop that keeps a DID resolvable even if every relay is down when the
// owner next opens biset (DID.md republish rules). No-op when a gateway is
// disabled (PKARR_GATEWAY off) — the PUT just fails and is swallowed.
import { identityIds, relaysForId, isApRelay, isDidCommRelay } from '../../context.ts'
import * as identityStore from '../../store/identities.ts'
import { getDidRecord, withDidLock } from '../store.ts'
import { buildBisetDocument, keyAgreementKeysFromHex, kidN } from './document.ts'
import { publishDocument, PUBLIC_PKARR_FALLBACKS } from './resolver.ts'
import { hexToBytes } from '../../utils.ts'

// The display name to publish in the DID document (biset extension, see
// document.ts) — reuses the same JMAP Identity.name the "Change display
// name" modal already sets (left-pane.ts), rather than inventing a separate
// DID-specific name to manage. An identity can span several relays/addresses;
// take the first one that has a name set at all.
export function displayNameFor(relaySessions: Array<{ account: { email: string } }>): string | undefined {
  for (const s of relaySessions) {
    const name = identityStore.all().find(i => i.email === s.account.email)?.name
    if (name) return name
  }
  return undefined
}


export function relayId(serverUrl: string): string {
  try { return new URL(serverUrl).hostname.split('.')[0] } catch { return 'relay' }
}

export function gatewayUrl(serverUrl: string): string {
  return serverUrl.replace(/\/$/, '') + '/pkarr'
}

// The one place that decides which gateways a DIDComm-related publish or
// resolve goes through: this identity's own relays (if any) and its own
// mediator's pkarr gateway (if registered — anchor/server.ts's /pkarr, open
// to anyone, see its own note on why that's safe) — self-owned resources,
// used whenever there's at least one. The public fallbacks are the LAST
// resort, only when this identity has neither (a relay-less, mediator-less
// did:dht) — user-reported (2026-07-27): this used to fan every publish out
// to the public chain unconditionally, in ADDITION to any self-owned
// gateway, including on every single boot for any did:dht identity with a
// mediator (reassertKeylistRegistration, channel.ts) — real, avoidable load
// on shared infrastructure biset doesn't operate and free-rides on (ARC.md's
// "Why did:dht?" section). One well-behaved gateway is enough: the DHT's own
// peer-to-peer replication is what actually provides resilience once a
// record lands anywhere, not redundant writes through every known door (see
// ARC.md: a still-referenced DID keeps resolving through the DHT directly
// even if every biset-run gateway disappeared, until its own ~2h TTL).
export function didCommGateways(relaySessions: Array<{ account: { serverUrl: string } }>, mediatorUrl?: string): string[] {
  const out = new Set(relaySessions.map(s => gatewayUrl(s.account.serverUrl)))
  if (mediatorUrl) out.add(`${mediatorUrl.replace(/\/$/, '')}/pkarr`)
  if (out.size === 0) for (const gw of PUBLIC_PKARR_FALLBACKS) out.add(gw)
  return [...out]
}

export interface OwnDocument {
  doc: ReturnType<typeof buildBisetDocument>
  gateways: string[]
  rootPrivateKey: Uint8Array
}

// Build this identity's current document from its stored key + LIVE relay set
// — the live sessions are the source of truth for "which relays serve me
// right now", never whatever happens to be published on the DHT already.
// Anything wanting to publish a variant of this document (e.g. adding a
// DIDComm _k1 + service, didcomm/register.ts) must start here rather than
// resolve-and-append: a resolve can transiently fail, and treating that as
// "no relays" would republish a document that erases the identity's real
// relay/address list — which is exactly what happened to a real account
// before this was unified (PLAN.md).
//
// Null when this DEVICE has no live relay session for this identity right
// now — not the same as "this identity has no relay at all": a device mid-
// logout (its own last relay already spliced out of sessions[]) must not
// treat that as "build with empty services", or a routine republish from
// exactly this state would broadcast a higher-seq document that wipes every
// relay OTHER devices still legitimately serve (found live, see
// unregister-last-relay-services-preserved.test.ts). Callers that need to
// publish SOMETHING for an identity with no live session at all —
// didcomm-devices.ts's publishBareOrCurrent, for the explicit "Republish"
// action on an identity with zero relays ever, or a device with no session
// right now — resolve the currently-published document and carry its
// services forward instead of asking this function to guess.
//
// `skipSync` bypasses the syncDevicePosition resolve-and-remerge below for
// this one build — needed by didcomm-devices.ts's removeDeviceKey: it
// edits rec.didCommSiblingKeys directly to drop an entry, and syncDevicePosition
// is grow-only by design, so calling it here would re-absorb that very entry
// off the still-stale published document before the removal ever reaches the
// network, undoing the deletion in the same call meant to perform it.
export async function buildOwnDocument(did: string, opts?: { skipSync?: boolean }): Promise<OwnDocument | null> {
  return withDidLock(did, () => buildOwnDocumentLocked(did, opts))
}

async function buildOwnDocumentLocked(did: string, opts?: { skipSync?: boolean }): Promise<OwnDocument | null> {
  const rec = await getDidRecord(did)
  if (!rec) return null
  // relaysForId(did) includes the synthetic DIDComm session (did/didcomm/
  // channel.ts) on purpose — that's what lets the SAME "which endpoints does
  // this identity have" lookup drive both message routing and this document
  // build. But it has no real relay behind it (serverUrl is the 'didcomm:'
  // sentinel, no actual HTTP endpoint) — treating it as a relay here
  // published a bogus service entry with serverUrl:'didcomm:' into the
  // identity's OWN DID document, and fed a literal 'didcomm:/pkarr' into
  // gateway lists used to resolve OTHER people's DIDs (every browser rejects
  // fetching an unsupported URL scheme outright). The identity's real
  // DIDComm service is added separately by did/didcomm/register.ts, not via
  // this generic per-relay services loop.
  const relaySessions = relaysForId(did).filter(s => !isDidCommRelay(s.account.serverUrl))
  if (!relaySessions.length) return null
  // Each endpoint carries its own protocol + address, so an AP relay and an
  // SMTP relay of one DID can advertise different addresses (see DidService).
  const services = relaySessions.map(s => ({
    id: relayId(s.account.serverUrl),
    serverUrl: s.account.serverUrl,
    protocol: isApRelay(s.account.serverUrl) ? 'activitypub' : 'mail',
    address: s.account.email,
  }))
  // didCommGateways always includes the public fallbacks — this function's
  // routine republish (publishOwnDids, every single boot) used to build its
  // own narrower list (relay gateways only) and so never pushed to them at
  // all, unlike the rarer explicit "Register with mediator" flow. Left them
  // dependent purely on organic DHT propagation from this identity's own
  // relay/anchor announce, which is real but was consistently, indefinitely
  // behind in practice (found live: two independently-operated public
  // gateways serving the same stale seq no matter how much later they were
  // asked, while this identity's own anchor was already current) — plausibly
  // their own read-side caching, entirely outside biset's control either way.
  // A direct PUT is the one thing guaranteed to actually reach them, so send
  // it every time this identity's document changes, not just occasionally.
  const gateways = didCommGateways(relaySessions, rec.didCommMediatorUrl)
  // All addresses of this identity (a moved identity spans several; zero for
  // an identity with no relay at all yet) — did is the key, not an address,
  // so it never appears here itself.
  const addresses = [...new Set(relaySessions.map(s => s.account.email))]
  const doc = buildBisetDocument(rec.did, hexToBytes(rec.rootPublicKey), services, addresses, displayNameFor(relaySessions))

  // Carry the DIDComm layer (this device's key + every known sibling device's
  // key + the mediator it's registered with, all from the local record) into
  // every publish. This function is the ONLY builder — publishOwnDids runs it
  // on every app start — so anything it omits gets republished away: without
  // this, registering with a mediator would silently un-register itself the
  // next time biset opened.
  //
  // Refreshed here, not just read from the cache: a device that registered
  // BEFORE a sibling existed never learned about it, and every one of ITS OWN
  // later boots republished a document that had simply never heard of the
  // other device — silently erasing it, since whichever device boots (i.e.
  // reopens its browser tab) more recently always wins the highest-seq race.
  // Found live: two of one identity's own browsers, unable to reach each
  // other, because the routine republish path never resolved to relearn
  // siblings (that used to only happen once, at registration time). This
  // reuses didcomm-devices.ts's syncDevicePosition — dynamic import to
  // avoid a static cycle (that file already dynamic-imports buildOwnDocument
  // from here) — which is safe to call repeatedly by design: best-effort, and
  // it only ever grows the sibling cache, never removes an entry, so a
  // resolve that fails or a gateway that's simply behind can't erase a real
  // device the way rebuilding the list from scratch would.
  if (rec.didCommOwnKid && !opts?.skipSync) {
    const { syncDevicePosition } = await import('../didcomm-devices.ts')
    await syncDevicePosition(rec, gateways).catch(() => {}) // best-effort — mutates + persists rec in place
  }
  const keyAgreementKeys = keyAgreementKeysFromHex(
    rec.didCommPublicKey && rec.didCommOwnKid ? { kid: rec.didCommOwnKid, publicKeyHex: rec.didCommPublicKey } : null,
    (rec.didCommSiblingKeys ?? []).map(s => ({ kid: s.kid, publicKeyHex: s.publicKey })),
  )
  if (keyAgreementKeys.length) doc.keyAgreementKeys = keyAgreementKeys
  // Carry forward whatever this device knows has been removed (document.ts's
  // removedKeyNs note) — every republish keeps propagating it to any sibling
  // that hasn't heard yet, the same way keyAgreementKeys itself propagates
  // sibling additions.
  if (rec.didCommRemovedKeys?.length) doc.removedKeyNs = rec.didCommRemovedKeys.map(kidN)
  // Gated on there being a key to reach, not just on a mediator being on
  // record — the service and the keyAgreement list stand or fall together
  // (didcomm-devices.ts's publishCurrentState carries the full reasoning and
  // the live incident). This builder always constructs the document from
  // scratch, so simply not pushing the entry IS the removal.
  if (keyAgreementKeys.length && rec.didCommMediatorUrl && rec.didCommRoutingKey) {
    doc.service.push({
      id: 'didcomm', type: 'DIDCommMessaging',
      serviceEndpoint: [rec.didCommMediatorUrl],
      accept: ['didcomm/v2'],
      routingKeys: [rec.didCommRoutingKey],
    })
  }
  return { doc, gateways, rootPrivateKey: hexToBytes(rec.rootPrivateKey) }
}

// Build + publish, returning how many gateways accepted the record. Shared by
// the automatic and manual paths.
//
// Deliberately does NOT swallow errors. `0` means only the two benign,
// expected outcomes — nothing to publish (no DID record / no connected
// relay), or every gateway refused a well-formed record. Anything else (a
// document that can't be built or signed, a chain whose continuation
// couldn't be placed) throws, because those mean the identity CANNOT
// publish, ever, until something is fixed, and some callers of this run
// automatically (no UI to report into) — swallowing them let a real
// account's document sit unpublished and decay out of the DHT (~2h TTL) with
// no signal anywhere. See PLAN.md's incident notes.
async function publishOne(did: string): Promise<number> {
  const own = await buildOwnDocument(did)
  if (!own) return 0
  return await publishDocument(own.rootPrivateKey, own.doc, own.gateways)
}

// NOT called at boot — publishing is opt-in, not automatic (see
// [[project_biset_did_relay_orthogonality]]'s published/unpublished design):
// an identity with a registered DIDComm mediator is kept alive by
// setupDidCommChannel's reassertKeylistRegistration instead (channel.ts),
// which republishes the FULL document (relay services if any, plus the
// DIDComm layer) whenever hasDidCommChannel() is true, and does nothing when
// it isn't. Remaining callers are explicit user actions (the account page's
// "Republish" button, via publishOneVisible) or a direct consequence of a
// mutation that changed the document's own contents (a relay removed, a
// display name changed) — never a routine keep-alive.
export async function publishOwnDids(): Promise<void> {
  for (const did of identityIds()) {
    // Per-identity best-effort: one identity's failure must not stop the
    // rest, but it must not disappear either.
    try {
      await publishOne(did)
    } catch (e) {
      console.error(`[did/publish] ${did}: DID document could not be published —`, e)
    }
  }
}

// Manual "Republish to DHT" action: true if at least one gateway accepted it,
// false if every gateway refused. Throws (with the real reason) when the
// document itself is the problem — the caller shows that reason rather than
// reporting every failure as "no gateway reachable", which is what it used
// to do even when the truth was e.g. "too big to sign".
export async function publishOneVisible(did: string): Promise<boolean> {
  return (await publishOne(did)) > 0
}
