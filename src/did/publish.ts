// Client-side "keep my DID record alive" — build each identity's did:dht
// document (relay list + address) from its stored root key and publish it to
// that identity's own relays' gateways. Called best-effort on app start and
// after account creation: DHT records expire in hours, and the client re-put is
// the backstop that keeps a DID resolvable even if every relay is down when the
// owner next opens biset (DID.md republish rules). No-op when a gateway is
// disabled (PKARR_GATEWAY off) — the PUT just fails and is swallowed.
import { identities, relaysFor, isApRelay, isDidCommRelay } from '../context.ts'
import * as identityStore from '../store/identities.ts'
import { getDidRecord, withDidLock } from './store.ts'
import { buildBisetDocument, keyAgreementKeysFromHex, kidN } from './document.ts'
import { publishDocument, PUBLIC_PKARR_FALLBACKS } from './resolver.ts'
import { hexToBytes } from '../utils.ts'

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


function relayId(serverUrl: string): string {
  try { return new URL(serverUrl).hostname.split('.')[0] } catch { return 'relay' }
}

export function gatewayUrl(serverUrl: string): string {
  return serverUrl.replace(/\/$/, '') + '/pkarr'
}

// The one place that decides which gateways a DIDComm-related publish or
// resolve goes through: this identity's own relays (if any), its own
// mediator's pkarr gateway (if registered — anchor/server.ts's /pkarr, open
// to anyone, see its own note on why that's safe), and the public fallbacks.
// Was three near-identical constructions across this file and
// create-standalone.ts, each independently deciding which of those three
// sources to include — which is exactly how the public fallbacks ended up
// missing from the most frequently-run one (buildOwnDocument's routine
// republish) while every other caller had them. One function, one list,
// used everywhere a DIDComm gateway list is needed.
export function didCommGateways(relaySessions: Array<{ account: { serverUrl: string } }>, mediatorUrl?: string): string[] {
  const out = new Set(relaySessions.map(s => gatewayUrl(s.account.serverUrl)))
  if (mediatorUrl) out.add(`${mediatorUrl.replace(/\/$/, '')}/pkarr`)
  for (const gw of PUBLIC_PKARR_FALLBACKS) out.add(gw)
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
// `skipSync` bypasses the syncDevicePosition resolve-and-remerge below for
// this one build — needed by create-standalone.ts's removeDeviceKey: it
// edits rec.didCommSiblingKeys directly to drop an entry, and syncDevicePosition
// is grow-only by design, so calling it here would re-absorb that very entry
// off the still-stale published document before the removal ever reaches the
// network, undoing the deletion in the same call meant to perform it.
export async function buildOwnDocument(email: string, opts?: { skipSync?: boolean }): Promise<OwnDocument | null> {
  return withDidLock(email, () => buildOwnDocumentLocked(email, opts))
}

async function buildOwnDocumentLocked(email: string, opts?: { skipSync?: boolean }): Promise<OwnDocument | null> {
  const rec = await getDidRecord(email)
  if (!rec) return null
  // relaysFor(email) includes the synthetic DIDComm session (did/didcomm/
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
  const relaySessions = relaysFor(email).filter(s => !isDidCommRelay(s.account.serverUrl))
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
  // All addresses of this identity (a moved identity spans several), the
  // representative `email` first as the primary a contact should deliver to.
  const addresses = [email, ...new Set(relaySessions.map(s => s.account.email))].filter((a, i, arr) => arr.indexOf(a) === i)
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
  // reuses create-standalone.ts's syncDevicePosition — dynamic import to
  // avoid a static cycle (that file already dynamic-imports buildOwnDocument
  // from here) — which is safe to call repeatedly by design: best-effort, and
  // it only ever grows the sibling cache, never removes an entry, so a
  // resolve that fails or a gateway that's simply behind can't erase a real
  // device the way rebuilding the list from scratch would.
  if (rec.didCommOwnKid && !opts?.skipSync) {
    const { syncDevicePosition } = await import('./create-standalone.ts')
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
  if (rec.didCommMediatorUrl && rec.didCommRoutingKey) {
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
// publish, ever, until something is fixed — and this is the only automatic
// publish path, so swallowing them let a real account's document sit
// unpublished and decay out of the DHT (~2h TTL) with no signal anywhere.
// See PLAN.md's incident notes.
async function publishOne(email: string): Promise<number> {
  const own = await buildOwnDocument(email)
  if (!own) return 0
  return await publishDocument(own.rootPrivateKey, own.doc, own.gateways)
}

export async function publishOwnDids(): Promise<void> {
  for (const email of identities()) {
    // Per-identity best-effort: one identity's failure must not stop the
    // rest, but it must not disappear either. This runs on every app start
    // with no UI to report into, so the console is where a permanently
    // unpublishable document becomes findable at all.
    try {
      await publishOne(email)
    } catch (e) {
      console.error(`[did/publish] ${email}: DID document could not be published —`, e)
    }
  }
}

// Manual "Republish to DHT" action: true if at least one gateway accepted it,
// false if every gateway refused. Throws (with the real reason) when the
// document itself is the problem — the caller shows that reason rather than
// reporting every failure as "no gateway reachable", which is what it used
// to do even when the truth was e.g. "too big to sign".
export async function publishOneVisible(email: string): Promise<boolean> {
  return (await publishOne(email)) > 0
}
