// biset-anchor: everything a biset identity needs that a single relay cannot
// answer for. ANCHOR.md's migration is finished — this holds all of it now:
//
//   - the claim registry: `localpart+domain → {fingerprint, did}`, which stops
//     one address being split across relays, and answers `by-did` with every
//     address an identity holds
//   - proof that a DID belongs to whoever claims it (didbind.ts). Relays used
//     to check this themselves; they forward it here instead and no relay
//     handles DID material any more
//   - address→DID discovery, via GET /.well-known/webfinger (server.ts's
//     handleWebfinger) — used to be a Cloudflare-published DNS TXT record;
//     answered from data already on disk now, no external credential needed
//     at all (2026-08-17, see that handler's own note for the full history)
//   - the DIDComm mediator, so a client that cannot hold a socket open can
//     still be delivered to
//
// Nothing here handles JMAP, mail or ActivityPub. A relay that sets no
// `anchor_url` runs "anchorless" and never contacts this service — which means
// no DIDs at all, not DIDs without coordination (ANCHOR.md decision 2).
//
// **An anchor is per-operator by construction, and that is load-bearing.** Its
// job is "mail.biset.md and ap.biset.md agree about the same @biset.md" — a
// question that only exists within one operator's domain. Running ONE anchor
// for everybody would hand it every lookup on the network to watch.
//
// Config: `config.json` next to the executable.
//   { "listen_addr": ":8081",          // required
//     "relay_token": "…",              // required; the secret its relays present
//     "mediator_url": "https://…" }    // optional; turns the DIDComm mediator on.
//
// `mediator_url` is a promise, not a setting: it is baked into the mediator's
// did:peer, which is how correspondents learn where to deliver. Changing it
// later changes the DID and strands every client already registered with it.
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve as resolvePath } from 'node:path'
import { ClaimStore } from './store.ts'
import { startAnchor } from './server.ts'
import { createMediator } from './mediator/server.ts'
import { loadMediatorIdentity } from './mediator/identity.ts'
import { ConnectionStore } from './mediator/connections.ts'
import { PushSubscriptionStore } from './mediator/pushsubs.ts'
import { MessageQueue } from './mediator/queue.ts'
import { MlsDeliveryService } from './mediator/mls-ds.ts'
import { fragmentOf, isDeviceKid } from '../did/devicekid.ts'
import { WebvhLogStore } from './webvh-store.ts'
import { resolveWebvhDocumentWithRouting } from './webvh-resolve.ts'
import { keyAgreementKeysFromWebvhState } from '../did/webvh/document.ts'

interface Config {
  listen_addr: string
  /** The secret this anchor's own relays present on every write, as
   * `Authorization: Bearer <token>` (go-jmapserver's AnchorRef).
   *
   * **Required. There is no unauthenticated mode.** This service is on the
   * public internet — the DIDComm mediator has to be reachable by clients — and
   * its registry decides who owns which address. A fingerprint-only claim
   * carries no proof by design (backfill and envelope rotation have no DID to
   * prove), so before this existed "can reach the anchor" was the whole
   * authorization story: anyone could claim a name nobody held, or DELETE the
   * claim of somebody who did and take it, DNS record and all.
   *
   * Making it optional would leave that as the default. src/did/dht/freshness.ts
   * refuses a default for the same reason and throws instead — an implicit
   * fallback is a *quiet* security downgrade, and quiet is what makes it bad. */
  relay_token: string
  /** The mediator's own public URL. Setting it turns the DIDComm mediator on;
   * omitting it leaves the anchor a pure registry. It must be the URL clients
   * can actually reach, because it goes into the mediator's DID — correspondents
   * read it from there to know where to deliver. */
  mediator_url?: string
  /** Web Push for the mediator's queued messages. Without these the mediator
   * queues silently and a closed browser learns nothing until it is reopened —
   * which is why a relay-less (DID⊥relay) identity had no notifications at all.
   *
   * **These MUST be the same keypair the relays are configured with.** A
   * Service Worker registration holds exactly one PushSubscription, bound to
   * the one applicationServerKey it was created with, so a client physically
   * cannot hold a separate subscription for the mediator. Copy the values out
   * of the relays' config.json (mediator/webpush.ts's header). */
  vapid_public_key?: string
  vapid_private_key?: string
  /** RFC 8292 `sub`: a bare email address or an https: URL. Apple's push
   * service 403s a send whose JWT has no usable subject, so this is required
   * alongside the keys, not optional metadata. */
  vapid_subscriber?: string
}

// Beside the executable when compiled (`bun build --compile`), beside this file
// when run from source — matching go-didanchor's filepath.Dir(os.Args[0]).
const baseDir = resolvePath(dirname(process.execPath.includes('bun') ? Bun.main : process.execPath))

function loadConfig(): Config {
  const path = join(baseDir, 'config.json')
  if (!existsSync(path)) {
    console.error(`config: ${path} not found`)
    process.exit(1)
  }
  let cfg: Config
  try {
    cfg = JSON.parse(readFileSync(path, 'utf-8'))
  } catch (e) {
    console.error('config:', e instanceof Error ? e.message : e)
    process.exit(1)
  }
  if (!cfg.listen_addr) {
    console.error('config: listen_addr required')
    process.exit(1)
  }
  if (!cfg.relay_token) {
    console.error('config: relay_token required — without it this anchor\'s registry is writable by anyone who can reach it, and it is reachable by everyone')
    process.exit(1)
  }
  return cfg
}

/** Go's ListenAndServe takes ":8081" or "127.0.0.1:8081"; an empty host means
 * all interfaces. Bun wants them separately. */
function parseListenAddr(addr: string): { hostname?: string; port: number } {
  const i = addr.lastIndexOf(':')
  if (i < 0) return { port: Number(addr) }
  const host = addr.slice(0, i)
  return { hostname: host === '' ? undefined : host, port: Number(addr.slice(i + 1)) }
}

const cfg = loadConfig()
const { hostname, port } = parseListenAddr(cfg.listen_addr)
if (!Number.isInteger(port) || port <= 0) {
  console.error(`config: bad listen_addr ${JSON.stringify(cfg.listen_addr)}`)
  process.exit(1)
}

const dataDir = join(baseDir, 'data')
mkdirSync(dataDir, { recursive: true, mode: 0o700 })

// The DID index is derived from the identity.fp files at startup rather than
// kept on disk — see store.ts for why (the Go service's on-disk copy had
// silently drifted in production and could not self-heal).
const claims = new ClaimStore(dataDir)
console.log(`[anchor] indexed ${claims.rebuildIndex()} DID(s) from ${dataDir}`)

// did:webvh log storage (PLANWEBVH.md §2.1/§2.3) — always on, unlike the
// mediator: it's a plain file store with no external network dependency, so
// there's nothing here worth gating behind a config flag.
const webvh = new WebvhLogStore(dataDir)

// Resolve a did:webvh peer's DIDComm key AT A SPECIFIC device's kid, so the
// mediator can authenticate/encrypt to did:webvh senders (PLANWEBVH.md §5.3).
// webvh-resolve.ts's resolveWebvhDocument tries this anchor's own store
// FIRST (no HTTP round trip back to itself), since that's the common case
// (biset's own users) — falling back to a guarded remote HTTPS resolve for
// anything not found there. A DID hosted on a domain this anchor doesn't own
// at all (a BYO domain, DID⊥relay's own point, or now also
// `authorized_did_domain`'s third-party case) is neither a bug nor rare; the
// mediator must be able to reach ANY did:webvh peer, not just ones this
// anchor happens to also host (found live: a moved-to-BYO-domain identity got
// "unresolvable did:webvh peer" registering with this SAME mediator, because
// only the own-store path existed).
const resolveDidWebvh = async (did: string, kid: string): Promise<Uint8Array | null> => {
  const fragment = fragmentOf(kid)
  if (!isDeviceKid(fragment)) return null
  try {
    const doc = await resolveWebvhDocumentWithRouting(did, webvh)
    return doc ? keyAgreementKeysFromWebvhState(doc).find(k => k.kid === fragment)?.publicKey ?? null : null
  } catch { return null }
}
// All three or nothing: a keypair without a subscriber produces a JWT Apple
// rejects, so half-configured Web Push would look enabled and never deliver.
const vapid = (cfg.vapid_public_key && cfg.vapid_private_key && cfg.vapid_subscriber)
  ? { publicKey: cfg.vapid_public_key, privateKey: cfg.vapid_private_key, subscriber: cfg.vapid_subscriber }
  : undefined
if (cfg.mediator_url && !vapid) {
  console.warn('[anchor] mediator has no vapid_* config — queued messages will not wake a closed client')
}
const mediator = cfg.mediator_url
  ? createMediator({
      mediator: loadMediatorIdentity(join(dataDir, 'mediator-identity.json'), cfg.mediator_url),
      connections: new ConnectionStore(join(dataDir, 'mediator-connections.json')),
      // Undelivered messages survive a restart now (queue.ts): a Forward is
      // answered 202 the moment it is queued, so nothing upstream is still
      // holding a copy to retry with, and every deploy used to eat whatever
      // was in flight.
      queue: new MessageQueue(join(dataDir, 'mediator-queue.json')),
      pushSubs: new PushSubscriptionStore(join(dataDir, 'mediator-push-subs.json')),
      // MLS groups and key packages, persisted for a reason the other stores
      // do not share: losing this is not a delivery that gets retried, it is
      // an identity's DEVICE LIST. A restart with in-memory state drops every
      // group, so every device falls back to publishing only itself, two
      // devices of one identity overwrite each other's document forever, and
      // nothing in the system notices (found live 2026-08-13 — this option was
      // simply never passed, so the default in-memory store was in use in
      // production).
      mlsDs: new MlsDeliveryService(join(dataDir, 'mediator-mls.json')),
      vapid,
      resolveDidWebvh,
    })
  : undefined
if (mediator) console.log(`[anchor] DIDComm mediator at ${cfg.mediator_url} — ${mediator.mediatorDid}${vapid ? ' (Web Push on)' : ''}`)
else console.log('[anchor] no mediator_url — registry only, no DIDComm mediation')

startAnchor({ claims, port, hostname, mediator, webvh, relayToken: cfg.relay_token })
console.log(`[anchor] listening on ${cfg.listen_addr} (data: ${dataDir})`)
