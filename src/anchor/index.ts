// biset-anchor: everything a biset identity needs that a single relay cannot
// answer for. ANCHOR.md's migration is finished — this holds all of it now:
//
//   - the claim registry: `localpart+domain → {fingerprint, did}`, which stops
//     one address being split across relays, and answers `by-did` with every
//     address an identity holds
//   - proof that a DID belongs to whoever claims it (didbind.ts). Relays used
//     to check this themselves; they forward it here instead and no relay
//     handles DID material any more
//   - the DNS anchor record, via Cloudflare — the only place that credential is
//     used, which is why this process's blast radius is worth caring about
//   - the Pkarr/DHT gateway that relays' `/pkarr` forwards to, so browsers can
//     read and write did:dht records without speaking UDP
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
//     "cloudflare_api_token": "…",     // optional; omit to record claims without DNS
//     "cloudflare_zone_id":   "…",     // required with the token
//     "pkarr_gateway": true,           // optional; joins the Mainline DHT (UDP)
//     "mediator_url": "https://…" }    // optional; turns the DIDComm mediator on.
//
// `mediator_url` is a promise, not a setting: it is baked into the mediator's
// did:peer, which is how correspondents learn where to deliver. Changing it
// later changes the DID and strands every client already registered with it.
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve as resolvePath } from 'node:path'
import { CloudflareAnchor } from './cloudflare.ts'
import { ClaimStore } from './store.ts'
import { startAnchor, type PkarrRef } from './server.ts'
import { createMediator } from './mediator/server.ts'
import { loadMediatorIdentity } from './mediator/identity.ts'
import { ConnectionStore } from './mediator/connections.ts'
import { PkarrGateway } from './pkarr.ts'
import { zbase32Encode } from '../did/zbase32.ts'
import { resolveVia, identityKeyFromDid, PUBLIC_PKARR_FALLBACKS, type DidDocument } from '../did/resolver.ts'
import { parseSignedPayload } from '../did/packet.ts'

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
   * Making it optional would leave that as the default. src/did/freshness.ts
   * refuses a default for the same reason and throws instead — an implicit
   * fallback is a *quiet* security downgrade, and quiet is what makes it bad. */
  relay_token: string
  cloudflare_api_token?: string
  cloudflare_zone_id?: string
  /** The mediator's own public URL. Setting it turns the DIDComm mediator on;
   * omitting it leaves the anchor a pure registry. It must be the URL clients
   * can actually reach, because it goes into the mediator's DID — correspondents
   * read it from there to know where to deliver. */
  mediator_url?: string
  /** Turns the Pkarr DHT gateway on. Opt-in, mirroring the PKARR_GATEWAY=1 flag
   * go-jmapserver gated its own gateway behind: it opens a UDP socket and joins
   * the Mainline DHT, which an operator should choose deliberately. Relays proxy
   * their /pkarr here when it's on. */
  pkarr_gateway?: boolean
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

const cloudflare = new CloudflareAnchor({ apiToken: cfg.cloudflare_api_token, zoneId: cfg.cloudflare_zone_id })
if (!cloudflare.enabled()) {
  console.log('[anchor] Cloudflare not configured — claims will be recorded but no DNS record written')
} else {
  // Which zone we can write to decides which addresses get a DNS anchor at all
  // (cloudflare.ts: everything outside it is the owner's to publish), so say it
  // out loud at startup rather than leaving it implicit in a zone id. Warn and
  // carry on if Cloudflare is unreachable — claims must not wait on DNS.
  cloudflare.zoneName()
    .then(z => console.log(`[anchor] Cloudflare zone ${z} — addresses outside it get no DNS anchor`))
    .catch(e => console.error('[anchor] Cloudflare zone lookup failed:', e?.message ?? e))
}

const dataDir = join(baseDir, 'data')
mkdirSync(dataDir, { recursive: true, mode: 0o700 })

// The DID index is derived from the identity.fp files at startup rather than
// kept on disk — see store.ts for why (the Go service's on-disk copy had
// silently drifted in production and could not self-heal).
const claims = new ClaimStore(dataDir)
console.log(`[anchor] indexed ${claims.rebuildIndex()} DID(s) from ${dataDir}`)

// The gateway republishes only identities this anchor anchors — the registry is
// the whole definition of "ours". A did:dht IS its public key, so the question
// costs one encode and a map lookup.
const isAnchored = (pubkey: Buffer) => claims.lookupByDid('did:dht:' + zbase32Encode(new Uint8Array(pubkey))).length > 0

// A mutable slot, not an awaited value: PkarrGateway.start() joining the
// Mainline DHT takes several seconds, and this used to be awaited BEFORE the
// HTTP listener opened at all — meaning the entire anchor (mediator inbox,
// claim registry, everything, not just /pkarr) was connection-refused for
// that whole window on every single restart. server.ts's handlePkarr reads
// this fresh on every request (see PkarrRef's own note), so the listener can
// open immediately below while the DHT join happens in the background —
// /pkarr answers a distinguishable 503 ("still starting") rather than either
// a connection refusal or the misleading-forever 404 that meant "no such
// identity" everywhere else it's used.
const pkarrRef: PkarrRef = { starting: !!cfg.pkarr_gateway }

// Resolve a did:dht peer's DIDComm key AT A SPECIFIC device's kid (e.g.
// "did:dht:X#k2") from the DHT, so the mediator can authenticate relay-less
// (did:dht) senders and encrypt replies to them — not just the self-
// certifying did:peer it started with. Kid-aware because a relay-less
// identity can have more than one registered device, each its own entry in
// the document's keyAgreementKeys (document.ts's DidKeyAgreement note) — "the"
// key for a bare DID would be ambiguous once there's more than one.
//
// Tries this anchor's OWN DHT node first (in-process, no HTTP round trip, no
// propagation lag) — it's the freshest possible source for a record a client
// JUST published moments earlier via this same anchor's /pkarr, which a brand
// new device key always is. Falls back to the public pkarr relays only if
// this anchor has no DHT node of its own, or genuinely doesn't have it yet.
// Was public-fallback-only, unconditionally, even though the anchor runs its
// own DHT node right here — a client registering with a fresh device key
// routinely failed mediate-request with "no such key on the DHT" simply
// because relay.pkarr.org/pkarr.pubky.org hadn't caught up yet, despite the
// record being available locally the whole time. Both paths verify the
// record's signature against the DID's own key, so neither can forge, only
// withhold.
const resolveDidDht = async (did: string, kid: string): Promise<Uint8Array | null> => {
  const n = Number(kid.split('#k')[1])
  if (!Number.isFinite(n)) return null
  try {
    let doc: DidDocument | undefined
    if (pkarrRef.current) {
      const pubkey = identityKeyFromDid(did)
      const payload = await pkarrRef.current.get(Buffer.from(pubkey))
      if (payload) {
        try { doc = parseSignedPayload(pubkey, new Uint8Array(payload)).document } catch { /* bad sig — fall through to public gateways */ }
      }
    }
    if (!doc) doc = (await resolveVia(did, PUBLIC_PKARR_FALLBACKS))?.document
    return doc?.keyAgreementKeys?.find(k => k.n === n)?.publicKey ?? null
  } catch { return null }
}
const mediator = cfg.mediator_url
  ? createMediator({
      mediator: loadMediatorIdentity(join(dataDir, 'mediator-identity.json'), cfg.mediator_url),
      connections: new ConnectionStore(join(dataDir, 'mediator-connections.json')),
      resolveDidDht,
    })
  : undefined
if (mediator) console.log(`[anchor] DIDComm mediator at ${cfg.mediator_url} — ${mediator.mediatorDid}`)
else console.log('[anchor] no mediator_url — registry only, no DIDComm mediation')

startAnchor({ claims, cloudflare, port, hostname, mediator, pkarr: pkarrRef, relayToken: cfg.relay_token })
console.log(`[anchor] listening on ${cfg.listen_addr} (data: ${dataDir})`)

if (cfg.pkarr_gateway) {
  PkarrGateway.start(dataDir, isAnchored)
    .then(g => {
      pkarrRef.current = g
      console.log('[pkarr] gateway enabled — joined the Mainline DHT')
    })
    .catch(e => console.error('[pkarr] failed to join the Mainline DHT:', e instanceof Error ? e.message : e))
    .finally(() => { pkarrRef.starting = false })
} else {
  console.log('[pkarr] no pkarr_gateway — registry only, no DHT')
}
