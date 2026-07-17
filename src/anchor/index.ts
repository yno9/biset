// biset-anchor: the identity registry. Its only job today is claim/verify
// `localpart+domain → {fingerprint, did}`, and — when a DID is present — keep
// that binding's DNS anchor record current via Cloudflare. Nothing here handles
// JMAP, mail, or ActivityPub: a relay that doesn't configure an anchor_url runs
// "anchorless" and never contacts this service (ARC.md / ANCHOR.md).
//
// This is **step 1** of ANCHOR.md's staged migration: behaviour-identical to
// the deployed `go-didanchor`, reading the same files, answering the same
// routes, so it can be swapped in (and back out) by changing `anchor_url`
// alone. The DIDComm mediator, the pkarr gateway, binding verification and the
// DID→address index all move here **later**, only once this has proven itself.
//
// Config: `config.json` next to the executable, same shape as go-didanchor's.
//   { "listen_addr": ":8081",
//     "cloudflare_api_token": "…",   // optional; omit to record claims without DNS
//     "cloudflare_zone_id":   "…" }
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve as resolvePath } from 'node:path'
import { CloudflareAnchor } from './cloudflare.ts'
import { ClaimStore } from './store.ts'
import { startAnchor } from './server.ts'
import { createMediator } from './mediator/server.ts'
import { loadMediatorIdentity } from './mediator/identity.ts'
import { PkarrGateway } from './pkarr.ts'

interface Config {
  listen_addr: string
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

const mediator = cfg.mediator_url
  ? createMediator({ mediator: loadMediatorIdentity(join(dataDir, 'mediator-identity.json'), cfg.mediator_url) })
  : undefined
if (mediator) console.log(`[anchor] DIDComm mediator at ${cfg.mediator_url} — ${mediator.mediatorDid}`)
else console.log('[anchor] no mediator_url — registry only, no DIDComm mediation')

// Started before listening: joining the DHT takes a moment, and answering
// /pkarr with a 404 in the meantime would look to a client exactly like "this
// identity does not exist" rather than "ask again shortly".
const pkarr = cfg.pkarr_gateway ? await PkarrGateway.start(dataDir) : undefined
if (pkarr) console.log('[pkarr] gateway enabled — joined the Mainline DHT')
else console.log('[pkarr] no pkarr_gateway — registry only, no DHT')

startAnchor({ claims, cloudflare, port, hostname, mediator, pkarr })
console.log(`[anchor] listening on ${cfg.listen_addr} (data: ${dataDir})`)
