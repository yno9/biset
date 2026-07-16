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
import { startAnchor } from './server.ts'

interface Config {
  listen_addr: string
  cloudflare_api_token?: string
  cloudflare_zone_id?: string
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
}

const dataDir = join(baseDir, 'data')
mkdirSync(dataDir, { recursive: true, mode: 0o700 })

startAnchor({ dataDir, cloudflare, port, hostname })
console.log(`[anchor] listening on ${cfg.listen_addr} (data: ${dataDir})`)
