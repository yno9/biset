// Standalone did:webvh hosting server — run this directly to host any
// did:webvh identity, biset or not (see core.ts's file header). No accounts,
// no mediator, no relay: just the GET/PUT/POST did.jsonl contract, sitting
// behind a normal TLS-terminating reverse proxy (Caddy/nginx) that passes
// Host straight through.
//
// Usage:
//   bun run src/webvh-server/standalone.ts --port 8770 --data-dir ./data
//   bun run src/webvh-server/standalone.ts --port 8770 --data-dir ./data --hostname 127.0.0.1
import { WebvhLogStore } from '../anchor/webvh-store.ts'
import { createWebvhHandler, CORS } from './core.ts'

function parseArgs(argv: string[]): { port: number; dataDir: string; hostname?: string } {
  const args = new Map<string, string>()
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!
    if (a.startsWith('--')) {
      const key = a.slice(2)
      const val = argv[i + 1]
      if (val === undefined || val.startsWith('--')) throw new Error(`--${key} needs a value`)
      args.set(key, val)
      i++
    }
  }
  const port = Number(args.get('port') ?? '8770')
  const dataDir = args.get('data-dir')
  if (!dataDir) throw new Error('--data-dir is required')
  return { port, dataDir, hostname: args.get('hostname') }
}

const { port, dataDir, hostname } = parseArgs(process.argv.slice(2))
const store = new WebvhLogStore(dataDir)
const handle = createWebvhHandler(store)

const server = Bun.serve({
  port,
  hostname,
  idleTimeout: 35,
  async fetch(req) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS })
    const url = new URL(req.url)
    try {
      return await handle(req, url)
    } catch (e) {
      console.error('[webvh-server] unhandled:', e)
      return new Response('internal error\n', { status: 500, headers: { ...CORS, 'Content-Type': 'text/plain; charset=utf-8' } })
    }
  },
})

console.log(`[webvh-server] listening on http://${server.hostname}:${server.port}, data dir ${dataDir}`)
