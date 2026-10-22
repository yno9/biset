// What v2 admin asks of the mediator: what it holds (counts and sizes, never what is in a message, which it cannot read). It lives on
// the mediator's own port, answers only a caller with the bearer token v2 admin shares with it, and with no token file there is no
// admin interface at all. (The reverse proxy passes every path through, so the token is the whole lock: without it, 404.)
import { readFileSync } from 'node:fs'
import { timingSafeEqual } from 'node:crypto'
import type { SqliteMediatorStore } from './sqlite-store.ts'

export function createMediatorAdminApi(options: { store: SqliteMediatorStore; tokenFile?: string }): (request: Request, url: URL) => Promise<Response | undefined> {
  const tokenFile = options.tokenFile ?? process.env.V2_ADMIN_TOKEN_FILE ?? '/etc/v2-admin/tokens/mediator'
  const token = (): string | null => { try { return readFileSync(tokenFile, 'utf8').trim() || null } catch { return null } }
  const allowed = (request: Request): boolean => {
    const expected = token()
    if (!expected) return false
    const given = /^Bearer (.+)$/.exec(request.headers.get('authorization') ?? '')?.[1] ?? ''
    const a = Buffer.from(given), b = Buffer.from(expected)
    return a.length === b.length && timingSafeEqual(a, b)
  }
  return async (request, url) => {
    if (!url.pathname.startsWith('/admin/')) return undefined
    if (!allowed(request) || request.method !== 'GET' || url.pathname !== '/admin/metrics') return new Response('not found\n', { status: 404 })
    const stats = options.store.stats()
    const oldest = stats.oldestQueuedAt === undefined ? 0 : Math.max(0, Math.round((Date.now() - stats.oldestQueuedAt) / 1000))
    return new Response(JSON.stringify({ metrics: {
      inboxes: { label: 'Device inboxes', value: stats.inboxes, kind: 'gauge' },
      recipients: { label: 'Recipient DIDs', value: stats.recipients, kind: 'gauge' },
      queuedMessages: { label: 'Messages waiting', value: stats.queuedMessages, kind: 'gauge' },
      queuedKiB: { label: 'Bytes waiting', value: Math.round(stats.queuedBytes / 1024), unit: 'KiB', kind: 'gauge' },
      pendingDeliveries: { label: 'Copies waiting for an ack', value: stats.pendingDeliveries, kind: 'gauge' },
      oldestSeconds: { label: 'Oldest message waiting', value: oldest, unit: 's', kind: 'gauge' },
    } }), { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } })
  }
}
