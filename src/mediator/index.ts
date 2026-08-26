// Standalone DIDComm mediator entrypoint -- a separate deploy unit from
// biset-core (ARC.md's DIDComm mediator redesign, 2026-08-27): no shared
// process, no shared database, no import from `core/`, `roster/`, or
// `vault/`. Anyone can run this, including biset itself, alongside any
// number of independently-operated others -- that plurality is the whole
// point (PLAN.md's non-centralization goal).
import { loadMediatorIdentity } from './identity.ts'
import { createMediator } from './server.ts'
import { MessageQueue } from './queue.ts'
import { ConnectionStore } from './connections.ts'
import { resolveDidCommSenderKey } from '../didcomm/webvh-resolve.ts'

const httpPort = Number(Bun.env.PORT ?? 8790)
const publicUrl = Bun.env.MEDIATOR_PUBLIC_URL
if (!publicUrl) throw new Error('MEDIATOR_PUBLIC_URL is required (this mediator\'s own reachable https:// URL)')

const dataDir = Bun.env.MEDIATOR_DATA_DIR ?? './mediator-data'
const mediator = loadMediatorIdentity(`${dataDir}/identity.json`, publicUrl)
const queue = new MessageQueue(`${dataDir}/queue.json`)
const connections = new ConnectionStore(`${dataDir}/connections.json`)

// did:webvh senders (biset users) are resolved over plain HTTP against
// their own signed log -- no dependency on any specific biset-core
// deployment, method-generic. A did:peer sender needs no resolver at all
// (self-certifying).
const { handle, mediatorDid } = createMediator({
  mediator, queue, connections,
  resolveDidWebvh: async (_did, kid) => {
    try { return await resolveDidCommSenderKey(kid) } catch { return null }
  },
})

Bun.serve({
  port: httpPort,
  async fetch(req) {
    const url = new URL(req.url)
    const res = await handle(req, url)
    return res ?? new Response('not found', { status: 404 })
  },
})

console.info(`biset mediator listening on :${httpPort} as ${mediatorDid}`)
