// A real mediator (createMediator over an in-memory SqliteMediatorStore --
// the production store, not a test double) plus the wire helpers the
// mediator tests share.
import { expect } from 'bun:test'
import { generatePeerIdentity, type PeerIdentity } from '../../src/protocol/didcomm/peer.ts'
import { createMediator, type LiveSocket, type MediatorHandler } from '../../src/server/mediator/server.ts'
import { SqliteMediatorStore, type SqliteMediatorLimits } from '../../src/server/mediator/sqlite-store.ts'
import { packAnoncrypt, packAuthcrypt, parseJwe, unpackAuthcrypt, didCommPost } from '../../src/protocol/didcomm/crypto.ts'
import { buildPlaintext, type DidCommPlaintext } from '../../src/protocol/didcomm/message.ts'

export const MEDIATOR_URL = 'https://mediator.test.example'
export const utf8 = (s: string) => new TextEncoder().encode(s)

/** Anything that can authcrypt as one keyAgreement key of a DID. */
export interface KeyHolder { did: string; xKid: string; xPriv: Uint8Array }

export function freshMediator(limits: Partial<SqliteMediatorLimits> = {}, store = SqliteMediatorStore.memory(limits)) {
  const mediator = store.loadIdentity(MEDIATOR_URL)
  const { handle } = createMediator({ mediator, store })
  const call = async (path: string, init: RequestInit) => {
    const url = new URL(path, MEDIATOR_URL)
    const res = await handle(new Request(url, init), url)
    if (!res) throw new Error(`mediator did not handle ${path}`)
    return res
  }
  const post = (body: unknown) => call('/', didCommPost(body))
  /** Authcrypts `type`/`body` from `sender`, POSTs it, unpacks the reply. */
  const request = async (sender: KeyHolder, type: string, body: unknown): Promise<DidCommPlaintext> => {
    const plaintext = buildPlaintext(type, body, sender.did, mediator.did, { returnRoute: 'all' })
    const res = await post(packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: sender.xKid, privateKey: sender.xPriv }, [{ kid: mediator.xKid, publicKey: mediator.xPub }]))
    expect(res.status).toBe(200)
    const reply = parseJwe(await res.json())
    if (!reply) throw new Error('mediator reply is not a JWE')
    const { plaintext: bytes } = await unpackAuthcrypt(reply, { kid: sender.xKid, privateKey: sender.xPriv }, async () => mediator.xPub)
    return JSON.parse(new TextDecoder().decode(bytes)) as DidCommPlaintext
  }
  /** An anoncrypt Forward to `next` carrying `payload` as its attachment. */
  const forward = (next: string, payload: unknown, id?: string) => {
    const msg = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next })
    if (id) msg.id = id
    msg.attachments = [{ id: 'inner', data: { json: payload } }]
    return post(packAnoncrypt(utf8(JSON.stringify(msg)), [{ kid: mediator.xKid, publicKey: mediator.xPub }]))
  }
  const pushLog = (jsonl: string) => call('/webvh-log', { method: 'POST', body: jsonl })
  return { mediator, store, handle, post, request, forward, pushLog }
}

export const T = {
  MEDIATE_REQUEST: 'https://didcomm.org/coordinate-mediation/3.0/mediate-request',
  RECIPIENT_UPDATE: 'https://didcomm.org/coordinate-mediation/3.0/recipient-update',
  RECIPIENT_QUERY: 'https://didcomm.org/coordinate-mediation/3.0/recipient-query',
  STATUS_REQUEST: 'https://didcomm.org/messagepickup/3.0/status-request',
  DELIVERY_REQUEST: 'https://didcomm.org/messagepickup/3.0/delivery-request',
  MESSAGES_RECEIVED: 'https://didcomm.org/messagepickup/3.0/messages-received',
  PROBLEM_REPORT: 'https://didcomm.org/report-problem/2.0/problem-report',
  DISCOVER_FEATURES_QUERIES: 'https://didcomm.org/discover-features/2.0/queries',
  DISCOVER_FEATURES_DISCLOSE: 'https://didcomm.org/discover-features/2.0/disclose',
} as const

export function peer(): PeerIdentity { return generatePeerIdentity() }

export function deviceLabel(n: number): string { return `device-${String(n).padStart(4, '0')}` }

/** A fresh, unique mediator URL per call -- fetchMediatorInfo caches its
 * result IN-MEMORY per URL (mediator-transport.ts's own note: right for a
 * real deployment's stable URL, but a shared constant across tests would
 * have one test's cached MediatorInfo silently answer for a DIFFERENT
 * freshly-minted mediator identity in the next). */
export function freshMediatorFetch() {
  const url = `https://mediator-${crypto.randomUUID()}.test.example`
  const store = SqliteMediatorStore.memory()
  const mediator = store.loadIdentity(url)
  const { handle, live } = createMediator({ mediator, store })
  const fetchImpl: typeof fetch = async (input, init) => {
    const reqUrl = new URL(String(input))
    const res = await handle(new Request(reqUrl, init), reqUrl)
    return res ?? new Response('not found', { status: 404 })
  }
  return { mediatorIdentity: mediator, store, fetchImpl, url, live, webSocketCtor: inProcessWebSocket(live) }
}

/** A WebSocket whose far end is the in-process mediator's `live` handler. */
export function inProcessWebSocket(live: MediatorHandler['live']): typeof WebSocket {
  class InProcessWebSocket {
    readyState = 0
    onopen: (() => void) | null = null
    onmessage: ((event: { data: string }) => void) | null = null
    onclose: (() => void) | null = null
    readonly socket: LiveSocket = { send: data => { setTimeout(() => this.onmessage?.({ data }), 0) } }
    constructor(readonly url: string) {
      setTimeout(() => { if (this.readyState !== 0) return; this.readyState = 1; this.onopen?.() }, 0)
    }
    send(data: string): void { void live.message(this.socket, data) }
    close(): void {
      if (this.readyState === 3) return
      this.readyState = 3
      live.close(this.socket)
      setTimeout(() => this.onclose?.(), 0)
    }
  }
  return InProcessWebSocket as unknown as typeof WebSocket
}
