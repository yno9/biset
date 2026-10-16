/**
 * A `Bun.serve`-shaped HTTP/WebSocket server on `node:http` and `ws`: a fetch handler taking a
 * Request and returning a Response (streamed bodies included, which MIMI's SSE needs), plus the
 * WebSocket upgrade the mediator's live mode uses. Resolves once it is listening.
 */
import { createServer, ServerResponse, type IncomingMessage, type Server as HttpServer } from 'node:http'
import type { Duplex } from 'node:stream'
import { Readable } from 'node:stream'
import { WebSocketServer, type WebSocket } from 'ws'

interface ServerWebSocket<Data> {
  readonly data: Data
  send(data: string | Uint8Array): void
  close(code?: number, reason?: string): void
}

export interface ServeOptions<Data> {
  hostname?: string
  port: number
  /** Larger request bodies are answered 413. */
  maxRequestBodySize?: number
  fetch(request: Request, server: Server<Data>): Response | undefined | Promise<Response | undefined>
  websocket?: {
    maxPayloadLength?: number
    /** Seconds without a pong before a socket is dropped; the server pings at a third of it. */
    idleTimeout?: number
    message(socket: ServerWebSocket<Data>, data: string | Uint8Array): void | Promise<void>
    close?(socket: ServerWebSocket<Data>, code: number, reason: string): void
  }
}

export interface Server<Data> {
  readonly port: number
  upgrade(request: Request, options: { data: Data }): boolean
  requestIP(request: Request): { address: string, port: number, family: string } | null
  stop(force?: boolean): Promise<void>
}

const DEFAULT_MAX_BODY = 128 * 1024 * 1024

export async function serve<Data = undefined>(options: ServeOptions<Data>): Promise<Server<Data>> {
  const maxBody = options.maxRequestBodySize ?? DEFAULT_MAX_BODY
  const origins = new WeakMap<Request, { request: IncomingMessage, socket: Duplex, head: Buffer }>()
  const peers = new WeakMap<Request, { address: string, port: number, family: string }>()
  const sockets = new Set<WebSocket>()
  const wss = options.websocket ? new WebSocketServer({ noServer: true, maxPayload: options.websocket.maxPayloadLength }) : undefined
  let server!: Server<Data>

  const http: HttpServer = createServer((incoming, outgoing) => {
    void handle(incoming, outgoing)
  })
  // No per-socket idle limit: SSE and live sockets are quiet for long stretches by design.
  http.timeout = 0
  http.requestTimeout = 0

  async function handle(incoming: IncomingMessage, outgoing: ServerResponse): Promise<void> {
    try {
      const declared = Number(incoming.headers['content-length'] ?? 0)
      if (declared > maxBody) { outgoing.writeHead(413).end('payload too large'); return }
      const request = toRequest(incoming, maxBody)
      peers.set(request, peer(incoming))
      const response = await options.fetch(request, server) ?? new Response('not found', { status: 404 })
      await send(response, outgoing)
    } catch (error) {
      if (!outgoing.headersSent) outgoing.writeHead(500, { 'content-type': 'text/plain' }).end('internal error')
      else outgoing.destroy()
      console.error('[serve]', error instanceof Error ? error.message : error)
    }
  }

  if (wss) {
    http.on('upgrade', (incoming, socket, head) => {
      void (async () => {
        try {
          const request = toRequest(incoming, maxBody)
          peers.set(request, peer(incoming))
          origins.set(request, { request: incoming, socket, head })
          const response = await options.fetch(request, server)
          // Not upgraded by the handler: answer the plain HTTP request on this socket.
          if (!origins.has(request)) return
          origins.delete(request)
          const outgoing = new ServerResponse(incoming)
          outgoing.assignSocket(socket as never)
          outgoing.on('finish', () => socket.destroy())
          await send(response ?? new Response('not found', { status: 404 }), outgoing)
        } catch { socket.destroy() }
      })()
    })
  }

  server = {
    get port() { return (http.address() as { port: number } | null)?.port ?? options.port },
    upgrade(request, { data }) {
      const origin = origins.get(request)
      if (!origin || !wss || !options.websocket) return false
      origins.delete(request)
      const handlers = options.websocket
      wss.handleUpgrade(origin.request, origin.socket, origin.head, raw => {
        sockets.add(raw)
        const socket: ServerWebSocket<Data> = {
          data,
          send: payload => raw.send(payload),
          close: (code, reason) => raw.close(code, reason),
        }
        let alive = true
        raw.on('pong', () => { alive = true })
        const interval = Math.max(1, (handlers.idleTimeout ?? 120) / 3) * 1000
        const timer = setInterval(() => {
          if (!alive) { raw.terminate(); return }
          alive = false
          raw.ping()
        }, interval)
        timer.unref()
        // Frames are handled one at a time, in order, as Bun does for an async handler.
        let chain: Promise<void> = Promise.resolve()
        raw.on('message', (frame, isBinary) => {
          const payload = isBinary ? new Uint8Array(frame as Buffer) : (frame as Buffer).toString('utf8')
          chain = chain.then(() => handlers.message(socket, payload)).catch(error => console.error('[serve:ws]', error instanceof Error ? error.message : error))
        })
        raw.on('close', (code, reason) => {
          clearInterval(timer)
          sockets.delete(raw)
          handlers.close?.(socket, code, reason.toString('utf8'))
        })
        raw.on('error', () => {})
      })
      return true
    },
    requestIP: request => peers.get(request) ?? null,
    async stop(force = false) {
      const closed = new Promise<void>(resolve => http.close(() => resolve()))
      if (force) {
        for (const raw of sockets) raw.terminate()
        http.closeAllConnections()
      } else http.closeIdleConnections()
      await closed
    },
  }

  await new Promise<void>((resolve, reject) => {
    http.once('error', reject)
    http.listen(options.port, options.hostname, () => { http.off('error', reject); resolve() })
  })
  return server
}

function peer(incoming: IncomingMessage) {
  const socket = incoming.socket
  return { address: socket.remoteAddress ?? 'unknown', port: socket.remotePort ?? 0, family: socket.remoteFamily ?? 'IPv4' }
}

function toRequest(incoming: IncomingMessage, maxBody: number): Request {
  const headers = new Headers()
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (value === undefined) continue
    if (Array.isArray(value)) for (const item of value) headers.append(name, item)
    else headers.set(name, value)
  }
  const url = `http://${incoming.headers.host ?? 'localhost'}${incoming.url ?? '/'}`
  const method = incoming.method ?? 'GET'
  if (method === 'GET' || method === 'HEAD') return new Request(url, { method, headers })
  let seen = 0
  const limited = Readable.toWeb(incoming).pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      seen += chunk.byteLength
      if (seen > maxBody) controller.error(new Error('request body too large'))
      else controller.enqueue(chunk)
    },
  }))
  return new Request(url, { method, headers, body: limited, duplex: 'half' } as RequestInit)
}

async function send(response: Response, outgoing: ServerResponse): Promise<void> {
  const headers: Record<string, string | string[]> = {}
  response.headers.forEach((value, name) => { if (name !== 'set-cookie') headers[name] = value })
  const cookies = response.headers.getSetCookie()
  if (cookies.length) headers['set-cookie'] = cookies
  outgoing.writeHead(response.status, response.statusText || undefined, headers)
  if (!response.body) { outgoing.end(); return }
  const reader = response.body.getReader()
  // A client that goes away must reach the stream's cancel(), which is how SSE listeners unsubscribe.
  outgoing.on('close', () => { void reader.cancel().catch(() => {}) })
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (outgoing.destroyed) break
      if (!outgoing.write(value)) await new Promise<void>(resolve => { outgoing.once('drain', resolve); outgoing.once('close', resolve) })
    }
  } catch { outgoing.destroy(); return }
  outgoing.end()
}
