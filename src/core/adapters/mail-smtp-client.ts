// Outbound SMTP client (PLAN.md §6.2). Delivers a message to arbitrary
// remote MX servers -- the client-side mirror of mail-smtp-listener.ts.
// Adapted from the archived Rust relay's smtp_out.rs: group recipients by
// domain, one connection per domain, client STARTTLS taken whenever the far
// end advertises it (a refused STARTTLS *command* falls back to plaintext; a
// failed *handshake* after the server's 220 is fatal for that domain group --
// once TLS is committed to there is no plaintext left to fall back to), a
// rejected RCPT TO is logged and skipped rather than failing the whole send,
// only the highest-priority MX is tried (no fallback; a queue's job, out of
// scope here). Deliberately no dependency on the vault/narrow-API/JMAP
// layers above it -- see PLAN.md §6.2's plan for what's still to come.
import { resolveMx as realResolveMx } from 'node:dns/promises'

export interface MailDeliveryResult {
  domain: string
  target: string
  accepted: string[]
  rejected: Array<{ address: string; reply: string }>
  outcome: 'delivered' | 'error'
  error?: string
}

export interface DeliverMailOptions {
  /** Announced in EHLO. */
  hostname: string
  /** Injectable for tests; defaults to real DNS. Returns hosts in priority
   * order, best first; empty means the domain takes no mail. */
  mxResolver?: (domain: string) => Promise<string[]>
  /** Injectable for tests; defaults to real Bun.connect. */
  connect?: typeof Bun.connect
  /** TLS options for the client-side STARTTLS upgrade (trusted CAs, etc).
   * Certificate verification stays on by default (Bun.TLSOptions'
   * rejectUnauthorized defaults to true) -- a relay that quietly accepted
   * any certificate on outbound delivery would be a weaker thing wearing
   * the same name, even though the upgrade itself is opportunistic. */
  tlsOptions?: Bun.TLSOptions
  /** SMTP port to connect to on the resolved MX host. Defaults to 25. */
  port?: number
}

export async function deliverMail(
  options: DeliverMailOptions,
  message: { mailFrom: string; rcptTo: string[]; rawRfc5322: Uint8Array },
): Promise<MailDeliveryResult[]> {
  if (message.rcptTo.length === 0) throw new TypeError('deliverMail requires at least one recipient')
  const mxResolver = options.mxResolver ?? (async (domain: string) => {
    const records = await realResolveMx(domain)
    return records.sort((a, b) => a.priority - b.priority).map(record => record.exchange)
  })
  const connect = options.connect ?? Bun.connect
  const port = options.port ?? 25

  const byDomain = groupRecipientsByDomain(message.rcptTo)
  const results: MailDeliveryResult[] = []
  for (const [domain, recipients] of byDomain) {
    const mx = await mxResolver(domain)
    const host = mx[0]
    if (!host) {
      results.push({ domain, target: '', accepted: [], rejected: [], outcome: 'error', error: `no MX for ${domain}` })
      continue
    }
    // A trailing dot makes the name absolute in DNS but not in a connect
    // string.
    const connectHost = host.replace(/\.$/, '')
    const target = `${connectHost}:${port}`
    try {
      const outcome = await deliverToHost(connect, connectHost, port, options.hostname, options.tlsOptions, message.mailFrom, recipients, message.rawRfc5322)
      results.push({ domain, target, ...outcome, outcome: 'delivered' })
    } catch (error) {
      results.push({ domain, target, accepted: [], rejected: [], outcome: 'error', error: error instanceof Error ? error.message : String(error) })
    }
  }
  return results
}

async function deliverToHost(
  connect: typeof Bun.connect,
  host: string,
  port: number,
  helloName: string,
  tlsOptions: Bun.TLSOptions | undefined,
  mailFrom: string,
  rcptTo: string[],
  rawRfc5322: Uint8Array,
): Promise<{ accepted: string[]; rejected: Array<{ address: string; reply: string }> }> {
  let reader = await connectReader(connect, host, port)
  try {
    await expect(reader, 220, 'greeting')
    let ehlo = await greet(reader, helloName)

    if (advertisesCapability(ehlo, 'STARTTLS')) {
      await reader.write('STARTTLS\r\n')
      const reply = await reader.readReply()
      if (reply.startsWith('2')) {
        // Anything the server sent after its 220 was sent before the
        // handshake and cannot be trusted -- carrying buffered plaintext
        // into the TLS session is how a stripping attack smuggles commands
        // in. Our reader only ever buffers whole replies (see
        // extractCompleteReply), so any leftover bytes here are exactly
        // that kind of pipelined-across-the-boundary data.
        if (reader.hasBufferedBytes()) throw new Error('server pipelined bytes across the TLS boundary')
        const tlsReader = await upgradeReader(reader, tlsOptions ?? {})
        reader.detach()
        reader = tlsReader
        ehlo = await greet(reader, helloName) // extension list does not carry over the upgrade
      }
      // A refused STARTTLS command (non-2xx) leaves the socket in the
      // clear; continue plaintext, matching the reference.
    }

    await reader.write(buildMailFromCommand(mailFrom, ehlo))
    await expect(reader, 250, 'MAIL FROM')

    const accepted: string[] = []
    const rejected: Array<{ address: string; reply: string }> = []
    for (const address of rcptTo) {
      await reader.write(`RCPT TO:<${address}>\r\n`)
      const reply = await reader.readReply()
      if (reply.startsWith('2')) accepted.push(address)
      else rejected.push({ address, reply: reply.trim() })
    }

    await reader.write('DATA\r\n')
    await expect(reader, 354, 'DATA')
    await reader.write(dotStuff(rawRfc5322))
    if (rawRfc5322.length === 0 || rawRfc5322[rawRfc5322.length - 1] !== 10) await reader.write('\r\n')
    await reader.write('.\r\n')
    await expect(reader, 250, 'end DATA')

    // A server that will not say goodbye has still taken the message.
    try { await reader.write('QUIT\r\n'); await reader.readReply() } catch { /* best-effort */ }

    return { accepted, rejected }
  } finally {
    reader.close()
  }
}

// ── Socket reply reader ──────────────────────────────────────────────────
//
// An outbound client controls its own pacing (unlike the inbound listener,
// which must react to untrusted, arbitrarily-paced input) -- a
// straightforward imperative async/await dialogue is the right fit here,
// not an effect-based state machine. This bridges Bun's callback-style
// socket into a promise-based readReply().

interface ReplyReader {
  write(data: string | Uint8Array): Promise<void>
  readReply(): Promise<string>
  hasBufferedBytes(): boolean
  detach(): void
  close(): void
  /** Only used by upgradeReader -- the raw Bun socket to upgrade. */
  socket: Bun.Socket<unknown>
}

interface ReaderState {
  buffer: string
  waiter: { resolve: (reply: string) => void; reject: (error: Error) => void } | undefined
  closed: boolean
  closeError: Error | undefined
}

function extractCompleteReply(buffer: string): { reply: string; rest: string } | undefined {
  let index = 0
  while (true) {
    const lineEnd = buffer.indexOf('\r\n', index)
    if (lineEnd === -1) return undefined
    const line = buffer.slice(index, lineEnd)
    index = lineEnd + 2
    if (line.length < 4 || line[3] !== '-') return { reply: buffer.slice(0, index), rest: buffer.slice(index) }
  }
}

function makeReaderState(): ReaderState {
  return { buffer: '', waiter: undefined, closed: false, closeError: undefined }
}

function feed(state: ReaderState, chunk: Uint8Array): void {
  state.buffer += new TextDecoder().decode(chunk)
  if (!state.waiter) return
  const complete = extractCompleteReply(state.buffer)
  if (!complete) return
  state.buffer = complete.rest
  const waiter = state.waiter
  state.waiter = undefined
  waiter.resolve(complete.reply)
}

function fail(state: ReaderState, error: Error): void {
  state.closed = true
  state.closeError = error
  if (state.waiter) { const waiter = state.waiter; state.waiter = undefined; waiter.reject(error) }
}

function readerFrom(socket: Bun.Socket<unknown>, state: ReaderState): ReplyReader {
  return {
    socket,
    async write(data) { socket.write(data) },
    readReply() {
      return new Promise((resolve, reject) => {
        if (state.closed) { reject(state.closeError ?? new Error('connection closed')); return }
        const complete = extractCompleteReply(state.buffer)
        if (complete) { state.buffer = complete.rest; resolve(complete.reply); return }
        state.waiter = { resolve, reject }
      })
    },
    hasBufferedBytes() { return state.buffer.length > 0 },
    detach() { /* no-op: state simply stops receiving further feed() calls once the socket handler is replaced by upgradeTLS */ },
    close() { try { socket.end() } catch { /* already closed */ } },
  }
}

async function connectReader(connect: typeof Bun.connect, host: string, port: number): Promise<ReplyReader> {
  const state = makeReaderState()
  const socket = await connect({
    hostname: host,
    port,
    socket: {
      data(_socket, chunk) { feed(state, chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)) },
      close() { fail(state, new Error('connection closed')) },
      error(_socket, error) { fail(state, error) },
    },
  })
  return readerFrom(socket, state)
}

async function upgradeReader(reader: ReplyReader, tlsOptions: Bun.TLSOptions): Promise<ReplyReader> {
  const state = makeReaderState()
  return new Promise((resolve, reject) => {
    const [, tlsSocket] = reader.socket.upgradeTLS({
      tls: tlsOptions,
      socket: {
        open(socket) { resolve(readerFrom(socket, state)) },
        data(_socket, chunk) { feed(state, chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)) },
        close() { fail(state, new Error('connection closed')) },
        error(_socket, error) { fail(state, error); reject(error) },
      },
    })
    void tlsSocket
  })
}

async function greet(reader: ReplyReader, helloName: string): Promise<string> {
  await reader.write(`EHLO ${helloName}\r\n`)
  const reply = await reader.readReply()
  if (reply.startsWith('2')) return reply
  await reader.write(`HELO ${helloName}\r\n`)
  return expect(reader, 250, 'EHLO')
}

async function expect(reader: ReplyReader, code: number, what: string): Promise<string> {
  const reply = await reader.readReply()
  const wantClass = String(Math.floor(code / 100))
  if (reply[0] === wantClass) return reply
  throw new Error(`${what}: ${reply.trim()}`)
}

// ── Pure helpers ──────────────────────────────────────────────────────────

export function groupRecipientsByDomain(addresses: string[]): Map<string, string[]> {
  const byDomain = new Map<string, string[]>()
  for (const address of addresses) {
    const at = address.lastIndexOf('@')
    if (at <= 0 || at === address.length - 1) throw new TypeError(`invalid recipient address: ${address}`)
    const domain = address.slice(at + 1).toLowerCase()
    const list = byDomain.get(domain)
    if (list) list.push(address)
    else byDomain.set(domain, [address])
  }
  return byDomain
}

/** Escapes a leading dot on every line (RFC 5321 §4.5.2) so a body line of
 * `.` alone cannot be mistaken for the DATA terminator. */
export function dotStuff(raw: Uint8Array): Uint8Array {
  const out: number[] = []
  let atLineStart = true
  for (const byte of raw) {
    if (atLineStart && byte === 46) out.push(46) // '.'
    out.push(byte)
    atLineStart = byte === 10 // '\n'
  }
  return new Uint8Array(out)
}

/** Whether an EHLO reply advertised `keyword` -- matched per line, on the
 * keyword token alone (a line may carry a parameter, e.g. "250-SIZE
 * 35882577", and a substring test would find "SIZE" inside another
 * keyword). */
export function advertisesCapability(ehloReply: string, keyword: string): boolean {
  return ehloReply.split(/\r\n/).some(line => {
    const rest = line.length > 4 ? line.slice(4) : ''
    return rest.trim().split(/\s+/)[0]?.toUpperCase() === keyword.toUpperCase()
  })
}

/** `MAIL FROM` with the ESMTP parameters a real client adds -- only what the
 * far end actually advertised, in the conventional order (BODY=8BITMIME
 * first, SMTPUTF8 second). A bare `MAIL FROM` is not equivalent: without
 * BODY=8BITMIME a strict server is entitled to assume 7-bit, and a UTF-8
 * body can be mangled or refused. */
export function buildMailFromCommand(from: string, ehloReply: string): string {
  let command = `MAIL FROM:<${from}>`
  if (advertisesCapability(ehloReply, '8BITMIME')) command += ' BODY=8BITMIME'
  if (advertisesCapability(ehloReply, 'SMTPUTF8')) command += ' SMTPUTF8'
  return `${command}\r\n`
}
