// Pure, socket-agnostic inbound SMTP session state machine. Ported from
// src/core/adapters/mail-smtp-protocol.ts with ONE change: this mediator
// has no identityId/deviceIds concept (PLAN_biset-mail-mediator.md section
// 2 -- "所有しないもの": Vault ID, MLS group, device roster), so
// `resolveRecipient` collapses to a plain "does a route exist for this
// address" boolean and `acceptIngress` carries only the address, not an
// identity. Command grammar, STARTTLS discard-on-upgrade semantics,
// 3-strikes error handling, and the RCPT-550-not-accept-then-drop choice
// are otherwise identical -- see the original file's header comment for
// why 550 here leaks nothing an attacker couldn't already learn (this
// mediator's routes are bound to addresses whose front-door kid is
// already a public did:webvh document).
//
// DATA bodies are handled at the byte level throughout (never decoded to
// a JS string) -- rawRfc5322 is opaque MIME/8BITMIME content downstream.
// Only command lines (ASCII by this slice's design -- no SMTPUTF8) are
// decoded for parsing.

export interface AcceptIngressInput {
  recipientAddress: string
  mailFrom: string
  /** The domain argument from EHLO/HELO, or undefined if the client sent
   * neither. Connection provenance for sourceEvidence, not used for
   * routing. */
  heloDomain: string | undefined
  rawRfc5322: Uint8Array
}

/** Thrown by an injected `acceptIngress` to signal store congestion
 * (spool full for this address) -- distinguished from any other failure
 * so the session can reply 452 (temporary, try smaller/later) instead of
 * a generic 451. */
export class SmtpIngressCongestionError extends Error {}

export type SmtpEffect =
  | { kind: 'reply'; text: string }
  | { kind: 'starttls' }
  | { kind: 'close' }

export interface SmtpSessionDeps {
  /** Announced in the greeting and echoed in the EHLO response context. */
  helloName: string
  /** Advertise STARTTLS this session -- false once already TLS, or when no
   * certificate is configured at all. */
  tlsAdvertised: boolean
  /** False for a session resumed immediately after a STARTTLS upgrade. */
  sendGreeting: boolean
  maxMessageBytes: number
  /** True if this address currently has a bound route (any holder) --
   * RCPT TO for an address with none is rejected 550. */
  resolveRecipient(reference: { address: string }): Promise<boolean>
  acceptIngress(input: AcceptIngressInput): Promise<void>
}

const ERROR_THRESHOLD = 3
const MAX_COMMAND_LINE_BYTES = 4096

type Mode = 'command' | 'data'

export class SmtpSession {
  private readonly deps: SmtpSessionDeps
  private buffer: Uint8Array = new Uint8Array(0)
  private mode: Mode = 'command'
  private greeted = false
  private closed = false
  private errorCount = 0
  private heloDomain: string | undefined
  private mailFrom: string | undefined
  private recipients: string[] = []
  private dataChunks: Uint8Array[] = []
  private dataBytes = 0
  private dataOverflow = false
  private greetingSent = false

  constructor(deps: SmtpSessionDeps) {
    this.deps = deps
  }

  /** The initial 220 banner, if this session should send one. Call once,
   * before the first feed(). */
  greeting(): SmtpEffect[] {
    if (this.greetingSent || !this.deps.sendGreeting) return []
    this.greetingSent = true
    return [reply(`220 ${this.deps.helloName} ESMTP Service Ready`)]
  }

  async feed(chunk: Uint8Array): Promise<SmtpEffect[]> {
    if (this.closed) return []
    this.buffer = concatBytes(this.buffer, chunk)
    const effects: SmtpEffect[] = []
    while (!this.closed) {
      const newline = this.buffer.indexOf(10) // '\n'
      if (newline === -1) {
        const cap = this.mode === 'command' ? MAX_COMMAND_LINE_BYTES : this.deps.maxMessageBytes + MAX_COMMAND_LINE_BYTES
        if (this.buffer.length > cap) {
          if (this.mode === 'command') {
            effects.push(reply('500 5.5.2 Line too long'))
            if (this.strike()) { effects.push(...this.closeNow()); break }
            this.buffer = new Uint8Array(0)
          } else {
            effects.push(...this.closeNow())
          }
        }
        break
      }
      let line = this.buffer.subarray(0, newline)
      if (line.length > 0 && line[line.length - 1] === 13) line = line.subarray(0, line.length - 1) // trailing '\r'
      this.buffer = this.buffer.subarray(newline + 1)

      if (this.mode === 'data') {
        const done = this.handleDataLine(line)
        if (done) effects.push(...(await this.finishData()))
        continue
      }
      effects.push(...(await this.handleCommandLine(line)))
    }
    return effects
  }

  private strike(): boolean {
    this.errorCount += 1
    return this.errorCount > ERROR_THRESHOLD
  }

  private closeNow(): SmtpEffect[] {
    this.closed = true
    return [{ kind: 'close' }]
  }

  private resetTransaction(): void {
    this.mailFrom = undefined
    this.recipients = []
  }

  private async handleCommandLine(lineBytes: Uint8Array): Promise<SmtpEffect[]> {
    const line = decodeAscii(lineBytes)
    const split = splitCommandLine(line)
    if (split === undefined) {
      const effects: SmtpEffect[] = [reply('501 5.5.2 Bad command')]
      if (this.strike()) effects.push(...this.closeNow())
      return effects
    }
    const { verb, rest } = split

    if (verb === '') {
      const effects: SmtpEffect[] = [reply('500 5.5.2 Error: bad syntax')]
      if (this.strike()) effects.push(...this.closeNow())
      return effects
    }

    switch (verb) {
      case 'EHLO': {
        this.greeted = true
        this.heloDomain = rest || undefined
        this.resetTransaction()
        return [reply(ehloResponse(this.deps, rest || this.deps.helloName))]
      }
      case 'HELO': {
        this.greeted = true
        this.heloDomain = rest || undefined
        this.resetTransaction()
        return [reply(`250 2.0.0 Hello ${rest || this.deps.helloName}`)]
      }
      case 'MAIL': {
        if (!this.greeted) return [reply('502 5.5.1 Please introduce yourself first.')]
        const address = parsePath(rest, 'FROM:')
        if (address === undefined) return [reply('501 5.5.2 Was expecting MAIL arg syntax of FROM:<address>')]
        this.mailFrom = address
        this.recipients = []
        return [reply(`250 2.0.0 Roger, accepting mail from <${address}>`)]
      }
      case 'RCPT': {
        if (this.mailFrom === undefined) return [reply('502 5.5.1 Missing MAIL FROM command.')]
        const address = parsePath(rest, 'TO:')
        if (address === undefined) return [reply('501 5.5.2 Was expecting RCPT arg syntax of TO:<address>')]
        return this.handleRcpt(address)
      }
      case 'DATA': {
        if (this.recipients.length === 0) return [reply('503 5.5.1 No valid recipients')]
        this.mode = 'data'
        this.dataChunks = []
        this.dataBytes = 0
        this.dataOverflow = false
        return [reply('354 Go ahead. End your data with <CR><LF>.<CR><LF>')]
      }
      case 'RSET': {
        this.resetTransaction()
        return [reply('250 2.0.0 Session reset')]
      }
      case 'NOOP': {
        return [reply('250 2.0.0 I have successfully done nothing')]
      }
      case 'QUIT': {
        this.closed = true
        return [reply('221 2.0.0 Bye'), { kind: 'close' }]
      }
      case 'AUTH': {
        return [reply('502 5.5.1 This is a public MX; no authentication is offered.')]
      }
      case 'VRFY': {
        return [reply('252 2.5.0 Cannot VRFY user, but will accept message')]
      }
      case 'STARTTLS': {
        if (!this.deps.tlsAdvertised) return [reply('454 4.7.0 TLS not available on this connection')]
        this.closed = true // this session object is done; the listener replaces it with a fresh one post-upgrade
        return [reply('220 2.0.0 Ready to start TLS'), { kind: 'starttls' }]
      }
      default: {
        const effects: SmtpEffect[] = [reply(`500 5.5.2 Syntax errors, ${verb} command unrecognized`)]
        if (this.strike()) effects.push(...this.closeNow())
        return effects
      }
    }
  }

  private async handleRcpt(address: string): Promise<SmtpEffect[]> {
    if (!isAsciiPrintable(address)) return [reply('550 5.6.7 Non-ASCII recipient address is not supported')]
    let routable: boolean
    try {
      routable = await this.deps.resolveRecipient({ address: address.toLowerCase() })
    } catch {
      return [reply('451 4.4.3 Temporary failure resolving recipient, try again later')]
    }
    if (!routable) return [reply('550 5.1.1 No such user here')]
    this.recipients.push(address)
    return [reply(`250 2.0.0 I'll make sure <${address}> gets this`)]
  }

  /** Returns true once the "." terminator line has been consumed. */
  private handleDataLine(line: Uint8Array): boolean {
    if (line.length === 1 && line[0] === 46) return true // lone "."
    if (this.dataOverflow) return false // already over the cap; keep discarding until the terminator
    const unstuffed = line.length > 0 && line[0] === 46 ? line.subarray(1) : line // RFC 5321 §4.5.2
    this.dataBytes += unstuffed.length + 2
    if (this.dataBytes > this.deps.maxMessageBytes) { this.dataOverflow = true; this.dataChunks = []; return false }
    this.dataChunks.push(unstuffed, CRLF)
    return false
  }

  private async finishData(): Promise<SmtpEffect[]> {
    this.mode = 'command'
    if (this.dataOverflow) {
      this.resetTransaction()
      return [reply('552 5.3.4 Message size exceeds fixed limit')]
    }
    const rawRfc5322 = concatAll(this.dataChunks)
    const mailFrom = this.mailFrom ?? ''
    const recipients = this.recipients
    this.resetTransaction()

    let succeeded = 0
    let sawCongestion = false
    let sawOtherFailure = false
    for (const address of recipients) {
      try {
        await this.deps.acceptIngress({ recipientAddress: address, heloDomain: this.heloDomain, mailFrom, rawRfc5322 })
        succeeded += 1
      } catch (error) {
        if (error instanceof SmtpIngressCongestionError) sawCongestion = true
        else sawOtherFailure = true
      }
    }

    if (succeeded === recipients.length) return [reply('250 2.0.0 OK: queued')]
    if (succeeded > 0) return [reply(`250 2.0.0 OK: queued for ${succeeded} of ${recipients.length} recipients`)]
    if (sawCongestion && !sawOtherFailure) return [reply('452 4.2.2 Insufficient system storage, try again later')]
    return [reply('451 4.3.0 Requested action aborted: local error in processing')]
  }
}

function reply(text: string): SmtpEffect {
  return { kind: 'reply', text: `${text}\r\n` }
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) return b
  if (b.length === 0) return a
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

function concatAll(chunks: Uint8Array[]): Uint8Array {
  let total = 0
  for (const chunk of chunks) total += chunk.length
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length }
  return out
}

const CRLF = new Uint8Array([13, 10])

function decodeAscii(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
}

function isAsciiPrintable(value: string): boolean {
  return /^[\x21-\x7e]+$/.test(value)
}

export function splitCommandLine(line: string): { verb: string; rest: string } | undefined {
  if (line.length >= 8 && line.slice(0, 8).toUpperCase() === 'STARTTLS') return { verb: 'STARTTLS', rest: '' }
  if (line.length === 0) return { verb: '', rest: '' }
  if (line.length < 4) return undefined
  if (line.length === 4) return { verb: line.toUpperCase(), rest: '' }
  if (line.length === 5) return undefined
  if (line[4] !== ' ') return undefined
  return { verb: line.slice(0, 4).toUpperCase(), rest: line.slice(5).trim() }
}

export function parsePath(rest: string, prefix: string): string | undefined {
  const trimmed = rest.trimStart()
  if (trimmed.slice(0, prefix.length).toUpperCase() !== prefix) return undefined
  const arg = trimmed.slice(prefix.length).trimStart()
  if (arg.startsWith('<')) {
    const end = arg.indexOf('>')
    if (end === -1) return undefined
    return arg.slice(1, end)
  }
  const end = arg.search(/\s/)
  const address = end === -1 ? arg : arg.slice(0, end)
  return address.length === 0 ? undefined : address
}

function ehloResponse(deps: SmtpSessionDeps, domain: string): string {
  const caps = ['PIPELINING', '8BITMIME', 'ENHANCEDSTATUSCODES', `SIZE ${deps.maxMessageBytes}`]
  if (deps.tlsAdvertised) caps.push('STARTTLS')
  const lines = [`250-Hello ${domain}`, ...caps.map((cap, index) => `250${index === caps.length - 1 ? ' ' : '-'}${cap}`)]
  return lines.join('\r\n')
}
