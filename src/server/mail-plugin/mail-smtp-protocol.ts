// Pure, socket-agnostic inbound SMTP session state machine (PLAN.md §6.2).
// No node:net/bun import here on purpose -- fed bytes via feed(), returns an
// ordered list of effects (replies to write, a STARTTLS request, a close
// request) for the socket-owning caller (this directory's listener.ts) to
// perform. Fully unit-testable with plain byte arrays and stub async deps.
//
// Protocol shape (command grammar, STARTTLS discard-on-upgrade semantics,
// 3-strikes error handling) is adapted from the archived Rust relay's
// jmapsmtp.bak/crates/jmapsmtp/src/smtp_in.rs, itself a port of go-smtp's
// conn.go. One deliberate reversal from that reference: RCPT TO for an
// unresolvable recipient is rejected 550 here, not accepted-then-dropped.
// The Rust version's header comment calls that acceptance an anti-oracle
// measure (a 550 lets anyone probing port 25 enumerate which addresses this
// relay serves) -- a real cost, accepted here because this relay's
// "addresses" are subdomain-per-identity DIDs, already public by
// construction (identity/webvh/resolver.ts resolves any of them from a bare
// domain with no authorization check), so a 550 leaks nothing an attacker
// couldn't already learn by fetching the DID log directly.
//
// DATA bodies are handled at the byte level throughout (never decoded to a
// JS string) -- rawRfc5322 is opaque MIME/8BITMIME content downstream
// (mail.ts's own doc comment), and round-tripping it through TextDecoder/
// Encoder would silently corrupt any line that isn't valid UTF-8. Only
// command lines (EHLO/MAIL/RCPT/etc, ASCII by this slice's design -- see
// SMTPUTF8 below) are decoded for parsing.

export interface SmtpRecipientResolution {
  identityId: string
  deviceIds: string[]
}

/** `TResolution` is whatever `resolveRecipient` returns for a RCPT this
 * session accepted -- biset-core's own identityId+deviceIds shape by
 * default, but genuinely just an opaque payload as far as this pure state
 * machine is concerned: it never reads a field off it, only carries it from
 * `resolveRecipient` through to `acceptIngress` per recipient (feedback:
 * unify common logic -- mediator/mail-plugin's own SMTP listener has no
 * identityId/deviceIds concept at all, and reuses this exact class with a
 * `resolution: undefined` shape instead of forking a near-duplicate copy of
 * the whole EHLO/MAIL/RCPT/DATA/STARTTLS grammar). */
export interface AcceptIngressInput<TResolution = SmtpRecipientResolution> {
  recipientAddress: string
  mailFrom: string
  /** The domain argument from EHLO/HELO, or undefined if the client sent
   * neither (can't happen on a path that reaches DATA, since EHLO/HELO is
   * required first -- kept optional because there is nothing to assert it
   * against inside this pure module). Connection provenance for
   * sourceEvidence, not used for routing. */
  heloDomain: string | undefined
  rawRfc5322: Uint8Array
  resolution: TResolution
}

/** Thrown by an injected `acceptIngress` to signal store congestion
 * (identity pending-item/byte-limit exceeded) -- distinguished from any
 * other failure so the session can reply 452 (temporary, try smaller/later)
 * instead of a generic 451. */
export class SmtpIngressCongestionError extends Error {}

export type SmtpEffect =
  | { kind: 'reply'; text: string }
  | { kind: 'starttls' }
  | { kind: 'close' }

export interface SmtpSessionDeps<TResolution = SmtpRecipientResolution> {
  /** Announced in the greeting and echoed in the EHLO response context. */
  helloName: string
  /** Advertise STARTTLS this session -- false once already TLS, or when no
   * certificate is configured at all. */
  tlsAdvertised: boolean
  /** False for a session resumed immediately after a STARTTLS upgrade: the
   * 220 banner answers the *connection*, not a command, and the client
   * already had it (see the reference's `Greeting` doc comment -- a second
   * banner desyncs every later reply by one command). */
  sendGreeting: boolean
  maxMessageBytes: number
  resolveRecipient(reference: { address: string }): Promise<TResolution | undefined>
  acceptIngress(input: AcceptIngressInput<TResolution>): Promise<void>
}

const ERROR_THRESHOLD = 3
const MAX_COMMAND_LINE_BYTES = 4096

type Mode = 'command' | 'data'

interface PendingRecipient<TResolution> {
  address: string
  resolution: TResolution
}

export class SmtpSession<TResolution = SmtpRecipientResolution> {
  private readonly deps: SmtpSessionDeps<TResolution>
  private buffer: Uint8Array = new Uint8Array(0)
  private mode: Mode = 'command'
  private greeted = false
  private closed = false
  private errorCount = 0
  private heloDomain: string | undefined
  private mailFrom: string | undefined
  private recipients: PendingRecipient<TResolution>[] = []
  private dataChunks: Uint8Array[] = []
  private dataBytes = 0
  private dataOverflow = false
  private greetingSent = false

  constructor(deps: SmtpSessionDeps<TResolution>) {
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
        // No complete line yet. Cap how long we'll wait for one -- in
        // 'command' mode a real command line is short; in 'data' mode an
        // unterminated single line growing well past any plausible message
        // size is abusive regardless (RFC 5321 §4.5.3.1.6 caps a real line
        // at 1000 octets; this is deliberately far more permissive than
        // that, just bounded).
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
    // Non-ASCII/SMTPUTF8 local-parts can't cleanly become the DNS label the
    // subdomain-per-identity resolution needs -- rejected here rather than
    // passed to resolveRecipient, matching the SMTPUTF8-unsupported EHLO
    // capability list (no SMTPUTF8 advertised).
    if (!isAsciiPrintable(address)) return [reply('550 5.6.7 Non-ASCII recipient address is not supported')]
    let resolution: TResolution | undefined
    try {
      resolution = await this.deps.resolveRecipient({ address: address.toLowerCase() })
    } catch {
      return [reply('451 4.4.3 Temporary failure resolving recipient, try again later')]
    }
    if (!resolution) return [reply('550 5.1.1 No such user here')]
    this.recipients.push({ address, resolution })
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
    for (const recipient of recipients) {
      try {
        await this.deps.acceptIngress({
          recipientAddress: recipient.address,
          heloDomain: this.heloDomain,
          mailFrom,
          rawRfc5322,
          resolution: recipient.resolution,
        })
        succeeded += 1
      } catch (error) {
        if (error instanceof SmtpIngressCongestionError) sawCongestion = true
        else sawOtherFailure = true
      }
    }

    if (succeeded === recipients.length) return [reply('250 2.0.0 OK: queued')]
    if (succeeded > 0) return [reply(`250 2.0.0 OK: queued for ${succeeded} of ${recipients.length} recipients`)]
    // No recipient succeeded: a store-congestion failure is retryable soon
    // (452); anything else gets a generic temporary failure (451) rather
    // than assuming the message itself is at fault.
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

/** Split a command line into its verb (upper-cased) and the rest, exactly as
 * the Rust reference's `split_command` does: a verb is always four
 * characters, and anything else is a parse error -- not an unknown command
 * (a client can tell "your command is malformed" from "I don't know that
 * command" apart). STARTTLS is the one exception, matched by prefix. An
 * empty line yields `{verb: '', rest: ''}`, handled by the caller as its own
 * distinct case (matching the reference, which does not treat an empty line
 * as a BadCommand). */
export function splitCommandLine(line: string): { verb: string; rest: string } | undefined {
  if (line.length >= 8 && line.slice(0, 8).toUpperCase() === 'STARTTLS') return { verb: 'STARTTLS', rest: '' }
  if (line.length === 0) return { verb: '', rest: '' }
  if (line.length < 4) return undefined
  if (line.length === 4) return { verb: line.toUpperCase(), rest: '' }
  if (line.length === 5) return undefined
  if (line[4] !== ' ') return undefined
  return { verb: line.slice(0, 4).toUpperCase(), rest: line.slice(5).trim() }
}

/** Pulls the address out of `FROM:<a@b>` or `TO:<a@b>`, ignoring any ESMTP
 * parameters that follow. Angle brackets are optional (not RFC-conformant,
 * but common enough in the wild that real senders rely on it working). */
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

function ehloResponse(deps: { maxMessageBytes: number; tlsAdvertised: boolean }, domain: string): string {
  const caps = ['PIPELINING', '8BITMIME', 'ENHANCEDSTATUSCODES', `SIZE ${deps.maxMessageBytes}`]
  if (deps.tlsAdvertised) caps.push('STARTTLS')
  const lines = [`250-Hello ${domain}`, ...caps.map((cap, index) => `250${index === caps.length - 1 ? ' ' : '-'}${cap}`)]
  return lines.join('\r\n')
}
