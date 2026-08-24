// The only file in the mail adapter that touches a real socket (PLAN.md
// §6.2). Composes mail-smtp-protocol.ts's pure SmtpSession with
// mail-recipient-resolver.ts and the existing MailIngressAdapter over Bun's
// native Bun.listen/socket.upgradeTLS -- nothing here uses node:net/node:tls;
// bun:sqlite is this codebase's established "use Bun's native API, not the
// Node compat shim" precedent.
import { ProtocolValidationError } from '../../protocol/validate.ts'
import { createMailRecipientResolver } from './mail-recipient-resolver.ts'
import { SmtpIngressCongestionError, SmtpSession } from './mail-smtp-protocol.ts'
import type { AcceptIngressInput, SmtpEffect } from './mail-smtp-protocol.ts'
import type { MailIngressAdapter } from './mail.ts'
import type { TrustedDeviceRoster } from '../identity/device-roster.ts'

export interface SmtpMailListenerTlsFileConfig {
  certPath: string
  keyPath: string
}

export interface SmtpMailListenerOptions {
  hostname?: string
  port: number
  /** Announced in the SMTP greeting/EHLO -- typically the mail domain. */
  helloName: string
  apexDomain: string
  mailDomain?: string
  tls?: SmtpMailListenerTlsFileConfig
  /** Defaults to 25 MiB, matching IngressStore's own maxPayloadBytes -- the
   * SMTP-advertised SIZE and the store's actual cap should agree. */
  maxMessageBytes?: number
  /** Defaults to 30 days, matching VaultDeliveryStore's default (decided:
   * consistency across ingress kinds, even though mail is expected to be
   * pulled promptly under the short-accept model). */
  ttlMs?: number
  ingressAdapter: MailIngressAdapter
  roster: TrustedDeviceRoster
}

export interface SmtpMailListener {
  readonly port: number
  stop(): void
}

const DEFAULT_MAX_MESSAGE_BYTES = 25 * 1024 * 1024
const DEFAULT_TTL_MS = 30 * 24 * 60 * 60 * 1000

interface ConnectionData {
  session: SmtpSession
  remoteAddress: string
  tls: boolean
}

export function createSmtpMailListener(options: SmtpMailListenerOptions): SmtpMailListener {
  const maxMessageBytes = options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS
  const resolveRecipient = createMailRecipientResolver({
    apexDomain: options.apexDomain,
    mailDomain: options.mailDomain,
    roster: options.roster,
  })
  // `isServer: true` is a real Bun 1.4 runtime option (server-side STARTTLS
  // support, added after socket.upgradeTLS existed client-side only) that
  // @types/bun@1.4.0 has not caught up to declaring yet -- confirmed by
  // hand against a real TLS handshake (openssl s_client -starttls smtp)
  // before relying on it here. The cast is narrow and load-bearing: without
  // it Bun treats the upgrade as a client-side handshake and it silently
  // never completes.
  const tlsOptions: Bun.TLSOptions | undefined = options.tls
    ? ({ cert: Bun.file(options.tls.certPath), key: Bun.file(options.tls.keyPath), isServer: true } as Bun.TLSOptions)
    : undefined

  function buildSession(input: { sendGreeting: boolean; tlsAdvertised: boolean; connectionData: ConnectionData }): SmtpSession {
    return new SmtpSession({
      helloName: options.helloName,
      tlsAdvertised: input.tlsAdvertised,
      sendGreeting: input.sendGreeting,
      maxMessageBytes,
      resolveRecipient,
      acceptIngress: acceptInput => acceptIngress(options.ingressAdapter, ttlMs, input.connectionData, acceptInput),
    })
  }

  function writeEffects(socket: { write(data: string): number }, effects: SmtpEffect[]): void {
    for (const effect of effects) if (effect.kind === 'reply') socket.write(effect.text)
  }

  /** Handles a plaintext connection's effects, including the STARTTLS
   * upgrade. `socket.upgradeTLS` swaps which handler owns future traffic on
   * this connection -- the returned tls socket gets its own `data`/`close`
   * closures below, wired to a brand-new SmtpSession (RFC 3207 §4.2:
   * discard everything negotiated pre-upgrade; a new object rather than a
   * mutated one makes that automatic). */
  async function applyPlaintextEffects(socket: Bun.Socket<ConnectionData>, effects: SmtpEffect[]): Promise<void> {
    const connectionData = socket.data
    for (const effect of effects) {
      if (effect.kind === 'reply') { socket.write(effect.text); continue }
      if (effect.kind === 'close') { socket.end(); continue }
      if (effect.kind === 'starttls' && tlsOptions) {
        // `open` fires once the TLS handshake completes (after upgradeTLS
        // returns, not during it) and always before this socket's own
        // `data` -- so building the fresh post-upgrade SmtpSession there,
        // rather than here, is what guarantees it exists before any TLS
        // application data arrives.
        socket.upgradeTLS<ConnectionData>({
          data: { session: undefined as unknown as SmtpSession, remoteAddress: connectionData.remoteAddress, tls: true },
          tls: tlsOptions,
          socket: {
            open(upgraded) {
              upgraded.data.session = buildSession({ sendGreeting: false, tlsAdvertised: false, connectionData: upgraded.data })
            },
            async data(upgraded, chunk) {
              await applyTlsEffects(upgraded, await upgraded.data.session.feed(toUint8Array(chunk)))
            },
            close() {},
            error(_s, error) { console.warn('[smtp] tls connection error:', error.message) },
          },
        })
      }
    }
  }

  async function applyTlsEffects(socket: Bun.Socket<ConnectionData>, effects: SmtpEffect[]): Promise<void> {
    for (const effect of effects) {
      if (effect.kind === 'reply') { socket.write(effect.text); continue }
      if (effect.kind === 'close') { socket.end(); continue }
      // A second STARTTLS is refused inside SmtpSession itself (tlsAdvertised
      // is false post-upgrade) -- no 'starttls' effect can occur here.
    }
  }

  const server = Bun.listen<ConnectionData>({
    hostname: options.hostname ?? '0.0.0.0',
    port: options.port,
    socket: {
      open(socket) {
        const connectionData: ConnectionData = { session: undefined as unknown as SmtpSession, remoteAddress: socket.remoteAddress, tls: false }
        connectionData.session = buildSession({ sendGreeting: true, tlsAdvertised: tlsOptions !== undefined, connectionData })
        socket.data = connectionData
        writeEffects(socket, connectionData.session.greeting())
      },
      async data(socket, chunk) {
        await applyPlaintextEffects(socket, await socket.data.session.feed(toUint8Array(chunk)))
      },
      close() {},
      error(_socket, error) {
        console.warn('[smtp] connection error:', error.message)
      },
    },
  })

  return {
    port: server.port,
    stop() { server.stop(true) },
  }
}

function toUint8Array(data: Buffer | Uint8Array): Uint8Array {
  return data instanceof Uint8Array ? data : new Uint8Array(data)
}

async function acceptIngress(
  adapter: MailIngressAdapter,
  ttlMs: number,
  connectionData: ConnectionData,
  input: AcceptIngressInput,
): Promise<void> {
  const now = new Date()
  const evidence: Record<string, unknown> = {
    remoteAddress: connectionData.remoteAddress,
    heloDomain: input.heloDomain,
    mailFrom: input.mailFrom,
    tlsUsed: connectionData.tls,
    receivedAt: now.toISOString(),
  }
  try {
    await adapter.accept({
      ingressId: `mail-${crypto.randomUUID()}`,
      recipientIdentityId: input.identityId,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
      rawRfc5322: input.rawRfc5322,
      smtpEnvelope: `MAIL FROM:<${input.mailFrom}> RCPT TO:<${input.recipientAddress}>`,
      sourceEvidence: new TextEncoder().encode(JSON.stringify(evidence)),
    })
  } catch (error) {
    if (error instanceof ProtocolValidationError && /limit exceeded/.test(error.message)) {
      throw new SmtpIngressCongestionError(error.message)
    }
    throw error
  }
}
