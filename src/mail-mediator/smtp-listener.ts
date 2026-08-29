// The only file in this mediator that touches a real socket. Composes
// smtp-protocol.ts's pure SmtpSession with route-store.ts/spool-store.ts
// over Bun's native Bun.listen/socket.upgradeTLS -- same "Bun's native API,
// not the node:net/tls compat shim" precedent as
// src/core/adapters/mail-smtp-listener.ts, which this is ported from. The
// only real change from that file: `resolveRecipient` asks route-store
// "does this address have a bound holder" instead of resolving a
// did:webvh identity + device roster, and `acceptIngress` enqueues into
// spool-store instead of biset-core's shared ingress store.
//
// SECURITY NOTE (TODO): PLAN_biset-mail-mediator.md section 6 calls for
// at-rest encryption of the spooled body (a DB-leak mitigation, not
// sender E2EE -- ordinary SMTP senders never encrypt for the recipient).
// This file does not yet do that; `encryptedBody` in spool-store is
// currently the plaintext RFC 5322 bytes. Left as a known gap rather than
// implemented ad hoc here, since the right key material (a mediator-held
// symmetric key, not per-holder wrapping -- nothing here needs to decrypt
// FOR a specific holder) still needs to be provisioned and rotated
// deliberately.
import { sha256 } from '@noble/hashes/sha2.js'
import { SmtpIngressCongestionError, SmtpSession } from './smtp-protocol.ts'
import type { AcceptIngressInput, SmtpEffect } from './smtp-protocol.ts'
import { SpoolFullError, type MailSpoolStore } from './spool-store.ts'
import type { MailRouteStore } from './route-store.ts'

export interface SmtpMailListenerTlsFileConfig {
  certPath: string
  keyPath: string
}

export interface SmtpMailListenerOptions {
  hostname?: string
  port: number
  /** Announced in the SMTP greeting/EHLO -- typically the mail domain. */
  helloName: string
  tls?: SmtpMailListenerTlsFileConfig
  /** Defaults to 25 MiB, matching the original core listener's default. */
  maxMessageBytes?: number
  /** Retention for a spooled message that is never claimed/acked. */
  ttlMs?: number
  routes: MailRouteStore
  spool: MailSpoolStore
  now?: () => string
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
  const now = options.now ?? (() => new Date().toISOString())

  const resolveRecipient = async ({ address }: { address: string }): Promise<boolean> =>
    options.routes.routeFor(address) !== undefined

  const acceptIngress = async (connectionData: ConnectionData, input: AcceptIngressInput): Promise<void> => {
    const bodyHash = sha256(input.rawRfc5322)
    const semanticIngressId = toHex(sha256(new TextEncoder().encode(
      `${input.recipientAddress}\0${input.mailFrom}\0${toHex(bodyHash)}`,
    )))
    try {
      options.spool.enqueue({
        address: input.recipientAddress,
        semanticIngressId,
        mailFrom: input.mailFrom,
        encryptedBody: input.rawRfc5322, // TODO(security): at-rest encrypt, see header comment
        bodyHash,
        createdAt: now(),
        expiresAt: new Date(Date.parse(now()) + ttlMs).toISOString(),
      })
    } catch (error) {
      if (error instanceof SpoolFullError) throw new SmtpIngressCongestionError(error.message)
      throw error
    }
  }

  // `isServer: true` is a real Bun 1.4 runtime option (server-side STARTTLS
  // support) that @types/bun has not caught up to declaring -- same cast
  // as the original core listener, confirmed there against a real TLS
  // handshake before relying on it.
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
      acceptIngress: acceptInput => acceptIngress(input.connectionData, acceptInput),
    })
  }

  async function applyPlaintextEffects(socket: Bun.Socket<ConnectionData>, effects: SmtpEffect[]): Promise<void> {
    const connectionData = socket.data
    for (const effect of effects) {
      if (effect.kind === 'reply') { socket.write(effect.text); continue }
      if (effect.kind === 'close') { socket.end(); continue }
      if (effect.kind === 'starttls' && tlsOptions) {
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
            error(_s, error) { console.warn('[mail-mediator smtp] tls connection error:', error.message) },
          },
        })
      }
    }
  }

  async function applyTlsEffects(socket: Bun.Socket<ConnectionData>, effects: SmtpEffect[]): Promise<void> {
    for (const effect of effects) {
      if (effect.kind === 'reply') { socket.write(effect.text); continue }
      if (effect.kind === 'close') { socket.end(); continue }
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
        console.warn('[mail-mediator smtp] connection error:', error.message)
      },
    },
  })

  return {
    port: server.port,
    stop() { server.stop(true) },
  }
}

function writeEffects(socket: { write(data: string): number }, effects: SmtpEffect[]): void {
  for (const effect of effects) if (effect.kind === 'reply') socket.write(effect.text)
}

function toUint8Array(data: Buffer | Uint8Array): Uint8Array {
  return data instanceof Uint8Array ? data : new Uint8Array(data)
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('')
}
