// Generic Bun.listen/STARTTLS socket plumbing (connection handling:
// greeting, plaintext data, STARTTLS upgrade discarding pre-upgrade session
// state, TLS data), parameterized over `TResolution` -- listener.ts's own
// SMTP server composes this. Formerly lived in src/core/adapters/, shared
// with biset-core's own SMTP listener; moved here 2026-09-03 when
// biset-core was retired (mail was never actually received through it) and
// this plugin became the sole consumer. Still nothing here touches
// node:net/node:tls; Bun.listen/socket.upgradeTLS only.
import { SmtpSession, type AcceptIngressInput, type SmtpEffect, type SmtpSessionDeps } from './mail-smtp-protocol.ts'

export interface SmtpSocketServerTlsFileConfig {
  certPath: string
  keyPath: string
}

export interface SmtpConnectionInfo {
  remoteAddress: string
  tls: boolean
}

export interface SmtpSocketServerOptions<TResolution> {
  hostname?: string
  port: number
  helloName: string
  tls?: SmtpSocketServerTlsFileConfig
  maxMessageBytes: number
  resolveRecipient: SmtpSessionDeps<TResolution>['resolveRecipient']
  /** Unlike `SmtpSessionDeps.acceptIngress`, also gets the connection this
   * arrived on -- source of `sourceEvidence` (remoteAddress, TLS used) for
   * whichever ingress store the caller commits to, without threading that
   * through the pure SmtpSession itself (which has no concept of a
   * transport connection at all). */
  acceptIngress(input: AcceptIngressInput<TResolution>, connection: SmtpConnectionInfo): Promise<void>
}

export interface SmtpSocketServer {
  readonly port: number
  stop(): void
}

interface ConnectionData<TResolution> {
  session: SmtpSession<TResolution>
  remoteAddress: string
  tls: boolean
}

export function createSmtpSocketServer<TResolution>(options: SmtpSocketServerOptions<TResolution>): SmtpSocketServer {
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

  function buildSession(input: { sendGreeting: boolean; tlsAdvertised: boolean; connectionData: ConnectionData<TResolution> }): SmtpSession<TResolution> {
    return new SmtpSession<TResolution>({
      helloName: options.helloName,
      tlsAdvertised: input.tlsAdvertised,
      sendGreeting: input.sendGreeting,
      maxMessageBytes: options.maxMessageBytes,
      resolveRecipient: options.resolveRecipient,
      acceptIngress: acceptInput => options.acceptIngress(acceptInput, { remoteAddress: input.connectionData.remoteAddress, tls: input.connectionData.tls }),
    })
  }

  /** Handles a plaintext connection's effects, including the STARTTLS
   * upgrade. `socket.upgradeTLS` swaps which handler owns future traffic on
   * this connection -- the returned tls socket gets its own `data`/`close`
   * closures below, wired to a brand-new SmtpSession (RFC 3207 §4.2:
   * discard everything negotiated pre-upgrade; a new object rather than a
   * mutated one makes that automatic). */
  async function applyPlaintextEffects(socket: Bun.Socket<ConnectionData<TResolution>>, effects: SmtpEffect[]): Promise<void> {
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
        socket.upgradeTLS<ConnectionData<TResolution>>({
          data: { session: undefined as unknown as SmtpSession<TResolution>, remoteAddress: connectionData.remoteAddress, tls: true },
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

  async function applyTlsEffects(socket: Bun.Socket<ConnectionData<TResolution>>, effects: SmtpEffect[]): Promise<void> {
    for (const effect of effects) {
      if (effect.kind === 'reply') { socket.write(effect.text); continue }
      if (effect.kind === 'close') { socket.end(); continue }
      // A second STARTTLS is refused inside SmtpSession itself (tlsAdvertised
      // is false post-upgrade) -- no 'starttls' effect can occur here.
    }
  }

  const server = Bun.listen<ConnectionData<TResolution>>({
    hostname: options.hostname ?? '0.0.0.0',
    port: options.port,
    socket: {
      open(socket) {
        const connectionData: ConnectionData<TResolution> = { session: undefined as unknown as SmtpSession<TResolution>, remoteAddress: socket.remoteAddress, tls: false }
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

function writeEffects(socket: { write(data: string): number }, effects: SmtpEffect[]): void {
  for (const effect of effects) if (effect.kind === 'reply') socket.write(effect.text)
}

function toUint8Array(data: Buffer | Uint8Array): Uint8Array {
  return data instanceof Uint8Array ? data : new Uint8Array(data)
}
