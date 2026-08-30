// biset-core's own SMTP listener: composes the shared
// smtp-socket-server.ts (Bun.listen/STARTTLS plumbing) with
// mail-recipient-resolver.ts and the existing MailIngressAdapter.
import { ProtocolValidationError } from '../../protocol/validate.ts'
import { createMailRecipientResolver } from './mail-recipient-resolver.ts'
import { SmtpIngressCongestionError, type SmtpRecipientResolution } from './mail-smtp-protocol.ts'
import type { AcceptIngressInput } from './mail-smtp-protocol.ts'
import { createSmtpSocketServer, type SmtpConnectionInfo } from './smtp-socket-server.ts'
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

export function createSmtpMailListener(options: SmtpMailListenerOptions): SmtpMailListener {
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS
  const resolveRecipient = createMailRecipientResolver({
    apexDomain: options.apexDomain,
    mailDomain: options.mailDomain,
    roster: options.roster,
  })

  return createSmtpSocketServer<SmtpRecipientResolution>({
    hostname: options.hostname,
    port: options.port,
    helloName: options.helloName,
    tls: options.tls,
    maxMessageBytes: options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES,
    resolveRecipient,
    acceptIngress: (input, connection) => acceptIngress(options.ingressAdapter, ttlMs, connection, input),
  })
}

async function acceptIngress(
  adapter: MailIngressAdapter,
  ttlMs: number,
  connection: SmtpConnectionInfo,
  input: AcceptIngressInput<SmtpRecipientResolution>,
): Promise<void> {
  const now = new Date()
  const evidence: Record<string, unknown> = {
    remoteAddress: connection.remoteAddress,
    heloDomain: input.heloDomain,
    mailFrom: input.mailFrom,
    tlsUsed: connection.tls,
    receivedAt: now.toISOString(),
  }
  try {
    await adapter.accept({
      ingressId: `mail-${crypto.randomUUID()}`,
      recipientIdentityId: input.resolution.identityId,
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
