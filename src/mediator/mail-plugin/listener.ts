// The mail plugin's own SMTP listener: composes the sibling
// smtp-socket-server.ts (Bun.listen/STARTTLS plumbing -- moved here from
// src/core/adapters/ on 2026-09-03 when biset-core was retired; this plugin
// is now its only consumer) with bridge.ts's resolve/pack split and an HTTP
// POST for delivery. No spool, no identityId/deviceIds concept -- RCPT TO
// resolves straight against the recipient's own routing.json (bridge.ts's
// `resolveMailRecipientRoute`), and DATA acceptance packs and delivers in
// one step, matching the "250 OK only after it's actually on its way, not
// just accepted" property a spool-backed listener would need a durable
// commit for.
import { createSmtpSocketServer } from './smtp-socket-server.ts'
import type { AcceptIngressInput } from './mail-smtp-protocol.ts'
import { resolveMailRecipientRoute, packInboundMailForward, type MailRecipientRoute } from './bridge.ts'
import { defaultFetch } from '../../net-fetch.ts'

export interface MailPluginListenerTlsFileConfig {
  certPath: string
  keyPath: string
}

export interface MailPluginListenerOptions {
  hostname?: string
  port: number
  /** Announced in the SMTP greeting/EHLO. */
  helloName: string
  apexDomain: string
  tls?: MailPluginListenerTlsFileConfig
  /** Defaults to 25 MiB, matching biset-core's own SMTP listener default. */
  maxMessageBytes?: number
  /** This plugin's own persisted did:peer (SqliteMediatorStore.
   * loadMailPluginIdentity) -- the `sender` an inbound-mail Forward is
   * authcrypt'd from. */
  senderIdentity: { kid: string; privateKey: Uint8Array }
  fetch?: typeof fetch
}

export interface MailPluginListener {
  readonly port: number
  stop(): void
}

const DEFAULT_MAX_MESSAGE_BYTES = 25 * 1024 * 1024

export function createMailPluginListener(options: MailPluginListenerOptions): MailPluginListener {
  const fetchImpl = options.fetch ?? defaultFetch()

  return createSmtpSocketServer<MailRecipientRoute>({
    hostname: options.hostname,
    port: options.port,
    helloName: options.helloName,
    tls: options.tls,
    maxMessageBytes: options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES,
    resolveRecipient: async reference => {
      const resolved = await resolveMailRecipientRoute(reference.address, options.apexDomain, fetchImpl)
      return resolved.ok ? resolved.route : undefined
    },
    acceptIngress: input => deliverInboundMail(options.senderIdentity, fetchImpl, input),
  })
}

async function deliverInboundMail(
  senderIdentity: { kid: string; privateKey: Uint8Array },
  fetchImpl: typeof fetch,
  input: AcceptIngressInput<MailRecipientRoute>,
): Promise<void> {
  const delivery = packInboundMailForward(
    input.resolution,
    { rawRfc5322: input.rawRfc5322, smtpEnvelope: `MAIL FROM:<${input.mailFrom}> RCPT TO:<${input.recipientAddress}>` },
    senderIdentity,
  )
  const response = await fetchImpl(delivery.postUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(delivery.outbound),
  })
  // 202 Accepted, same convention didcomm/send-message.ts's own delivery
  // POST checks -- for both a Forward-wrapped delivery (mediator/server.ts's
  // FORWARD case) and a direct one to the recipient's own service endpoint.
  if (response.status !== 202) {
    throw new Error(`mail bridge delivery failed: HTTP ${response.status} ${(await response.text().catch(() => '')).slice(0, 256)}`)
  }
}
