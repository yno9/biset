import { createBisetCoreFetchHandler } from './app.ts'
import { createBisetCoreDeployment } from './deployment.ts'
import { MailIngressAdapter } from './adapters/mail.ts'
import { createSmtpMailListener } from './adapters/mail-smtp-listener.ts'
import { WebvhSigningKeyResolver } from './identity/webvh-signing-key-resolver.ts'

/**
 * Without DATABASE_PATH set, this binary deliberately exposes health only --
 * a deployment must inject an identity/MLS-authorised delivery store before
 * it can expose bounded relay endpoints, and there is no default database
 * path this process should ever silently create. With it set (and
 * APEX_DOMAIN, required alongside it), this runs the real production
 * composition: the narrow HTTP surface (roster/delivery/restore/ingress
 * pull+ack) plus the inbound SMTP listener (PLAN.md §6.2), sharing one
 * `BisetCoreDeployment` -- a device pulls queued mail ingress through the
 * same HTTP surface the SMTP listener feeds.
 */
const httpPort = Number(Bun.env.PORT ?? 8787)
const databasePath = Bun.env.DATABASE_PATH

if (!databasePath) {
  Bun.serve({ port: httpPort, fetch: createBisetCoreFetchHandler({}) })
  console.info(`biset-core listening on :${httpPort} (health only -- set DATABASE_PATH and APEX_DOMAIN for a full deployment)`)
} else {
  const apexDomain = Bun.env.APEX_DOMAIN
  if (!apexDomain) throw new Error('APEX_DOMAIN is required alongside DATABASE_PATH')

  const smtpPort = Number(Bun.env.SMTP_PORT ?? 25)
  const smtpHostname = Bun.env.SMTP_HOSTNAME ?? '0.0.0.0'
  const helloName = Bun.env.SMTP_HELLO_NAME ?? `mail.${apexDomain}`

  const core = createBisetCoreDeployment({ databasePath, signingKeys: new WebvhSigningKeyResolver(), mailHelloName: helloName })
  const certPath = Bun.env.SMTP_TLS_CERT_PATH
  const keyPath = Bun.env.SMTP_TLS_KEY_PATH
  const smtp = createSmtpMailListener({
    hostname: smtpHostname,
    port: smtpPort,
    helloName,
    apexDomain,
    mailDomain: Bun.env.SMTP_MAIL_DOMAIN,
    tls: certPath && keyPath ? { certPath, keyPath } : undefined,
    ingressAdapter: new MailIngressAdapter(core.ingressAdapter),
    roster: core.roster,
  })

  Bun.serve({ port: httpPort, fetch: core.fetch })

  console.info(`biset-core listening on :${httpPort} (HTTP) and :${smtp.port} (SMTP, ${helloName}${certPath ? ', TLS configured' : ', plaintext only -- no SMTP_TLS_CERT_PATH/SMTP_TLS_KEY_PATH set'})`)
}
