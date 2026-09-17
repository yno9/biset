// did.md Internet-mail relay.  This is deliberately a process of its own:
// third-party DIDComm mediators neither share its database nor participate in
// SMTP recipient resolution.
import { createMailPluginListener } from '../mediator/mail-plugin/listener.ts'
import { resolveDidMdMailRecipientRoute } from '../mediator/mail-plugin/bridge.ts'
import { SqliteMailRelayStore } from './sqlite-store.ts'
import { createMailRelaySubmissionHandler } from './submission-http.ts'
import { mailBridgeDidDocument, mailBridgeDiscoveryDocument } from './did-document.ts'
import { createMailBridgeAgent } from './agent-http.ts'
import { MAIL_BRIDGE_DID } from './did-document.ts'
import { loadMailRelayDkim } from './dkim-config.ts'

const authorityUrl = required('DID_MD_AUTHORITY_URL')
const authoritySecret = required('DID_MD_MAIL_RELAY_SECRET')
const databasePath = required('MAIL_RELAY_DATABASE_PATH')
const apexDomain = Bun.env.MAIL_RELAY_APEX_DOMAIN ?? 'did.md'
if (apexDomain !== 'did.md') throw new Error('MAIL_RELAY_APEX_DOMAIN must be did.md')

const signDkim = loadMailRelayDkim(Bun.env)
if (!signDkim) console.warn(JSON.stringify({ level: 'warn', message: 'DKIM is not configured; outbound mail will be unsigned' }))
const store = SqliteMailRelayStore.open(databasePath)
const identity = store.loadIdentity()
const bridgeIdentity = { kid: `${MAIL_BRIDGE_DID}#key-1`, privateKey: identity.xPriv }
const listener = createMailPluginListener({
  hostname: Bun.env.MAIL_RELAY_SMTP_HOST ?? '0.0.0.0',
  port: integer('MAIL_RELAY_SMTP_PORT', 25),
  helloName: Bun.env.MAIL_RELAY_SMTP_HELLO_NAME ?? 'mail.did.md',
  apexDomain,
  maxMessageBytes: integer('MAIL_RELAY_MAX_MESSAGE_BYTES', 25 * 1024 * 1024),
  senderIdentity: bridgeIdentity,
  resolveRecipient: async address => {
    const resolved = await resolveDidMdMailRecipientRoute(address, authorityUrl, authoritySecret, fetch)
    return resolved.ok ? resolved.route : undefined
  },
  ...(Bun.env.MAIL_RELAY_TLS_CERT_PATH && Bun.env.MAIL_RELAY_TLS_KEY_PATH
    ? { tls: { certPath: Bun.env.MAIL_RELAY_TLS_CERT_PATH, keyPath: Bun.env.MAIL_RELAY_TLS_KEY_PATH } }
    : {}),
})
const relayOrigin = Bun.env.MAIL_RELAY_ORIGIN ?? 'https://api.did.md'
const legacySubmission = createMailRelaySubmissionHandler({
  hostname: Bun.env.MAIL_RELAY_SMTP_HELLO_NAME ?? 'mail.did.md', signDkim, authorityUrl, authoritySecret,
  relayOrigin, allowedOrigins: new Set((Bun.env.MAIL_RELAY_ALLOWED_ORIGINS ?? '').split(',').map(value => value.trim()).filter(Boolean)),
  idempotency: { get: (messageId, request) => store.submissionResult(messageId, request), save: (messageId, request, result) => store.saveSubmissionResult(messageId, request, result) },
})
const bridgeAgent = createMailBridgeAgent({ hostname: Bun.env.MAIL_RELAY_SMTP_HELLO_NAME ?? 'mail.did.md', signDkim, apexDomain, identity: bridgeIdentity })
const submission = Bun.serve({
  hostname: Bun.env.MAIL_RELAY_SUBMIT_HOST ?? '127.0.0.1',
  port: integer('MAIL_RELAY_SUBMIT_PORT', 8792),
  fetch: request => {
    const path = new URL(request.url).pathname
    if (request.method === 'GET' && path === '/.well-known/did.json') {
      const host = request.headers.get('host')?.split(':', 1)[0]?.toLowerCase()
      const headers = { 'cache-control': 'no-store', 'access-control-allow-origin': '*' }
      if (host === 'smtp.did.md') return Response.json(mailBridgeDidDocument(identity.xPub), { headers })
      if (host === 'did.md') return Response.json(mailBridgeDiscoveryDocument(), { headers })
    }
    if (path === '/v1/mail') return bridgeAgent(request)
    return legacySubmission(request)
  },
})

console.info(JSON.stringify({ at: new Date().toISOString(), level: 'info', message: 'did.md mail relay SMTP listener started', port: listener.port, senderKid: bridgeIdentity.kid }))
console.info(JSON.stringify({ at: new Date().toISOString(), level: 'info', message: 'did.md mail relay submission started', port: submission.port }))
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => { listener.stop(); submission.stop(); store.close() })
}

function required(name: string): string {
  const value = Bun.env[name]?.trim()
  if (!value) throw new Error(`${name} is required`)
  return value
}
function integer(name: string, fallback: number): number {
  const value = Bun.env[name] === undefined ? fallback : Number(Bun.env[name])
  if (!Number.isSafeInteger(value) || value < 1 || value > 128 * 1024 * 1024) throw new Error(`${name} is invalid`)
  return value
}
