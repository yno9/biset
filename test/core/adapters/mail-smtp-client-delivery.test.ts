// Real-socket, end-to-end symmetry test: the outbound client (this plan)
// delivering into the already-built inbound listener (previous plan), both
// real implementations, no stubbing of either side's wire protocol.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createBisetCoreDeployment } from '../../../src/core/deployment.ts'
import { MailIngressAdapter } from '../../../src/core/adapters/mail.ts'
import { createSmtpMailListener } from '../../../src/core/adapters/mail-smtp-listener.ts'
import { deliverMail } from '../../../src/core/adapters/mail-smtp-client.ts'
import { CoreIngressTransport } from '../../../src/vault/core-ingress-transport.ts'
import { ingressPullSigningBytes } from '../../../src/protocol/signing.ts'
import { buildGenesisLog, withFetch } from '../../protocol/support/webvh-log-fixture.ts'

const rootPrivateKey = ed25519.utils.randomSecretKey()
const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
const { did: identityId, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
const devicePrivateKey = ed25519.utils.randomSecretKey()
const devicePublicKey = ed25519.getPublicKey(devicePrivateKey)
const deviceKid = `${identityId}#device-a`

const certPath = `${import.meta.dir}/../../fixtures/smtp-tls-cert.pem`
const keyPath = `${import.meta.dir}/../../fixtures/smtp-tls-key.pem`

const usedDatabasePaths: string[] = []
afterEach(() => { for (const path of usedDatabasePaths.splice(0)) { try { rmSync(path) } catch {} } })

function makeCore() {
  const databasePath = `/tmp/biset-smtp-out-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.sqlite`
  usedDatabasePaths.push(databasePath)
  return createBisetCoreDeployment({
    databasePath,
    signingKeys: { async resolveEd25519PublicKey(keyId) { return keyId === deviceKid ? devicePublicKey : undefined } },
  })
}

async function installRoster(core: ReturnType<typeof makeCore>) {
  await core.roster.installAcceptedProjection({
    version: 1, identityId, selfGroupId: 'self-group-1', epoch: '1', acceptedAt: '2099-08-21T00:00:00.000Z',
    devices: [{ deviceId: 'device-a', deliveryFloor: '1', signingKeyId: deviceKid }],
  })
}

async function pulledPayloads(core: ReturnType<typeof makeCore>): Promise<Uint8Array[]> {
  const transport = new CoreIngressTransport({ baseUrl: 'https://core.example', fetch: (input, init) => core.fetch(new Request(input, init)) })
  const unsigned = { version: 1 as const, identityId, recipientDeviceId: 'device-a', requestedAt: '2099-08-21T00:00:30.000Z' }
  const envelopes = await transport.pull({ ...unsigned, signature: ed25519.sign(ingressPullSigningBytes(unsigned), devicePrivateKey) })
  return envelopes.map(e => e.protectedPayload)
}

describe('deliverMail against a real inbound listener', () => {
  test('delivers plaintext to a resolvable recipient, landing a pullable ingress record', async () => {
    const core = makeCore()
    await installRoster(core)
    const listener = createSmtpMailListener({
      port: 0, helloName: 'mail.test.example', apexDomain: 'test.example',
      ingressAdapter: new MailIngressAdapter(core.ingressAdapter), roster: core.roster,
    })
    try {
      const raw = new TextEncoder().encode('Subject: outbound test\r\n\r\nhello from the outbound client\r\n')
      await withFetch(log, async () => {
        const results = await deliverMail(
          { hostname: 'client.example', port: listener.port, mxResolver: async () => ['127.0.0.1'] },
          { mailFrom: 'sender@example.test', rcptTo: ['alice@mail.test.example'], rawRfc5322: raw },
        )
        expect(results).toHaveLength(1)
        expect(results[0]).toMatchObject({ domain: 'mail.test.example', outcome: 'delivered', accepted: ['alice@mail.test.example'], rejected: [] })
      })
      const payloads = await pulledPayloads(core)
      expect(payloads).toHaveLength(1)
      expect(new TextDecoder().decode(payloads[0]!)).toBe(new TextDecoder().decode(raw))
    } finally {
      listener.stop()
      core.close()
    }
  })

  test('negotiates and uses real STARTTLS when the inbound listener offers it', async () => {
    const core = makeCore()
    await installRoster(core)
    const listener = createSmtpMailListener({
      port: 0, helloName: 'mail.test.example', apexDomain: 'test.example',
      ingressAdapter: new MailIngressAdapter(core.ingressAdapter), roster: core.roster,
      tls: { certPath, keyPath },
    })
    try {
      const raw = new TextEncoder().encode('Subject: outbound over tls\r\n\r\nencrypted in transit\r\n')
      await withFetch(log, async () => {
        const results = await deliverMail(
          {
            hostname: 'client.example', port: listener.port, mxResolver: async () => ['127.0.0.1'],
            // The fixture cert (test/fixtures/README.md) is a plain leaf
            // certificate with no CA basic-constraints, so it can't be
            // trusted via `ca:` the way a real CA chain would be -- same
            // reason the inbound listener's own STARTTLS test
            // (mail-smtp-listener.test.ts) uses rejectUnauthorized: false
            // rather than pinning a CA. What this test actually proves is
            // that the outbound client completes a real TLS handshake and
            // sends the DATA/RCPT dialogue over the encrypted channel, not
            // certificate-chain trust (production TLS keeps verification on
            // by default -- see DeliverMailOptions.tlsOptions' doc comment).
            tlsOptions: { rejectUnauthorized: false, serverName: 'mail.example.com' },
          },
          { mailFrom: 'sender@example.test', rcptTo: ['alice@mail.test.example'], rawRfc5322: raw },
        )
        expect(results).toHaveLength(1)
        expect(results[0]?.outcome).toBe('delivered')
        expect(results[0]?.accepted).toEqual(['alice@mail.test.example'])
      })
      const payloads = await pulledPayloads(core)
      expect(payloads).toHaveLength(1)
    } finally {
      listener.stop()
      core.close()
    }
  })

  test('a domain with no MX does not stop other domain groups in the same call', async () => {
    const core = makeCore()
    await installRoster(core)
    const listener = createSmtpMailListener({
      port: 0, helloName: 'mail.test.example', apexDomain: 'test.example',
      ingressAdapter: new MailIngressAdapter(core.ingressAdapter), roster: core.roster,
    })
    try {
      const raw = new TextEncoder().encode('Subject: mixed domains\r\n\r\nbody\r\n')
      await withFetch(log, async () => {
        const results = await deliverMail(
          {
            hostname: 'client.example', port: listener.port,
            mxResolver: async domain => domain === 'mail.test.example' ? ['127.0.0.1'] : [],
          },
          { mailFrom: 'sender@example.test', rcptTo: ['alice@mail.test.example', 'bob@nowhere.invalid'], rawRfc5322: raw },
        )
        expect(results).toHaveLength(2)
        const ok = results.find(r => r.domain === 'mail.test.example')
        const bad = results.find(r => r.domain === 'nowhere.invalid')
        expect(ok?.outcome).toBe('delivered')
        expect(bad).toMatchObject({ outcome: 'error', error: 'no MX for nowhere.invalid' })
      })
      expect(await pulledPayloads(core)).toHaveLength(1)
    } finally {
      listener.stop()
      core.close()
    }
  })
})
