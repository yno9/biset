import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { connect } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import type { Socket } from 'node:net'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createBisetCoreDeployment } from '../../../src/core/deployment.ts'
import { MailIngressAdapter } from '../../../src/core/adapters/mail.ts'
import { createSmtpMailListener } from '../../../src/core/adapters/mail-smtp-listener.ts'
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
  const databasePath = `/tmp/biset-smtp-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.sqlite`
  usedDatabasePaths.push(databasePath)
  const core = createBisetCoreDeployment({
    databasePath,
    signingKeys: { async resolveEd25519PublicKey(keyId) { return keyId === deviceKid ? devicePublicKey : undefined } },
  })
  return core
}

async function installRoster(core: ReturnType<typeof makeCore>) {
  await core.roster.installAcceptedProjection({
    version: 1, identityId, selfGroupId: 'self-group-1', epoch: '1', acceptedAt: '2099-08-21T00:00:00.000Z',
    devices: [{ deviceId: 'device-a', deliveryFloor: '1', signingKeyId: deviceKid }],
  })
}

async function pullPulledPayloads(core: ReturnType<typeof makeCore>): Promise<Uint8Array[]> {
  const transport = new CoreIngressTransport({ baseUrl: 'https://core.example', fetch: (input, init) => core.fetch(new Request(input, init)) })
  const unsigned = { version: 1 as const, identityId, recipientDeviceId: 'device-a', requestedAt: '2099-08-21T00:00:30.000Z' }
  const envelopes = await transport.pull({ ...unsigned, signature: ed25519.sign(ingressPullSigningBytes(unsigned), devicePrivateKey) })
  return envelopes.map(e => e.protectedPayload)
}

function connectRaw(port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1')
    socket.once('connect', () => resolve(socket))
    socket.once('error', reject)
  })
}

/** Reads until the buffered text contains a full reply ending in `\r\n` whose
 * final line is not a continuation ("250-..."). Good enough for this test's
 * scripted, well-behaved exchanges. */
function readReply(socket: Socket): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = ''
    const onData = (chunk: Buffer) => {
      buf += chunk.toString('utf8')
      const lines = buf.split('\r\n').filter(Boolean)
      const last = lines[lines.length - 1]
      if (last && /^\d{3} /.test(last)) { cleanup(); resolve(buf) }
    }
    const onError = (error: Error) => { cleanup(); reject(error) }
    const cleanup = () => { socket.off('data', onData); socket.off('error', onError) }
    socket.on('data', onData)
    socket.on('error', onError)
  })
}

describe('SMTP mail listener', () => {
  test('a full EHLO/MAIL/RCPT/DATA transaction over plaintext lands a pullable ingress record', async () => {
    const core = makeCore()
    await installRoster(core)
    const listener = createSmtpMailListener({
      port: 0, helloName: 'mail.test.example', apexDomain: 'test.example',
      ingressAdapter: new MailIngressAdapter(core.ingressAdapter), roster: core.roster,
    })
    try {
      await withFetch(log, async () => {
        const socket = await connectRaw(listener.port)
        await readReply(socket) // 220 banner
        socket.write('EHLO client.example\r\n'); await readReply(socket)
        socket.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(socket)
        socket.write('RCPT TO:<alice@mail.test.example>\r\n')
        expect(await readReply(socket)).toContain('250')
        socket.write('DATA\r\n'); await readReply(socket)
        const body = 'Subject: hi\r\n\r\nhello world\r\n.\r\n'
        socket.write(body)
        expect(await readReply(socket)).toContain('250')
        socket.write('QUIT\r\n')
        await readReply(socket)
        socket.end()
      })
      const payloads = await pullPulledPayloads(core)
      expect(payloads).toHaveLength(1)
      expect(new TextDecoder().decode(payloads[0]!)).toBe('Subject: hi\r\n\r\nhello world\r\n')
    } finally {
      listener.stop()
      core.close()
    }
  })

  test('RCPT to the wrong domain is rejected 550, nothing lands', async () => {
    const core = makeCore()
    await installRoster(core)
    const listener = createSmtpMailListener({
      port: 0, helloName: 'mail.test.example', apexDomain: 'test.example',
      ingressAdapter: new MailIngressAdapter(core.ingressAdapter), roster: core.roster,
    })
    try {
      const socket = await connectRaw(listener.port)
      await readReply(socket)
      socket.write('EHLO client.example\r\n'); await readReply(socket)
      socket.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(socket)
      socket.write('RCPT TO:<alice@somewhere-else.example>\r\n')
      expect(await readReply(socket)).toContain('550')
      socket.end()
      expect(await pullPulledPayloads(core)).toHaveLength(0)
    } finally {
      listener.stop()
      core.close()
    }
  })

  test('RCPT to a domain with no roster projection is rejected 550', async () => {
    const core = makeCore()
    // Deliberately no installRoster() call.
    const listener = createSmtpMailListener({
      port: 0, helloName: 'mail.test.example', apexDomain: 'test.example',
      ingressAdapter: new MailIngressAdapter(core.ingressAdapter), roster: core.roster,
    })
    try {
      await withFetch(log, async () => {
        const socket = await connectRaw(listener.port)
        await readReply(socket)
        socket.write('EHLO client.example\r\n'); await readReply(socket)
        socket.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(socket)
        socket.write('RCPT TO:<alice@mail.test.example>\r\n')
        expect(await readReply(socket)).toContain('550')
        socket.end()
      })
    } finally {
      listener.stop()
      core.close()
    }
  })

  test('STARTTLS discards pre-upgrade state: MAIL right after the 220 without a fresh EHLO is refused', async () => {
    const core = makeCore()
    await installRoster(core)
    const listener = createSmtpMailListener({
      port: 0, helloName: 'mail.test.example', apexDomain: 'test.example',
      ingressAdapter: new MailIngressAdapter(core.ingressAdapter), roster: core.roster,
      tls: { certPath, keyPath },
    })
    try {
      await withFetch(log, async () => {
        const raw = await connectRaw(listener.port)
        await readReply(raw)
        raw.write('EHLO client.example\r\n'); await readReply(raw)
        raw.write('STARTTLS\r\n')
        expect(await readReply(raw)).toContain('220')

        const upgraded: Socket = await new Promise((resolve, reject) => {
          const tlsSocket = tlsConnect({ socket: raw, rejectUnauthorized: false }, () => resolve(tlsSocket as unknown as Socket))
          tlsSocket.once('error', reject)
        })

        upgraded.write('MAIL FROM:<sender@example.test>\r\n')
        expect(await readReply(upgraded)).toContain('502')

        upgraded.write('EHLO client.example\r\n'); await readReply(upgraded)
        upgraded.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(upgraded)
        upgraded.write('RCPT TO:<alice@mail.test.example>\r\n')
        expect(await readReply(upgraded)).toContain('250')
        upgraded.write('DATA\r\n'); await readReply(upgraded)
        upgraded.write('body\r\n.\r\n')
        expect(await readReply(upgraded)).toContain('250')
        upgraded.end()
      })
      const payloads = await pullPulledPayloads(core)
      expect(payloads).toHaveLength(1)
    } finally {
      listener.stop()
      core.close()
    }
  })

  test('disconnecting mid-DATA, before the terminator, delivers nothing', async () => {
    const core = makeCore()
    await installRoster(core)
    const listener = createSmtpMailListener({
      port: 0, helloName: 'mail.test.example', apexDomain: 'test.example',
      ingressAdapter: new MailIngressAdapter(core.ingressAdapter), roster: core.roster,
    })
    try {
      await withFetch(log, async () => {
        const socket = await connectRaw(listener.port)
        await readReply(socket)
        socket.write('EHLO client.example\r\n'); await readReply(socket)
        socket.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(socket)
        socket.write('RCPT TO:<alice@mail.test.example>\r\n'); await readReply(socket)
        socket.write('DATA\r\n'); await readReply(socket)
        socket.write('Subject: partial\r\nthis never gets a terminator')
        socket.destroy()
        await new Promise(resolve => setTimeout(resolve, 50))
      })
      expect(await pullPulledPayloads(core)).toHaveLength(0)
    } finally {
      listener.stop()
      core.close()
    }
  })
})
