// Mail written by ordinary OpenPGP clients (Thunderbird, Roundcube with Enigma, GnuPG) to this identity's Autocrypt key opens like
// Delta Chat's: their keys are RSA or ECC with SEIPD v1, and what they encrypt is a MIME entity or plain text.
import { describe, expect, test } from 'vitest'
import * as openpgp from 'openpgp'
import { generatePgpKey } from './support/pgp.ts'
import { autocryptKeydata } from '../src/client/pgp/keyring.ts'
import { base64ToBytes } from '../src/protocol/base64.ts'
import { openStoredMail } from '../src/client/pgp/open.ts'
import { storedEncryptedBody } from '../src/client/pgp/stored.ts'

async function ours() {
  const key = await generatePgpKey('n@did.md')
  // What a client got from our Autocrypt header: the cut-down public key.
  const published = await openpgp.readKey({ binaryKey: base64ToBytes(await autocryptKeydata(key.privateKey, 'n@did.md')) })
  return { key, published }
}

async function foreign(type: 'rsa' | 'ecc') {
  return openpgp.generateKey({ type, ...(type === 'rsa' ? { rsaBits: 3072 } : { curve: 'nistP256' as const }), userIDs: [{ name: 'Thea', email: 'thea@example.org' }], format: 'object' })
}

const body = 'Grüße from Thunderbird\r\nsecond line'
const THUNDERBIRD = [
  'Content-Type: multipart/mixed; boundary="------------abc"; protected-headers="v1"',
  'Subject: A real subject', 'From: Thea <thea@example.org>', 'To: n@did.md', 'Date: Tue, 3 Nov 2026 10:00:00 +0000', 'Message-ID: <t1@example.org>', 'MIME-Version: 1.0', '',
  '--------------abc', 'Content-Type: text/plain; charset=UTF-8; format=flowed', 'Content-Transfer-Encoding: quoted-printable', '', 'Gr=C3=BC=C3=9Fe from Thunderbird', 'second line', '--------------abc--', '',
].join('\r\n')
const ENIGMA = ['Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: 8bit', '', body].join('\r\n')

async function open(plaintext: string, options: { sign: boolean; wildcard?: boolean; type?: 'rsa' | 'ecc'; plain?: boolean }) {
  const { key, published } = await ours()
  const sender = await foreign(options.type ?? 'rsa')
  const armored = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: plaintext }), encryptionKeys: published,
    ...(options.sign ? { signingKeys: sender.privateKey } : {}), ...(options.wildcard ? { wildcard: true } : {}),
  }) as string
  return openStoredMail(storedEncryptedBody('This message is encrypted.', armored), { privateKeys: [key.privateKey], senderKeys: [sender.publicKey.write()] })
}

describe('mail from ordinary OpenPGP clients', () => {
  test('Thunderbird: signed and encrypted, a multipart with protected headers', async () => {
    const opened = await open(THUNDERBIRD, { sign: true })
    expect(opened?.subject).toBe('A real subject')
    expect(opened?.signature?.verified).toBe(true)
    expect(new TextDecoder().decode(opened!.raw)).toContain('Gr=C3=BC=C3=9Fe')
  })
  test('Roundcube / Enigma: a text entity, encrypted only', async () => {
    const opened = await open(ENIGMA, { sign: false, type: 'ecc' })
    expect(opened).toBeDefined()
    expect(opened?.signature).toBeUndefined()
  })
  test('a hidden recipient (key ID 0, GnuPG -R / throw-keyids)', async () => {
    expect(await open(THUNDERBIRD, { sign: true, wildcard: true, type: 'ecc' })).toBeDefined()
  })
  test('inline PGP: the plain text itself, with no MIME headers', async () => {
    const opened = await open('Hello\r\nSubject: not a header\r\n\r\nbody', { sign: true })
    expect(opened).toBeDefined()
    const text = new TextDecoder().decode(opened!.raw)
    expect(text).toBe('Content-Type: text/plain; charset=utf-8\r\n\r\nHello\nSubject: not a header\n\nbody')
    expect(opened?.subject).toBeUndefined()
  })
})
