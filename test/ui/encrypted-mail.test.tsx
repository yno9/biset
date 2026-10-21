// @vitest-environment happy-dom
import { displayName } from '../../src/client/app/ui/did-display.ts'
import { afterEach, expect, test } from 'vitest'
import * as openpgp from 'openpgp'
import { refreshInbox, setEncryptedMailOpener } from '../../src/client/app/ui/shell.ts'
import { mail } from '../../src/client/app/ui/stores.ts'
import { generatePgpKey } from '../support/pgp.ts'
import { buildInnerMime } from '../../src/client/pgp/mime.ts'
import { encryptMessage } from '../../src/client/pgp/message-crypto.ts'
import { openStoredMail } from '../../src/client/pgp/open.ts'
import { storedEncryptedBody } from '../../src/client/pgp/stored.ts'

afterEach(() => setEncryptedMailOpener(undefined))

const publicBytes = async (key: { publicArmor: string }) => (await openpgp.readKey({ armoredKey: key.publicArmor })).write()
const NOTICE = 'This message is encrypted with OpenPGP. The mail bridge cannot read it; decrypt the attached message with your OpenPGP key.'

async function setup() {
  const alice = await generatePgpKey('alice@did.md'), bob = await generatePgpKey('bob@x.test')
  const inner = buildInnerMime({ headers: [['Subject', 'ひみつ'], ['Date', 'Wed, 21 Oct 2026 04:03:02 GMT'], ['Message-ID', '<real@x.test>'], ['In-Reply-To', '<before@x.test>']], text: 'the real words' })
  const armored = await encryptMessage({ plaintext: inner, recipients: [await publicBytes(alice)], signer: bob.privateKey })
  const stored = storedEncryptedBody(NOTICE, armored)
  const model = {
    async snapshot() { return { emails: [{ id: 'e1', blobId: 'b1', threadId: 't1', mailboxIds: {}, keywords: {}, receivedAt: '2026-10-21T00:00:00Z', sentAt: '2026-10-17T11:53:00Z', subject: '[...]', from: [{ email: 'did:web:did.md:x.test:bob' }] }], contactCards: [] } as never },
    async download() { return new TextEncoder().encode(stored) },
  }
  return { alice, bob, model, stored }
}

test('an encrypted mail is shown opened: the real body and subject, its threading, and whether its signature held', async () => {
  const { alice, bob, model } = await setup()
  setEncryptedMailOpener(async rawBody => openStoredMail(rawBody, { privateKeys: [alice.privateKey], senderKeys: [await publicBytes(bob)] }))
  await refreshInbox(model as never)
  const [shown] = mail.get().messages
  expect(shown!.msg.body.trim()).toBe('the real words')
  expect(shown!.msg.subject).toBe('ひみつ')
  expect(shown!.msg.in_reply_to).toBe('before@x.test')
  expect(shown!.msg.encrypted).toEqual({ signed: true, verified: true })
  // The outer sentAt (a made-up day, as Delta Chat does) is not the time shown: the inner Date is.
  expect(shown!.msg.ts).toBe(Date.parse('2026-10-21T04:03:02Z'))
})

test('without the sender\'s key the signature is reported as not verified; without our key the mail is not shown, and comes once the key is here', async () => {
  const { alice, model } = await setup()
  setEncryptedMailOpener(async rawBody => openStoredMail(rawBody, { privateKeys: [alice.privateKey], senderKeys: [] }))
  await refreshInbox(model as never)
  expect(mail.get().messages[0]!.msg.encrypted).toEqual({ signed: true, verified: false })

  setEncryptedMailOpener(async rawBody => openStoredMail(rawBody, { privateKeys: [], senderKeys: [] }))
  await refreshInbox(model as never)
  expect(mail.get().messages).toHaveLength(0) // no armor, no "[...]" subject: nothing to read

  setEncryptedMailOpener(async rawBody => openStoredMail(rawBody, { privateKeys: [alice.privateKey], senderKeys: [] }))
  await refreshInbox(model as never)
  expect(mail.get().messages).toHaveLength(1)
})

test('a key that is not a recipient shows nothing (a Secure-Join step after its join, mail for another key)', async () => {
  const { model } = await setup()
  const other = await generatePgpKey('carol@did.md')
  setEncryptedMailOpener(async rawBody => openStoredMail(rawBody, { privateKeys: [other.privateKey], senderKeys: [] }))
  await refreshInbox(model as never)
  expect(mail.get().messages).toHaveLength(0)
})

test('a message for an earlier generation\'s key is opened by the next key in the list', async () => {
  const { alice, bob, model } = await setup()
  const newer = await generatePgpKey('alice@did.md') // the key of a later generation
  setEncryptedMailOpener(async rawBody => openStoredMail(rawBody, { privateKeys: [newer.privateKey, alice.privateKey], senderKeys: [await publicBytes(bob)] }))
  await refreshInbox(model as never)
  expect(mail.get().messages[0]!.msg.body.trim()).toBe('the real words')
  expect(mail.get().messages[0]!.msg.encrypted).toEqual({ signed: true, verified: true })
})

test('a key update from Delta Chat (an encrypted disposition-notification report) is not shown', async () => {
  const alice = await generatePgpKey('alice@did.md'), bob = await generatePgpKey('bob@x.test')
  const report = ['Content-Type: multipart/report; report-type=disposition-notification; boundary="b"', 'Subject: Keyupdate', '', '--b', 'Content-Type: text/plain', '', "This message updates the sender's encryption key and relay list.", '--b--', ''].join('\r\n')
  const armored = await encryptMessage({ plaintext: report, recipients: [await publicBytes(alice)], signer: bob.privateKey })
  const model = {
    async snapshot() { return { emails: [{ id: 'e1', blobId: 'b1', threadId: 't1', mailboxIds: {}, keywords: {}, receivedAt: '2026-10-21T00:00:00Z', subject: '[...]', from: [{ email: 'did:web:did.md:x.test:bob' }] }], contactCards: [] } as never },
    async download() { return new TextEncoder().encode(storedEncryptedBody(NOTICE, armored)) },
  }
  setEncryptedMailOpener(async rawBody => openStoredMail(rawBody, { privateKeys: [alice.privateKey], senderKeys: [] }))
  await refreshInbox(model as never)
  expect(mail.get().messages).toHaveLength(0)
})

test('a name in the contact list is the one shown for the sender, over the name the message carried', async () => {
  const bob = 'did:web:did.md:x.test:bob'
  const card = { id: 'c1', '@type': 'Card', version: '1.0', uid: 'u', addressBookIds: { default: true }, name: { full: 'Robert' }, onlineServices: { didcomm: { service: 'DIDComm', uri: bob } } }
  const model = {
    async snapshot() { return { emails: [{ id: 'e1', blobId: 'b1', threadId: 't1', mailboxIds: {}, keywords: {}, receivedAt: '2026-10-21T00:00:00Z', subject: 'hi', from: [{ email: bob, name: 'bob from the mail' }] }], contactCards: [card] } as never },
    async download() { return new TextEncoder().encode('hello') },
  }
  setEncryptedMailOpener(undefined)
  await refreshInbox(model as never)
  expect(mail.get().messages[0]!.msg.from_name).toBe('Robert')
  expect(displayName(bob)).toBe('Robert')
})
