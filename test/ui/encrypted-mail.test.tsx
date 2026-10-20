// @vitest-environment happy-dom
import { afterEach, expect, test } from 'vitest'
import * as openpgp from 'openpgp'
import { refreshInbox, setEncryptedMailOpener } from '../../src/client/app/ui/shell.ts'
import { mail } from '../../src/client/app/ui/stores.ts'
import { generatePgpKey } from '../../src/client/pgp/keyring.ts'
import { buildInnerMime } from '../../src/client/pgp/mime.ts'
import { encryptMessage } from '../../src/client/pgp/message-crypto.ts'
import { openStoredMail } from '../../src/client/pgp/open.ts'
import { storedEncryptedBody } from '../../src/client/pgp/stored.ts'

afterEach(() => setEncryptedMailOpener(undefined))

const publicBytes = async (key: { publicArmor: string }) => (await openpgp.readKey({ armoredKey: key.publicArmor })).write()
const NOTICE = 'This message is encrypted with OpenPGP. The mail bridge cannot read it; decrypt the attached message with your OpenPGP key.'

async function setup() {
  const alice = await generatePgpKey('alice@did.md'), bob = await generatePgpKey('bob@x.test')
  const inner = buildInnerMime({ headers: [['Subject', 'ひみつ'], ['Message-ID', '<real@x.test>'], ['In-Reply-To', '<before@x.test>']], text: 'the real words' })
  const armored = await encryptMessage({ plaintext: inner, recipients: [await publicBytes(alice)], signer: bob.privateKey })
  const stored = storedEncryptedBody(NOTICE, armored)
  const model = {
    async snapshot() { return { emails: [{ id: 'e1', blobId: 'b1', threadId: 't1', mailboxIds: {}, keywords: {}, receivedAt: '2026-10-21T00:00:00Z', subject: '[...]', from: [{ email: 'did:web:did.md:x.test:bob' }] }], contactCards: [] } as never },
    async download() { return new TextEncoder().encode(stored) },
  }
  return { alice, bob, model, stored }
}

test('an encrypted mail is shown opened: the real body and subject, its threading, and whether its signature held', async () => {
  const { alice, bob, model } = await setup()
  setEncryptedMailOpener(async rawBody => openStoredMail(rawBody, { privateKey: alice.privateKey, senderKeys: [await publicBytes(bob)] }))
  await refreshInbox(model as never)
  const [shown] = mail.get().messages
  expect(shown!.msg.body.trim()).toBe('the real words')
  expect(shown!.msg.subject).toBe('ひみつ')
  expect(shown!.msg.in_reply_to).toBe('before@x.test')
  expect(shown!.msg.encrypted).toEqual({ signed: true, verified: true })
})

test('without the sender\'s key the signature is reported as not verified; without our key the notice stays', async () => {
  const { alice, model } = await setup()
  setEncryptedMailOpener(async rawBody => openStoredMail(rawBody, { privateKey: alice.privateKey, senderKeys: [] }))
  await refreshInbox(model as never)
  expect(mail.get().messages[0]!.msg.encrypted).toEqual({ signed: true, verified: false })

  setEncryptedMailOpener(async rawBody => openStoredMail(rawBody, { privateKey: undefined, senderKeys: [] }))
  await refreshInbox(model as never)
  const shown = mail.get().messages[0]!.msg
  expect(shown.encrypted).toBeUndefined()
  expect(shown.body).toContain('This message is encrypted with OpenPGP.')
})

test('a key that is not a recipient leaves the notice (the message is not lost)', async () => {
  const { model } = await setup()
  const other = await generatePgpKey('carol@did.md')
  setEncryptedMailOpener(async rawBody => openStoredMail(rawBody, { privateKey: other.privateKey, senderKeys: [] }))
  await refreshInbox(model as never)
  expect(mail.get().messages[0]!.msg.encrypted).toBeUndefined()
  expect(mail.get().messages[0]!.msg.body).toContain('This message is encrypted with OpenPGP.')
})
