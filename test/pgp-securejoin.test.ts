import { describe, expect, test } from 'vitest'
import * as openpgp from 'openpgp'
import { derivePgpKey } from '../src/client/pgp/derive.ts'
import { autocryptKeydata } from '../src/client/pgp/keyring.ts'
import { decryptMessage, encryptMessage } from '../src/client/pgp/message-crypto.ts'
import { buildInnerMime, keydataHeader, parseInnerMime, parseKeydataHeader } from '../src/client/pgp/mime.ts'
import { symmetricDecrypt, symmetricEncryptSigned } from '../src/client/pgp/symmetric.ts'
import { handleSecureJoin, INVITE_DAYS, inviteOfDay, inviteUrl, sharedSecret, validAuths, type SecureJoinContext } from '../src/client/pgp/securejoin.ts'

const NOW = Date.parse('2026-10-21T12:00:00Z')
const DAY = 24 * 60 * 60 * 1000
const seed = () => crypto.getRandomValues(new Uint8Array(32))

/** Alice is us; Bob is Delta Chat opening our invite. */
async function world(overrides: Partial<SecureJoinContext> = {}) {
  const aliceSeed = seed()
  const alice = await derivePgpKey(aliceSeed, 'alice@did.md')
  const bob = await derivePgpKey(seed(), 'bob@x.test')
  const bobPublic = (await openpgp.readKey({ armoredKey: bob.publicArmor })).write()
  const sent: string[] = []
  const learned: Array<{ address: string; keydata: string }> = []
  const context: SecureJoinContext = {
    seed: aliceSeed, key: alice, address: 'alice@did.md', now: NOW,
    async send(_to, armored) { sent.push(armored) },
    async learn(party, keydata) { learned.push({ address: party.address, keydata }) },
    ...overrides,
  }
  const from = { did: 'did:web:did.md:x.test:bob', address: 'bob@x.test' }
  const auth = inviteOfDay(aliceSeed, Math.floor(NOW / DAY)).auth
  const bobKeydata = await autocryptKeydata(bob.privateKey, 'bob@x.test')
  const requestPubkey = (authToken = auth, password = sharedSecret(alice.fingerprint, authToken)) =>
    symmetricEncryptSigned(buildInnerMime({ lines: ['Secure-Join: vc-request-pubkey', `Secure-Join-Auth: ${authToken}`], text: 'Secure-Join' }), password, bob.privateKey)
  const requestWithAuth = async (options: { auth?: string; fingerprint?: string; signer?: Uint8Array; addr?: string } = {}) => encryptMessage({
    plaintext: buildInnerMime({
      lines: [keydataHeader('Autocrypt', options.addr ?? 'bob@x.test', bobKeydata, true), 'Secure-Join: vc-request-with-auth', `Secure-Join-Auth: ${options.auth ?? auth}`, `Secure-Join-Fingerprint: ${options.fingerprint ?? bob.fingerprint}`],
      text: 'Secure-Join',
    }),
    recipients: [(await openpgp.readKey({ armoredKey: alice.publicArmor })).write()], signer: options.signer ?? bob.privateKey,
  })
  return { alice, bob, bobPublic, bobKeydata, aliceSeed, auth, sent, learned, context, from, requestPubkey, requestWithAuth }
}

describe('the invite', () => {
  test('a link Delta Chat reads: our fingerprint, version 3, the day\'s number and auth, our address and name', () => {
    const value = seed()
    const url = inviteUrl({ seed: value, key: { fingerprint: 'abcd'.repeat(10) }, address: 'bob+tag@did.md', name: 'Bob É', now: NOW })
    const { invitenumber, auth } = inviteOfDay(value, Math.floor(NOW / DAY))
    expect(url).toBe(`https://i.delta.chat/#${'ABCD'.repeat(10)}&v=3&i=${invitenumber}&s=${auth}&a=bob%2Btag%40did.md&n=Bob+%C3%89`)
    expect(invitenumber).toMatch(/^[A-Za-z0-9_-]{24}$/)
    expect(auth).toMatch(/^[A-Za-z0-9_-]{24}$/)
    expect(auth).not.toBe(invitenumber)
  })

  test('it follows from the seed and the day: the same everywhere, another day another invite, and thirty days stay valid', () => {
    const value = seed()
    expect(inviteOfDay(value, 20000)).toEqual(inviteOfDay(value.slice(), 20000))
    expect(inviteOfDay(value, 20000).auth).not.toBe(inviteOfDay(value, 20001).auth)
    expect(inviteOfDay(seed(), 20000).auth).not.toBe(inviteOfDay(value, 20000).auth)
    const auths = validAuths(value, NOW)
    expect(auths).toHaveLength(INVITE_DAYS)
    expect(auths[0]).toBe(inviteOfDay(value, Math.floor(NOW / DAY)).auth)
    expect(auths).toContain(inviteOfDay(value, Math.floor(NOW / DAY) - (INVITE_DAYS - 1)).auth)
    expect(auths).not.toContain(inviteOfDay(value, Math.floor(NOW / DAY) - INVITE_DAYS).auth)
  })
})

describe('Secure-Join, the invited side', () => {
  test('vc-request-pubkey is answered with vc-pubkey: password-encrypted, signed by us, our key in Autocrypt', async () => {
    const w = await world()
    expect(await handleSecureJoin(await w.requestPubkey(), w.from, w.context)).toBe('vc-request-pubkey')
    expect(w.sent).toHaveLength(1)
    const answer = (await symmetricDecrypt(w.sent[0]!, [sharedSecret(w.alice.fingerprint, w.auth)], [(await openpgp.readKey({ armoredKey: w.alice.publicArmor })).write()]))!
    expect(answer.signedBy).toHaveLength(1)
    const mime = parseInnerMime(answer.plaintext)
    expect(mime.headers['secure-join']).toBe('vc-pubkey')
    expect(mime.headers['secure-join-auth']).toBe(w.auth)
    const key = parseKeydataHeader(mime.headers.autocrypt)!
    expect(key.addr).toBe('alice@did.md')
    expect((await openpgp.readKey({ binaryKey: Uint8Array.from(atob(key.keydata), char => char.charCodeAt(0)) })).getFingerprint().toUpperCase()).toBe(w.alice.fingerprint)
    expect(w.learned).toHaveLength(0)
  })

  test('vc-request-with-auth makes the other side\'s key known, and is answered with vc-contact-confirm that gossips that key back', async () => {
    const w = await world()
    expect(await handleSecureJoin(await w.requestWithAuth(), w.from, w.context)).toBe('vc-request-with-auth')
    expect(w.learned).toEqual([{ address: 'bob@x.test', keydata: w.bobKeydata }])
    expect(w.sent).toHaveLength(1)
    const confirm = await decryptMessage({ armored: w.sent[0]!, privateKey: w.bob.privateKey, senderKeys: [(await openpgp.readKey({ armoredKey: w.alice.publicArmor })).write()] })
    expect(confirm.signature?.verified).toBe(true)
    const mime = parseInnerMime(confirm.plaintext)
    expect(mime.headers['secure-join']).toBe('vc-contact-confirm')
    expect(mime.gossip.map(value => parseKeydataHeader(value))).toEqual([{ addr: 'bob@x.test', keydata: w.bobKeydata }])
  })

  test('the whole handshake in order, as one run', async () => {
    const w = await world()
    await handleSecureJoin(await w.requestPubkey(), w.from, w.context)
    await handleSecureJoin(await w.requestWithAuth(), w.from, w.context)
    expect(w.sent).toHaveLength(2)
    expect(w.learned).toHaveLength(1)
  })

  test('an invite from a few weeks back still works; one from before the window does not', async () => {
    const w = await world()
    const old = inviteOfDay(w.aliceSeed, Math.floor(NOW / DAY) - 20).auth
    expect(await handleSecureJoin(await w.requestPubkey(old), w.from, w.context)).toBe('vc-request-pubkey')
    const expired = inviteOfDay(w.aliceSeed, Math.floor(NOW / DAY) - 45).auth
    // encrypted to a password that is not among the valid ones: not ours, so it is just a message we cannot open
    expect(await handleSecureJoin(await w.requestPubkey(expired), w.from, w.context)).toBeUndefined()
  })

  test('nothing is answered or learned for: an unknown auth token, a fingerprint that is not the key sent, a signature by another key, a key for another address', async () => {
    const w = await world()
    const other = await derivePgpKey(seed(), 'bob@x.test')
    for (const bad of [
      await w.requestWithAuth({ auth: 'A'.repeat(24) }),
      await w.requestWithAuth({ fingerprint: other.fingerprint }),
      await w.requestWithAuth({ signer: other.privateKey }),
      await w.requestWithAuth({ addr: 'eve@x.test' }),
    ]) await expect(handleSecureJoin(bad, w.from, w.context)).rejects.toThrow()
    expect(w.sent).toHaveLength(0)
    expect(w.learned).toHaveLength(0)
  })

  test('a password message with a valid password but the wrong step is refused; ordinary mail is left alone', async () => {
    const w = await world()
    const wrongStep = await symmetricEncryptSigned(buildInnerMime({ lines: ['Secure-Join: vc-pubkey', `Secure-Join-Auth: ${w.auth}`], text: 'x' }), sharedSecret(w.alice.fingerprint, w.auth), w.bob.privateKey)
    await expect(handleSecureJoin(wrongStep, w.from, w.context)).rejects.toThrow('vc-request-pubkey')
    const ordinary = await encryptMessage({ plaintext: buildInnerMime({ headers: [['Subject', 'hi']], text: 'hello' }), recipients: [(await openpgp.readKey({ armoredKey: w.alice.publicArmor })).write()], signer: w.bob.privateKey })
    expect(await handleSecureJoin(ordinary, w.from, w.context)).toBeUndefined()
    const toSomeoneElse = await encryptMessage({ plaintext: 'x', recipients: [w.bobPublic], signer: w.bob.privateKey })
    expect(await handleSecureJoin(toSomeoneElse, w.from, w.context)).toBeUndefined()
    expect(w.sent).toHaveLength(0)
  })
})
