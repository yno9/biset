import { describe, expect, test } from 'vitest'
import * as openpgp from 'openpgp'
import { decryptMessage } from '../src/client/pgp/message-crypto.ts'
import { parseInnerMime, parseKeydataHeader } from '../src/client/pgp/mime.ts'
import { derivePgpKey } from '../src/client/pgp/derive.ts'
import { autocryptKeydata } from '../src/client/pgp/keyring.ts'
import { handleSecureJoin, inviteUrl, type SecureJoinContext } from '../src/client/pgp/securejoin.ts'
import { beginJoin, handleJoinStep, InviteError, parseInvite, PENDING_HOURS, type JoinContext, type PendingJoin } from '../src/client/pgp/securejoin-join.ts'

const NOW = Date.parse('2026-10-21T12:00:00Z')
const seed = () => crypto.getRandomValues(new Uint8Array(32))

/** We are Bob (joining); Alice is the inviter, answered by the other half of the protocol (securejoin.ts). */
async function world() {
  const aliceSeed = seed()
  const alice = await derivePgpKey(aliceSeed, 'alice@x.test')
  const bob = await derivePgpKey(seed(), 'bob@did.md')
  const aliceParty = { did: 'did:web:did.md:x.test:alice', address: 'alice@x.test' }
  const bobParty = { did: 'did:web:did.md:did.md:bob', address: 'bob@did.md' }
  const toAlice: Array<{ armored: string; introduction?: boolean }> = []
  const toBob: string[] = []
  const bobLearned: string[] = []
  const bobNames: Array<string | undefined> = []
  const aliceLearned: string[] = []
  const pending = new Map<string, PendingJoin>()
  const bobContext: JoinContext = {
    key: bob, address: 'bob@did.md', now: NOW,
    pending: { list: async () => [...pending.values()], put: async join => { pending.set(join.address, join) }, remove: async address => { pending.delete(address) } },
    async send(_to, armored, options) { toAlice.push({ armored, ...(options.introduction ? { introduction: true } : {}) }) },
    async learn(_party, keydata, name) { bobLearned.push(keydata); bobNames.push(name) },
  }
  const aliceContext: SecureJoinContext = {
    seed: aliceSeed, key: alice, address: 'alice@x.test', now: NOW,
    async send(_to, armored) { toBob.push(armored) },
    async learn(_party, keydata) { aliceLearned.push(keydata) },
  }
  const url = inviteUrl({ seed: aliceSeed, key: alice, address: 'alice@x.test', name: 'Alice', now: NOW })
  return { alice, bob, aliceParty, bobParty, toAlice, toBob, bobLearned, bobNames, aliceLearned, pending, bobContext, aliceContext, url }
}

describe('the invite we are given', () => {
  test('reads the link our own inviter makes, and the OPENPGP4FPR form', async () => {
    const w = await world()
    expect(parseInvite(w.url)).toMatchObject({ fingerprint: w.alice.fingerprint, address: 'alice@x.test', name: 'Alice' })
    const fp = 'AB'.repeat(20)
    expect(parseInvite(`OPENPGP4FPR:${fp}#a=a%2Bb%40x.test&n=Al+B&i=inv&s=${'x'.repeat(24)}&v=3`)).toEqual({ fingerprint: fp, auth: 'x'.repeat(24), address: 'a+b@x.test', name: 'Al B' })
  })

  test('refuses what it cannot follow: an old invite, a group, a broken one', () => {
    const fp = 'AB'.repeat(20), s = 'x'.repeat(24)
    expect(() => parseInvite(`https://i.delta.chat/#${fp}&a=a%40x.test&i=1&s=${s}`)).toThrow(/older/)
    expect(() => parseInvite(`https://i.delta.chat/#${fp}&a=a%40x.test&i=1&s=${s}&v=3&x=group&g=name`)).toThrow(InviteError)
    expect(() => parseInvite(`https://i.delta.chat/#12345&a=a%40x.test&s=${s}&v=3`)).toThrow(/fingerprint/)
    expect(() => parseInvite(`https://i.delta.chat/#${fp}&a=nobody&s=${s}&v=3`)).toThrow(/address/)
    expect(() => parseInvite('hello')).toThrow(InviteError)
  })
})

describe('Secure-Join, the joining side, against the inviting side', () => {
  test('the four steps end with each holding the other\'s key, ours as verified', async () => {
    const w = await world()
    await beginJoin(parseInvite(w.url), w.aliceParty, w.bobContext)
    expect(w.toAlice).toHaveLength(1)
    expect(w.toAlice[0]!.introduction).toBe(true)

    expect(await handleSecureJoin(w.toAlice[0]!.armored, w.bobParty, w.aliceContext)).toBe('vc-request-pubkey')
    // the inviting half, run first on what arrives, leaves the joiner's steps alone
    const bobAsInviter: SecureJoinContext = { seed: seed(), key: w.bob, address: 'bob@did.md', now: NOW, send: async () => {}, learn: async () => {} }
    expect(await handleSecureJoin(w.toBob[0]!, w.aliceParty, bobAsInviter)).toBeUndefined()
    expect(await handleJoinStep(w.toBob[0]!, w.aliceParty, w.bobContext)).toBe('vc-pubkey')
    expect(w.toAlice).toHaveLength(2)
    expect(w.toAlice[1]!.introduction).toBeUndefined()

    // Delta Chat takes the step only with the inviter's own key gossiped in it (securejoin.rs: "No self addr+pubkey gossip found")
    const step3 = parseInnerMime((await decryptMessage({ armored: w.toAlice[1]!.armored, privateKey: w.alice.privateKey })).plaintext)
    expect(step3.gossip).toHaveLength(1)
    const gossiped = parseKeydataHeader(step3.gossip[0]!)!
    expect((await openpgp.readKey({ binaryKey: Uint8Array.from(atob(gossiped.keydata), char => char.charCodeAt(0)) })).getFingerprint().toUpperCase()).toBe(w.alice.fingerprint)
    expect(await handleSecureJoin(w.toAlice[1]!.armored, w.bobParty, w.aliceContext)).toBe('vc-request-with-auth')
    expect(w.aliceLearned).toEqual([await autocryptKeydata(w.bob.privateKey, 'bob@did.md')])
    expect(await handleSecureJoin(w.toBob[1]!, w.aliceParty, bobAsInviter)).toBeUndefined()
    expect(await handleJoinStep(w.toBob[1]!, w.aliceParty, w.bobContext)).toBe('vc-contact-confirm')
    expect(w.bobLearned).toEqual([await autocryptKeydata(w.alice.privateKey, 'alice@x.test')])
    expect(w.bobNames).toEqual(['Alice']) // the name the invite gave
    expect(w.pending.size).toBe(0)
  })

  test('with nothing pending nothing is a step, and a wrong step under the password is refused', async () => {
    const w = await world()
    expect(await handleJoinStep('-----BEGIN PGP MESSAGE-----\n\nx\n-----END PGP MESSAGE-----', w.aliceParty, w.bobContext)).toBeUndefined() // nothing pending
    await beginJoin(parseInvite(w.url), w.aliceParty, w.bobContext)
    // a message under the invite's password that is not vc-pubkey (here our own request played back) is no step
    await expect(handleJoinStep(w.toAlice[0]!.armored, w.aliceParty, w.bobContext)).rejects.toThrow(/vc-pubkey/)
  })

  test('a vc-pubkey with another key than the invite names is refused, and the join stays pending', async () => {
    const w = await world()
    const impostor = await derivePgpKey(seed(), 'alice@x.test')
    await beginJoin(parseInvite(w.url), w.aliceParty, w.bobContext)
    await handleSecureJoin(w.toAlice[0]!.armored, w.bobParty, { ...w.aliceContext, key: { ...impostor, fingerprint: w.alice.fingerprint } })
    await expect(handleJoinStep(w.toBob[0]!, w.aliceParty, w.bobContext)).rejects.toThrow()
    expect(w.pending.get('alice@x.test')?.stage).toBe('requested')
    expect(w.toAlice).toHaveLength(1)
  })

  test('a join older than the pending window is not continued', async () => {
    const w = await world()
    await beginJoin(parseInvite(w.url), w.aliceParty, w.bobContext)
    await handleSecureJoin(w.toAlice[0]!.armored, w.bobParty, w.aliceContext)
    expect(await handleJoinStep(w.toBob[0]!, w.aliceParty, { ...w.bobContext, now: NOW + (PENDING_HOURS + 1) * 3600_000 })).toBeUndefined()
  })
})

test('the answers may come from another address of the inviter (a Delta Chat account has several relays)', async () => {
  const w = await world()
  const elsewhere = { did: 'did:web:did.md:y.test:alice2', address: 'alice2@y.test' }
  const alice2 = { ...w.aliceContext, address: 'alice2@y.test' } // its Autocrypt header names the address it sends from
  await beginJoin(parseInvite(w.url), w.aliceParty, w.bobContext) // the invite names alice@x.test
  await handleSecureJoin(w.toAlice[0]!.armored, w.bobParty, alice2)
  expect(await handleJoinStep(w.toBob[0]!, elsewhere, w.bobContext)).toBe('vc-pubkey')
  await handleSecureJoin(w.toAlice[1]!.armored, w.bobParty, alice2)
  expect(await handleJoinStep(w.toBob[1]!, elsewhere, w.bobContext)).toBe('vc-contact-confirm')
  expect(w.bobLearned).toEqual([await autocryptKeydata(w.alice.privateKey, 'alice2@y.test')])
})
