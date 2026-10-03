// DIDComm Messaging v2.1 Appendix C.3 test vectors (multi-recipient JWEs to
// three X25519 keys of one DID), checked against this implementation. These
// are the interop anchor for multiplexed encryption: one ciphertext, one CEK
// wrapped per recipient key, any of Bob's devices can open it.
import { describe, expect, test } from 'bun:test'
import vectors from '../fixtures/didcomm-v2.1-x25519-vectors.json'
import { x25519 } from '@noble/curves/ed25519.js'
import { b64urlToBytes, packAnoncrypt, packAuthcrypt, protectedHeaderOf, unpackAnoncrypt, unpackAuthcrypt, type DidCommJWE } from '../../src/protocol/didcomm/crypto.ts'

const decode = (bytes: Uint8Array) => JSON.parse(new TextDecoder().decode(bytes))
const alicePublic = b64urlToBytes(vectors.aliceX25519.x)

describe('DIDComm v2.1 Appendix C.3 vectors', () => {
  for (const bob of vectors.bobX25519) {
    test(`anoncrypt (ECDH-ES+A256KW, XC20P) opens with ${bob.kid}`, async () => {
      const plaintext = await unpackAnoncrypt(vectors.anoncryptX25519Xc20p as DidCommJWE, { kid: bob.kid, privateKey: b64urlToBytes(bob.d) })
      expect(decode(plaintext)).toEqual(vectors.plaintext)
    })
    test(`authcrypt (ECDH-1PU+A256KW, A256CBC-HS512) opens with ${bob.kid} and names Alice`, async () => {
      const { plaintext, senderKid } = await unpackAuthcrypt(vectors.authcryptX25519A256cbcHs512 as DidCommJWE, { kid: bob.kid, privateKey: b64urlToBytes(bob.d) }, async kid => {
        expect(kid).toBe(vectors.aliceX25519.kid)
        return alicePublic
      })
      expect(senderKid).toBe(vectors.aliceX25519.kid)
      expect(decode(plaintext)).toEqual(vectors.plaintext)
    })
  }
})

describe('multi-recipient pack', () => {
  const bobs = vectors.bobX25519.map(b => ({ kid: b.kid, privateKey: b64urlToBytes(b.d), publicKey: b64urlToBytes(b.x) }))
  const alice = { kid: vectors.aliceX25519.kid, privateKey: b64urlToBytes(vectors.aliceX25519.d) }
  const bytes = new TextEncoder().encode(JSON.stringify(vectors.plaintext))
  // Recipient order must not matter to apv (the spec sorts the kids).
  const shuffled = [bobs[2]!, bobs[0]!, bobs[1]!]

  test('apv is the spec digest of the sorted recipient kids', () => {
    const want = (protectedHeaderOf(vectors.authcryptX25519A256cbcHs512 as DidCommJWE) as { apv: string }).apv
    expect(protectedHeaderOf(packAuthcrypt(bytes, alice, shuffled))!.apv).toBe(want)
    expect(protectedHeaderOf(packAnoncrypt(bytes, shuffled))!.apv).toBe(want)
  })

  test('one authcrypt JWE opens with every recipient key', async () => {
    const jwe = packAuthcrypt(bytes, alice, shuffled)
    expect(jwe.recipients.map(r => r.header.kid)).toEqual(shuffled.map(b => b.kid))
    for (const bob of bobs) {
      const { plaintext, senderKid } = await unpackAuthcrypt(jwe, bob, async () => x25519.getPublicKey(alice.privateKey))
      expect(senderKid).toBe(alice.kid)
      expect(decode(plaintext)).toEqual(vectors.plaintext)
    }
  })

  test('one anoncrypt JWE opens with every recipient key', async () => {
    const jwe = packAnoncrypt(bytes, shuffled)
    for (const bob of bobs) expect(decode(await unpackAnoncrypt(jwe, bob))).toEqual(vectors.plaintext)
  })

  test('a JWE whose recipients list was trimmed is refused (apv mismatch)', async () => {
    const jwe = packAuthcrypt(bytes, alice, bobs)
    const trimmed = { ...jwe, recipients: jwe.recipients.slice(0, 1) }
    await expect(unpackAuthcrypt(trimmed, bobs[0]!, async () => x25519.getPublicKey(alice.privateKey))).rejects.toThrow('apv does not match')
    const anon = packAnoncrypt(bytes, bobs)
    await expect(unpackAnoncrypt({ ...anon, recipients: anon.recipients.slice(1) }, bobs[1]!)).rejects.toThrow('apv does not match')
  })

  test('empty or duplicate recipients are refused', () => {
    expect(() => packAuthcrypt(bytes, alice, [])).toThrow('no recipients')
    expect(() => packAnoncrypt(bytes, [bobs[0]!, bobs[0]!])).toThrow('duplicate recipient kid')
  })
})
