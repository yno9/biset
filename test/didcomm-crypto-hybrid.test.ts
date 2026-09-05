// Hybrid (X25519 + ML-KEM-768) authcrypt round-trip (PLAN.md "did:webvh
// PQハイブリッド化", Phase 2) — no RFC test vectors exist for this
// biset-specific construction, so this locks in a self-consistent round-trip
// plus the properties the design depends on: tamper detection on the KEM
// ciphertext, and that a non-hybrid peer's plain packAuthcrypt/unpackAuthcrypt
// path is completely unaffected (the fallback the hybrid design requires).
import { describe, expect, test } from 'bun:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import {
  packAuthcrypt, unpackAuthcrypt, packAuthcryptHybrid, unpackAuthcryptHybrid,
  b64urlToBytes, b64url, type DidCommJWE,
} from '../src/shared/didcomm/crypto.ts'

const senderX = x25519.utils.randomSecretKey()
const senderXPub = x25519.getPublicKey(senderX)
const senderKid = 'did:webvh:alice#k1'

const recipientX = x25519.utils.randomSecretKey()
const recipientXPub = x25519.getPublicKey(recipientX)
const recipientKem = ml_kem768.keygen()
const recipientKid = 'did:webvh:bob#k1'

const resolveSenderKey = async (kid: string) => {
  if (kid !== senderKid) throw new Error('unexpected sender kid ' + kid)
  return senderXPub
}

const plaintext = new TextEncoder().encode(JSON.stringify({ hello: 'world', n: 42 }))

describe('DIDComm hybrid (X25519 + ML-KEM-768) authcrypt', () => {
  test('round-trips plaintext and reports the sender kid, with the hybrid alg and pqKem ciphertext in the header', async () => {
    const jwe = packAuthcryptHybrid(plaintext, { kid: senderKid, privateKey: senderX }, {
      kid: recipientKid, x25519PublicKey: recipientXPub, mlkemPublicKey: recipientKem.publicKey,
    })
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
    expect(header.alg).toBe('ECDH-1PU-X25519MLKEM768+A256KW')
    expect(b64urlToBytes(header.pqKem.ct).length).toBe(1088) // ML-KEM-768 ciphertext size

    const { plaintext: out, senderKid: outKid } = await unpackAuthcryptHybrid(jwe, {
      kid: recipientKid, x25519PrivateKey: recipientX, mlkemPrivateKey: recipientKem.secretKey,
    }, resolveSenderKey)
    expect(out).toEqual(plaintext)
    expect(outKid).toBe(senderKid)
  })

  test('rejects a tampered pqKem.ct rather than silently decrypting with the wrong shared secret', async () => {
    const jwe = packAuthcryptHybrid(plaintext, { kid: senderKid, privateKey: senderX }, {
      kid: recipientKid, x25519PublicKey: recipientXPub, mlkemPublicKey: recipientKem.publicKey,
    })
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
    // Tamper with pqKem.ct -- decapsulation must not silently succeed with a
    // DIFFERENT shared secret and let AEAD catch it; either way unpack must
    // reject (decapsulate can throw on a malformed ciphertext, or succeed
    // with a wrong Zpq and let the tag mismatch catch it downstream -- both
    // are acceptable, "unpack succeeds" is not).
    const tampered: DidCommJWE = { ...jwe, protected: b64url(new TextEncoder().encode(JSON.stringify({
      ...header, pqKem: { ...header.pqKem, ct: b64url(crypto.getRandomValues(new Uint8Array(1088))) },
    }))) }
    await expect(unpackAuthcryptHybrid(tampered, {
      kid: recipientKid, x25519PrivateKey: recipientX, mlkemPrivateKey: recipientKem.secretKey,
    }, resolveSenderKey)).rejects.toThrow()
  })

  test('leaves the plain (non-hybrid) packAuthcrypt/unpackAuthcrypt path unaffected, with no pqKem field', async () => {
    const jwe = packAuthcrypt(plaintext, { kid: senderKid, privateKey: senderX }, { kid: recipientKid, publicKey: recipientXPub })
    const { plaintext: out } = await unpackAuthcrypt(jwe, { kid: recipientKid, privateKey: recipientX }, resolveSenderKey)
    expect(out).toEqual(plaintext)
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
    expect(header.pqKem).toBeUndefined()
  })
})
