// anoncrypt (ECDH-ES+A256KW) round-trip -- Forward wrapping's crypto layer
// (ARC.md's DIDComm mediator redesign, 2026-08-27 Phase 2). Locks in: a
// self-consistent round-trip, that unpackAnoncrypt correctly finds no
// sender to authenticate (anoncrypt's whole point), and -- since we must
// consume XC20P even though we never produce it (didcomm-rust's own
// default `enc` for anoncrypt, this file's own header) -- that a hand-built
// XC20P envelope from a hypothetical third-party sender still decrypts.
import { describe, expect, test } from 'bun:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import {
  packAnoncrypt, unpackAnoncrypt, b64urlToBytes, b64url, __internal, type DidCommJWE,
} from '../src/shared/didcomm/crypto.ts'

const recipientPriv = x25519.utils.randomSecretKey()
const recipientPub = x25519.getPublicKey(recipientPriv)
const routingKid = 'did:webvh:mediator#routing-1'
const plaintext = new TextEncoder().encode(JSON.stringify({ type: 'https://didcomm.org/routing/2.0/forward', body: { next: 'did:webvh:alice#k_devicehash' } }))

describe('DIDComm anoncrypt (ECDH-ES+A256KW)', () => {
  test('round-trips plaintext with no sender to authenticate', async () => {
    const jwe = packAnoncrypt(plaintext, { kid: routingKid, publicKey: recipientPub })
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
    expect(header.alg).toBe('ECDH-ES+A256KW')
    expect(header.skid).toBeUndefined()
    expect(header.apu).toBeUndefined()

    const out = await unpackAnoncrypt(jwe, { kid: routingKid, privateKey: recipientPriv })
    expect(out).toEqual(plaintext)
  })

  test('rejects a tampered ciphertext rather than silently decrypting garbage', async () => {
    const jwe = packAnoncrypt(plaintext, { kid: routingKid, publicKey: recipientPub })
    const tampered: DidCommJWE = { ...jwe, ciphertext: b64url(crypto.getRandomValues(new Uint8Array(b64urlToBytes(jwe.ciphertext).length))) }
    await expect(unpackAnoncrypt(tampered, { kid: routingKid, privateKey: recipientPriv })).rejects.toThrow()
  })

  test('rejects an unexpected alg', async () => {
    const jwe = packAnoncrypt(plaintext, { kid: routingKid, publicKey: recipientPub })
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
    const tampered: DidCommJWE = { ...jwe, protected: b64url(new TextEncoder().encode(JSON.stringify({ ...header, alg: 'ECDH-1PU+A256KW' }))) }
    await expect(unpackAnoncrypt(tampered, { kid: routingKid, privateKey: recipientPriv })).rejects.toThrow('unexpected alg')
  })

  // We only ever PRODUCE A256CBC-HS512 (packAnoncrypt never reaches for
  // XC20P), but didcomm-rust -- the reference implementation, hence most
  // third-party agents -- defaults anoncrypt's `enc` to XC20P, so unpack
  // must still read it. Hand-built here since nothing in this codebase
  // ever constructs one.
  test('decrypts a third-party XC20P anoncrypt envelope', async () => {
    const alg = 'ECDH-ES+A256KW'
    const ephemPriv = x25519.utils.randomSecretKey()
    const ephemPub = x25519.getPublicKey(ephemPriv)
    const apv = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(routingKid)))
    const header = { typ: 'application/didcomm-encrypted+json', alg, enc: 'XC20P', apv: b64url(apv), epk: { kty: 'OKP', crv: 'X25519', x: b64url(ephemPub) } }
    const protectedB64 = b64url(new TextEncoder().encode(JSON.stringify(header)))

    const cek = crypto.getRandomValues(new Uint8Array(32))
    const iv = crypto.getRandomValues(new Uint8Array(24))
    const aad = new TextEncoder().encode(protectedB64)
    const sealed = xchacha20poly1305(cek, iv, aad).encrypt(plaintext)
    const ciphertext = sealed.slice(0, sealed.length - 16)
    const tag = sealed.slice(sealed.length - 16)

    const z = __internal.ecdh(ephemPriv, recipientPub)
    const kek = __internal.deriveEcdhEs(z, alg, new Uint8Array(0), apv, 256)
    const { aeskw } = await import('@noble/ciphers/aes.js')
    const encryptedKey = aeskw(kek).encrypt(cek)

    const jwe: DidCommJWE = {
      protected: protectedB64,
      recipients: [{ header: { kid: routingKid }, encrypted_key: b64url(encryptedKey) }],
      iv: b64url(iv),
      ciphertext: b64url(ciphertext),
      tag: b64url(tag),
    }

    const out = await unpackAnoncrypt(jwe, { kid: routingKid, privateKey: recipientPriv })
    expect(out).toEqual(plaintext)
  })
})
