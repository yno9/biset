// Regression guard: unpackAuthcrypt must reject a message with an
// unsupported `enc` (or an `apv` that disagrees with its recipients) BEFORE ever calling resolveSenderKey --
// a live outbound DID resolve to whatever domain the sender-claimed,
// unverified `apu`/`skid` header names. Getting this ordering backwards lets
// an attacker who merely knows a real, publicly-published recipient kid
// (published keyAgreement entries are meant to be discoverable) trigger
// the recipient's own device into contacting an arbitrary attacker-chosen
// host, for a message that was always going to be rejected anyway (found
// live, 2026-08-26).
import { describe, expect, test } from 'bun:test'
import { x25519 } from '@noble/curves/ed25519.js'
import {
  packAuthcrypt, unpackAuthcrypt,
  b64urlToBytes, b64url, type DidCommJWE,
} from '../src/protocol/didcomm/crypto.ts'

const senderX = x25519.utils.randomSecretKey()
const senderKid = 'did:webvh:alice#k1'
const recipientX = x25519.utils.randomSecretKey()
const recipientXPub = x25519.getPublicKey(recipientX)
const recipientKid = 'did:webvh:bob#k1'
const plaintext = new TextEncoder().encode(JSON.stringify({ hello: 'world' }))

function withTamperedEnc(jwe: DidCommJWE): DidCommJWE {
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
  return { ...jwe, protected: b64url(new TextEncoder().encode(JSON.stringify({ ...header, enc: 'XC20P' }))) }
}

describe('unpack rejects an unsupported enc before resolving the sender key', () => {
  test('unpackAuthcrypt: never calls resolveSenderKey for a bad enc', async () => {
    const jwe = withTamperedEnc(packAuthcrypt(plaintext, { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }]))
    let called = false
    const resolveSenderKey = async () => { called = true; return new Uint8Array(32) }
    await expect(unpackAuthcrypt(jwe, { kid: recipientKid, privateKey: recipientX }, resolveSenderKey)).rejects.toThrow('unsupported enc')
    expect(called).toBe(false)
  })

  test('unpackAuthcrypt: never calls resolveSenderKey for an apv that disagrees with the recipients', async () => {
    const other = x25519.getPublicKey(x25519.utils.randomSecretKey())
    const packed = packAuthcrypt(plaintext, { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }, { kid: 'did:webvh:bob#k2', publicKey: other }])
    const jwe = { ...packed, recipients: packed.recipients.slice(0, 1) }
    let called = false
    const resolveSenderKey = async () => { called = true; return new Uint8Array(32) }
    await expect(unpackAuthcrypt(jwe, { kid: recipientKid, privateKey: recipientX }, resolveSenderKey)).rejects.toThrow('apv does not match')
    expect(called).toBe(false)
  })
})
