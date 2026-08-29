// Round-trip DKIM verification tests: this file signs its own fixture
// messages (RSA and Ed25519) using the exact same canonicalization
// exports as dkim.ts, then verifies them through verifyDkimSignatures
// with an injected fake DNS resolver -- no network involved.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifyDkimSignatures, parseHeaders, canonicalizeHeaderRelaxed, canonicalizeBodyRelaxed, type RawHeader } from '../../src/mail-mediator/dkim.ts'
import { buildSignedMessage, latin1ToBytes, bytesToBase64 } from './support/dkim-fixture.ts'

const FIXTURE_HEADERS: RawHeader[] = [
  { name: 'From', value: ' alice@example.com' },
  { name: 'To', value: ' bob@biset.md' },
  { name: 'Subject', value: ' hello' },
  { name: 'Date', value: ' Mon, 01 Jan 2026 00:00:00 +0000' },
]
const FIXTURE_BODY = 'Hello world\r\n'

describe('verifyDkimSignatures', () => {
  test('verifies a valid rsa-sha256 signature', async () => {
    const keyPair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey))
    const raw = await buildSignedMessage(FIXTURE_HEADERS, FIXTURE_BODY, {
      domain: 'example.com', selector: 'sel1', algorithm: 'rsa-sha256',
      sign: async input => new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keyPair.privateKey, input.slice().buffer)),
    })
    const results = await verifyDkimSignatures(raw, {
      resolveTxt: async name => name === 'sel1._domainkey.example.com' ? [`v=DKIM1; k=rsa; p=${bytesToBase64(spki)}`] : [],
    })
    expect(results).toEqual([{ domain: 'example.com', selector: 'sel1', algorithm: 'rsa-sha256' }])
  })

  test('verifies a valid ed25519-sha256 signature', async () => {
    const privateKey = ed25519.utils.randomSecretKey()
    const publicKey = ed25519.getPublicKey(privateKey)
    const raw = await buildSignedMessage(FIXTURE_HEADERS, FIXTURE_BODY, {
      domain: 'example.com', selector: 'sel1', algorithm: 'ed25519-sha256',
      sign: input => ed25519.sign(input, privateKey),
    })
    const results = await verifyDkimSignatures(raw, {
      resolveTxt: async name => name === 'sel1._domainkey.example.com' ? [`v=DKIM1; k=ed25519; p=${bytesToBase64(publicKey)}`] : [],
    })
    expect(results).toEqual([{ domain: 'example.com', selector: 'sel1', algorithm: 'ed25519-sha256' }])
  })

  test('a tampered body fails verification', async () => {
    const privateKey = ed25519.utils.randomSecretKey()
    const publicKey = ed25519.getPublicKey(privateKey)
    const raw = await buildSignedMessage(FIXTURE_HEADERS, FIXTURE_BODY, {
      domain: 'example.com', selector: 'sel1', algorithm: 'ed25519-sha256',
      sign: input => ed25519.sign(input, privateKey),
    })
    const tampered = new TextDecoder('latin1').decode(raw).replace('Hello world', 'Goodbye world')
    const results = await verifyDkimSignatures(latin1ToBytes(tampered), {
      resolveTxt: async () => [`v=DKIM1; k=ed25519; p=${bytesToBase64(publicKey)}`],
    })
    expect(results).toEqual([])
  })

  test('a tampered header fails verification', async () => {
    const privateKey = ed25519.utils.randomSecretKey()
    const publicKey = ed25519.getPublicKey(privateKey)
    const raw = await buildSignedMessage(FIXTURE_HEADERS, FIXTURE_BODY, {
      domain: 'example.com', selector: 'sel1', algorithm: 'ed25519-sha256',
      sign: input => ed25519.sign(input, privateKey),
    })
    const tampered = new TextDecoder('latin1').decode(raw).replace('alice@example.com', 'mallory@example.com')
    const results = await verifyDkimSignatures(latin1ToBytes(tampered), {
      resolveTxt: async () => [`v=DKIM1; k=ed25519; p=${bytesToBase64(publicKey)}`],
    })
    expect(results).toEqual([])
  })

  test('a wrong public key fails verification', async () => {
    const privateKey = ed25519.utils.randomSecretKey()
    const wrongPublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const raw = await buildSignedMessage(FIXTURE_HEADERS, FIXTURE_BODY, {
      domain: 'example.com', selector: 'sel1', algorithm: 'ed25519-sha256',
      sign: input => ed25519.sign(input, privateKey),
    })
    const results = await verifyDkimSignatures(raw, {
      resolveTxt: async () => [`v=DKIM1; k=ed25519; p=${bytesToBase64(wrongPublicKey)}`],
    })
    expect(results).toEqual([])
  })

  test('no DNS record at all yields no verified signatures', async () => {
    const privateKey = ed25519.utils.randomSecretKey()
    const raw = await buildSignedMessage(FIXTURE_HEADERS, FIXTURE_BODY, {
      domain: 'example.com', selector: 'sel1', algorithm: 'ed25519-sha256',
      sign: input => ed25519.sign(input, privateKey),
    })
    const results = await verifyDkimSignatures(raw, { resolveTxt: async () => [] })
    expect(results).toEqual([])
  })

  test('an explicitly revoked key (empty p=) yields no verified signatures', async () => {
    const privateKey = ed25519.utils.randomSecretKey()
    const raw = await buildSignedMessage(FIXTURE_HEADERS, FIXTURE_BODY, {
      domain: 'example.com', selector: 'sel1', algorithm: 'ed25519-sha256',
      sign: input => ed25519.sign(input, privateKey),
    })
    const results = await verifyDkimSignatures(raw, { resolveTxt: async () => ['v=DKIM1; k=ed25519; p='] })
    expect(results).toEqual([])
  })

  test('a message with no DKIM-Signature header yields no results', async () => {
    const raw = `From: alice@example.com\r\nTo: bob@biset.md\r\n\r\nno signature here\r\n`
    expect(await verifyDkimSignatures(new TextEncoder().encode(raw))).toEqual([])
  })

  test('rejects a signature declaring simple canonicalization (out of scope)', async () => {
    const privateKey = ed25519.utils.randomSecretKey()
    const publicKey = ed25519.getPublicKey(privateKey)
    const raw = await buildSignedMessage(FIXTURE_HEADERS, FIXTURE_BODY, {
      domain: 'example.com', selector: 'sel1', algorithm: 'ed25519-sha256',
      sign: input => ed25519.sign(input, privateKey),
    })
    const withSimple = new TextDecoder('latin1').decode(raw).replace('c=relaxed/relaxed', 'c=simple/simple')
    const results = await verifyDkimSignatures(latin1ToBytes(withSimple), {
      resolveTxt: async () => [`v=DKIM1; k=ed25519; p=${bytesToBase64(publicKey)}`],
    })
    expect(results).toEqual([])
  })

  test('rejects a signature declaring a body length limit (l=)', async () => {
    const privateKey = ed25519.utils.randomSecretKey()
    const publicKey = ed25519.getPublicKey(privateKey)
    const raw = await buildSignedMessage(FIXTURE_HEADERS, FIXTURE_BODY, {
      domain: 'example.com', selector: 'sel1', algorithm: 'ed25519-sha256',
      sign: input => ed25519.sign(input, privateKey),
    })
    const withL = new TextDecoder('latin1').decode(raw).replace('DKIM-Signature:', 'DKIM-Signature: l=100;')
    const results = await verifyDkimSignatures(latin1ToBytes(withL), {
      resolveTxt: async () => [`v=DKIM1; k=ed25519; p=${bytesToBase64(publicKey)}`],
    })
    expect(results).toEqual([])
  })
})

describe('parseHeaders / canonicalizeHeaderRelaxed / canonicalizeBodyRelaxed', () => {
  test('unfolds a continuation line and collapses internal whitespace', () => {
    const headers = parseHeaders('Subject: hello\r\n  world\r\nFrom:  alice@example.com  ')
    expect(headers).toEqual([{ name: 'Subject', value: ' hello\r\n  world' }, { name: 'From', value: '  alice@example.com  ' }])
    expect(canonicalizeHeaderRelaxed(headers[0]!)).toBe('subject:hello world')
    expect(canonicalizeHeaderRelaxed(headers[1]!)).toBe('from:alice@example.com')
  })

  test('body canonicalization trims trailing whitespace and empty lines', () => {
    expect(canonicalizeBodyRelaxed('a  b \r\nc\r\n\r\n\r\n')).toBe('a b\r\nc\r\n')
    expect(canonicalizeBodyRelaxed('')).toBe('')
    expect(canonicalizeBodyRelaxed('\r\n\r\n')).toBe('')
  })
})
