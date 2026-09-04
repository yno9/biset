import { describe, expect, test } from 'bun:test'
import { base64urlToBytes, bytesToBase64url, canonicalHash, canonicalJson, domainHash, equalBytes } from '../../src/shared/protocol/canonical.ts'
import { assertIngressEnvelope, ProtocolValidationError } from '../../src/shared/protocol/validate.ts'

describe('protocol canonical encoding', () => {
  test('sorts object keys without changing array order', () => {
    expect(canonicalJson({ zebra: [2, 1], alpha: { b: true, a: null } }))
      .toBe('{"alpha":{"a":null,"b":true},"zebra":[2,1]}')
  })

  test('binds hashes to their domain label', () => {
    const body = new TextEncoder().encode('biset')
    expect(domainHash('biset/vault/object/v1', body)).not.toBe(domainHash('biset/ingress/v1', body))
    expect(canonicalHash('biset/vault/object/v1', { a: 1, b: 2 }))
      .toBe(canonicalHash('biset/vault/object/v1', { b: 2, a: 1 }))
  })

  test('compares bytes without accepting a prefix', () => {
    expect(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true)
    expect(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false)
  })

  test('round-trips long base64url byte sequences without padding', () => {
    const bytes = new Uint8Array(513)
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = index & 0xff
    expect(base64urlToBytes(bytesToBase64url(bytes))).toEqual(bytes)
    expect(() => base64urlToBytes('A')).toThrow('invalid base64url')
    expect(() => base64urlToBytes('AB')).toThrow('trailing bits')
  })
})

describe('IngressEnvelopeV1 validation', () => {
  test('accepts the minimal valid envelope', () => {
    const envelope = {
      version: 1,
      ingressId: 'ingress-1',
      protocol: 'mail',
      recipientIdentityId: 'did:webvh:example:alice',
      recipientDeviceSnapshot: ['device-a'],
      createdAt: '2026-08-21T00:00:00.000Z',
      expiresAt: '2026-08-22T00:00:00.000Z',
      transportMetadata: { messageId: '<example@example.test>' },
      sourceEvidence: new Uint8Array([1]),
      protectedPayload: new Uint8Array([2]),
      protectedPayloadHash: new Uint8Array([3]),
    }
    expect(() => assertIngressEnvelope(envelope)).not.toThrow()
  })

  test('rejects a duplicate recipient device', () => {
    const envelope = {
      version: 1,
      ingressId: 'ingress-1',
      protocol: 'mail',
      recipientIdentityId: 'did:webvh:example:alice',
      recipientDeviceSnapshot: ['device-a', 'device-a'],
      createdAt: '2026-08-21T00:00:00.000Z',
      expiresAt: '2026-08-22T00:00:00.000Z',
      transportMetadata: {},
      sourceEvidence: new Uint8Array([1]),
      protectedPayload: new Uint8Array([2]),
      protectedPayloadHash: new Uint8Array([3]),
    }
    expect(() => assertIngressEnvelope(envelope)).toThrow(ProtocolValidationError)
  })
})
