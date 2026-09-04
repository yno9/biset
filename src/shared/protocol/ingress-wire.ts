import { base64urlToBytes, bytesToBase64url } from './canonical.ts'
import type { IngressAckV1, IngressEnvelopeV1, IngressPullV1 } from './ingress.ts'
import { assertIngressAck, assertIngressEnvelope, assertIngressPull } from './validate.ts'

/** Strict JSON boundary for an endpoint's bounded ingress receive API. */
export function encodeIngressPullWire(value: IngressPullV1): string {
  assertIngressPull(value)
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeIngressPullWire(text: string): IngressPullV1 {
  const input = record(text)
  const value = { ...input, signature: binary(input.signature) }
  assertIngressPull(value)
  return value
}

export function encodeIngressAckWire(value: IngressAckV1): string {
  assertIngressAck(value)
  return JSON.stringify({ ...value, protectedPayloadHash: bytesToBase64url(value.protectedPayloadHash), signature: bytesToBase64url(value.signature) })
}

export function decodeIngressAckWire(text: string): IngressAckV1 {
  const input = record(text)
  const value = { ...input, protectedPayloadHash: binary(input.protectedPayloadHash), signature: binary(input.signature) }
  assertIngressAck(value)
  return value
}

export function encodeIngressPullResultWire(values: IngressEnvelopeV1[]): string {
  return JSON.stringify({ items: values.map(envelopeToWire) })
}

export function decodeIngressPullResultWire(text: string): IngressEnvelopeV1[] {
  const input = record(text)
  if (!Array.isArray(input.items)) throw new TypeError('invalid ingress pull response')
  return input.items.map(wireToEnvelope)
}

function envelopeToWire(value: IngressEnvelopeV1): Record<string, unknown> {
  assertIngressEnvelope(value)
  return {
    ...value,
    sourceEvidence: bytesToBase64url(value.sourceEvidence),
    protectedPayload: bytesToBase64url(value.protectedPayload),
    protectedPayloadHash: bytesToBase64url(value.protectedPayloadHash),
  }
}

function wireToEnvelope(value: unknown): IngressEnvelopeV1 {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('invalid ingress envelope response')
  const input = value as Record<string, unknown>
  const result = {
    ...input,
    sourceEvidence: binary(input.sourceEvidence),
    protectedPayload: binary(input.protectedPayload),
    protectedPayloadHash: binary(input.protectedPayloadHash),
  }
  assertIngressEnvelope(result)
  return result
}

function record(text: string): Record<string, unknown> {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new TypeError('ingress HTTP body is not JSON') }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('ingress HTTP body must be an object')
  return value as Record<string, unknown>
}

function binary(value: unknown): Uint8Array {
  if (typeof value !== 'string') throw new TypeError('ingress HTTP binary field is invalid')
  return base64urlToBytes(value)
}
