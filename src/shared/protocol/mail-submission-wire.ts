import { base64urlToBytes, bytesToBase64url } from './canonical.ts'
import type { MailSubmissionRequestV1, MailSubmissionResultV1 } from './mail-submission.ts'
import { assertMailSubmissionRequest } from './validate.ts'

export function encodeMailSubmissionRequestWire(value: MailSubmissionRequestV1): string {
  assertMailSubmissionRequest(value)
  return JSON.stringify({ ...value, rawRfc5322: bytesToBase64url(value.rawRfc5322), signature: bytesToBase64url(value.signature) })
}

export function decodeMailSubmissionRequestWire(text: string): MailSubmissionRequestV1 {
  const input = record(text)
  const value = { ...input, rawRfc5322: binary(input.rawRfc5322), signature: binary(input.signature) }
  assertMailSubmissionRequest(value)
  return value
}

export function encodeMailSubmissionResultWire(value: MailSubmissionResultV1): string {
  return JSON.stringify(value)
}

export function decodeMailSubmissionResultWire(text: string): MailSubmissionResultV1 {
  const input = record(text)
  if (input.status !== 'accepted' && input.status !== 'temporary-failure') throw new TypeError('invalid mail submission result status')
  if (typeof input.occurredAt !== 'string') throw new TypeError('invalid mail submission result occurredAt')
  if (input.detail !== undefined && typeof input.detail !== 'string') throw new TypeError('invalid mail submission result detail')
  return { status: input.status, occurredAt: input.occurredAt, ...(input.detail === undefined ? {} : { detail: input.detail }) }
}

function record(text: string): Record<string, unknown> {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    throw new TypeError('invalid mail submission JSON')
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('mail submission wire value must be an object')
  return value as Record<string, unknown>
}

function binary(value: unknown): Uint8Array {
  if (typeof value !== 'string') throw new TypeError('expected a base64url string')
  return base64urlToBytes(value)
}
