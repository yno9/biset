import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { mailSubmissionSigningBytes } from '../../src/shared/protocol/signing.ts'
import {
  decodeMailSubmissionRequestWire, decodeMailSubmissionResultWire,
  encodeMailSubmissionRequestWire, encodeMailSubmissionResultWire,
} from '../../src/shared/protocol/mail-submission-wire.ts'
import type { MailSubmissionRequestV1, MailSubmissionResultV1 } from '../../src/shared/protocol/mail-submission.ts'

describe('mail submission wire', () => {
  test('request round-trips through encode/decode', () => {
    const privateKey = ed25519.utils.randomSecretKey()
    const unsigned = {
      version: 1 as const, identityId: 'did:web:alice.example', deviceId: 'did:web:alice.example#device-a',
      mailFrom: 'alice@mail.example.test', rcptTo: ['bob@mail.other.test'],
      rawRfc5322: new TextEncoder().encode('Subject: hi\r\n\r\nbody'), submittedAt: '2026-08-24T00:00:00.000Z',
    }
    const request: MailSubmissionRequestV1 = { ...unsigned, signature: ed25519.sign(mailSubmissionSigningBytes(unsigned), privateKey) }
    const decoded = decodeMailSubmissionRequestWire(encodeMailSubmissionRequestWire(request))
    expect(decoded).toEqual(request)
  })

  test('result round-trips through encode/decode', () => {
    const result: MailSubmissionResultV1 = { status: 'accepted', occurredAt: '2026-08-24T00:00:00.000Z' }
    expect(decodeMailSubmissionResultWire(encodeMailSubmissionResultWire(result))).toEqual(result)
    const failed: MailSubmissionResultV1 = { status: 'temporary-failure', occurredAt: '2026-08-24T00:00:00.000Z', detail: 'no MX' }
    expect(decodeMailSubmissionResultWire(encodeMailSubmissionResultWire(failed))).toEqual(failed)
  })

  test('rejects an empty rcptTo', () => {
    const unsigned = {
      version: 1 as const, identityId: 'did:web:alice.example', deviceId: 'did:web:alice.example#device-a',
      mailFrom: 'alice@mail.example.test', rcptTo: [] as string[],
      rawRfc5322: new TextEncoder().encode('x'), submittedAt: '2026-08-24T00:00:00.000Z',
    }
    const request = { ...unsigned, signature: new Uint8Array(64) } as MailSubmissionRequestV1
    expect(() => encodeMailSubmissionRequestWire(request)).toThrow()
  })
})
