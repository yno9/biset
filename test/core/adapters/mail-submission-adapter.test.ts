import { describe, expect, test } from 'bun:test'
import { CoreMailSubmissionAdapter } from '../../../src/core/adapters/mail-submission-adapter.ts'
import type { MailSubmissionAuthorizer } from '../../../src/core/identity/authorizers.ts'
import type { MailSubmissionRequestV1 } from '../../../src/protocol/mail-submission.ts'
import type { MailDeliveryResult } from '../../../src/core/adapters/mail-smtp-client.ts'

function makeRequest(): MailSubmissionRequestV1 {
  return {
    version: 1, identityId: 'did:web:alice.example', deviceId: 'did:web:alice.example#device-a',
    mailFrom: 'alice@mail.example.test', rcptTo: ['bob@mail.other.test'],
    rawRfc5322: new TextEncoder().encode('Subject: hi\r\n\r\nbody'), submittedAt: '2026-08-24T00:00:00.000Z',
    signature: new Uint8Array(64),
  }
}

describe('CoreMailSubmissionAdapter', () => {
  test('rejects an unauthorised request before deliverMail is ever called', async () => {
    let deliverCalls = 0
    const authorizer: MailSubmissionAuthorizer = { async verify() { return false } }
    const adapter = new CoreMailSubmissionAdapter(authorizer, 'mail.test.example', async () => { deliverCalls += 1; return [] })
    await expect(adapter.submit(makeRequest())).rejects.toThrow('mail submission is not authorised')
    expect(deliverCalls).toBe(0)
  })

  test('delivers and reports accepted when every domain group succeeds', async () => {
    const authorizer: MailSubmissionAuthorizer = { async verify() { return true } }
    const results: MailDeliveryResult[] = [{ domain: 'mail.other.test', target: 'x:25', accepted: ['bob@mail.other.test'], rejected: [], outcome: 'delivered' }]
    const adapter = new CoreMailSubmissionAdapter(authorizer, 'mail.test.example', async () => results)
    const result = await adapter.submit(makeRequest())
    expect(result.status).toBe('accepted')
  })

  test('reports temporary-failure with detail when a domain group errors', async () => {
    const authorizer: MailSubmissionAuthorizer = { async verify() { return true } }
    const results: MailDeliveryResult[] = [{ domain: 'mail.other.test', target: '', accepted: [], rejected: [], outcome: 'error', error: 'no MX for mail.other.test' }]
    const adapter = new CoreMailSubmissionAdapter(authorizer, 'mail.test.example', async () => results)
    const result = await adapter.submit(makeRequest())
    expect(result.status).toBe('temporary-failure')
    expect(result.detail).toContain('no MX')
  })

  test('reports temporary-failure when a recipient is rejected even if the group "delivered"', async () => {
    const authorizer: MailSubmissionAuthorizer = { async verify() { return true } }
    const results: MailDeliveryResult[] = [{ domain: 'mail.other.test', target: 'x:25', accepted: [], rejected: [{ address: 'bob@mail.other.test', reply: '550 no such user' }], outcome: 'delivered' }]
    const adapter = new CoreMailSubmissionAdapter(authorizer, 'mail.test.example', async () => results)
    const result = await adapter.submit(makeRequest())
    expect(result.status).toBe('temporary-failure')
    expect(result.detail).toContain('550 no such user')
  })
})
