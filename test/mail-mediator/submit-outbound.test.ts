// buildSmtpSubmitOutbound's per-recipient mapping, exercised both against
// a real inbound listener (accepted/rejected split) and against MX
// resolution failures (temporary-failure without any socket at all) --
// mirrors test/core/adapters/mail-smtp-client-delivery.test.ts's own
// "real socket, no stubbing the wire" approach for the delivered path.
import { describe, expect, test } from 'bun:test'
import { buildSmtpSubmitOutbound } from '../../src/mail-mediator/submit-outbound.ts'
import { createSmtpMailListener } from '../../src/mail-mediator/smtp-listener.ts'
import { RouteStore } from '../../src/mail-mediator/route-store.ts'
import { SpoolStore } from '../../src/mail-mediator/spool-store.ts'
import type { SubmissionRecord } from '../../src/mail-mediator/submission-store.ts'

function record(overrides: Partial<SubmissionRecord> = {}): SubmissionRecord {
  return {
    idempotencyKey: 'idem-1', mailFrom: 'y@biset.md', rcptTo: ['a@one.example'],
    rawRfc5322: new Uint8Array([1, 2, 3]), state: 'in-flight', createdAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  }
}

describe('buildSmtpSubmitOutbound', () => {
  test('a delivered domain maps accepted and rejected recipients individually', async () => {
    const routes = new RouteStore()
    routes.bind('accepted@mail.test.example', { relationshipKid: 'k1', pickupPublicKey: new Uint8Array(32), expiresAt: '2030-01-01T00:00:00.000Z' }, 'gen-1', '2026-01-01T00:00:00.000Z')
    // "rejected@..." is deliberately left unbound so the inbound listener
    // itself rejects the RCPT TO with 550 -- exactly what a real
    // unregistered recipient looks like from the sending side.
    const spool = new SpoolStore()
    const listener = createSmtpMailListener({ port: 0, helloName: 'mail.test.example', routes, spool })
    try {
      const submitOutbound = buildSmtpSubmitOutbound('client.example', {
        mxResolver: async () => ['127.0.0.1'], port: listener.port,
      })
      const raw = new TextEncoder().encode('Subject: hi\r\n\r\nbody\r\n')
      const results = await submitOutbound(record({
        mailFrom: 'sender@example.test', rcptTo: ['accepted@mail.test.example', 'rejected@mail.test.example'], rawRfc5322: raw,
      }))
      expect(results).toContainEqual({ recipient: 'accepted@mail.test.example', status: 'accepted' })
      const rejected = results.find(r => r.recipient === 'rejected@mail.test.example')
      expect(rejected?.status).toBe('permanent-failure')
      expect(rejected?.detail).toContain('550')

      const claimed = spool.claim('accepted@mail.test.example', 'holder-a', 60_000, 10, '2026-01-01T00:00:00.000Z')
      expect(claimed).toHaveLength(1)
    } finally {
      listener.stop()
    }
  })

  test('a domain with no MX becomes temporary-failure for every recipient grouped under it', async () => {
    const submitOutbound = buildSmtpSubmitOutbound('mail.biset.md', { mxResolver: async () => [] })
    const results = await submitOutbound(record({ rcptTo: ['a@nowhere.example', 'b@nowhere.example'] }))
    expect(results).toEqual([
      { recipient: 'a@nowhere.example', status: 'temporary-failure', detail: 'no MX for nowhere.example' },
      { recipient: 'b@nowhere.example', status: 'temporary-failure', detail: 'no MX for nowhere.example' },
    ])
  })

  test('recipients across two domains are reported independently', async () => {
    const submitOutbound = buildSmtpSubmitOutbound('mail.biset.md', {
      mxResolver: async domain => (domain === 'has-mx.example' ? ['127.0.0.1'] : []),
      port: 1, // nothing listens here -- has-mx.example's connection attempt also fails, deliberately
    })
    const results = await submitOutbound(record({ rcptTo: ['a@no-mx.example', 'b@has-mx.example'] }))
    expect(results).toHaveLength(2)
    expect(results.every(r => r.status === 'temporary-failure')).toBe(true)
  })
})
