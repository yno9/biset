import { describe, expect, test } from 'bun:test'
import { buildOutboundRfc5322 } from '../src/mail/rfc5322-builder.ts'
import { readRfc5322HeaderSummary } from '../src/mail/rfc5322-headers.ts'

const NOW = new Date('2026-08-24T09:30:15.000Z')

describe('buildOutboundRfc5322', () => {
  test('assembles From/To/Subject/Date/Message-Id and a plain-text body', () => {
    const { rawRfc5322, messageId } = buildOutboundRfc5322({
      from: 'alice@mail.example.test', fromName: 'Alice', to: ['bob@mail.other.test'],
      subject: 'hello', body: 'hi there',
    }, NOW)
    const text = new TextDecoder().decode(rawRfc5322)
    expect(text).toContain('From: Alice <alice@mail.example.test>')
    expect(text).toContain('To: bob@mail.other.test')
    expect(text).toContain('Subject: hello')
    expect(text).toContain('Date: Mon, 24 Aug 2026 09:30:15 +0000')
    expect(text).toContain(`Message-Id: <${messageId}>`)
    expect(text.endsWith('hi there')).toBe(true)
    expect(messageId.endsWith('@mail.example.test')).toBe(true)
  })

  test('omits In-Reply-To/References when not replying', () => {
    const { rawRfc5322 } = buildOutboundRfc5322({ from: 'a@x.test', to: ['b@y.test'], subject: 's', body: 'b' }, NOW)
    const text = new TextDecoder().decode(rawRfc5322)
    expect(text).not.toContain('In-Reply-To')
    expect(text).not.toContain('References')
  })

  test('includes In-Reply-To and a References chain when replying', () => {
    const { rawRfc5322 } = buildOutboundRfc5322({
      from: 'a@x.test', to: ['b@y.test'], subject: 're: s', body: 'b',
      inReplyTo: 'm2@y.test', references: ['m1@y.test', 'm2@y.test'],
    }, NOW)
    const text = new TextDecoder().decode(rawRfc5322)
    expect(text).toContain('In-Reply-To: <m2@y.test>')
    expect(text).toContain('References: <m1@y.test> <m2@y.test>')
  })

  test('joins multiple recipients with a comma', () => {
    const { rawRfc5322 } = buildOutboundRfc5322({ from: 'a@x.test', to: ['b@y.test', 'c@z.test'], subject: 's', body: 'b' }, NOW)
    expect(new TextDecoder().decode(rawRfc5322)).toContain('To: b@y.test, c@z.test')
  })

  test('normalizes bare LF/CR line endings in the body to CRLF', () => {
    const { rawRfc5322 } = buildOutboundRfc5322({ from: 'a@x.test', to: ['b@y.test'], subject: 's', body: 'line1\nline2\r\nline3' }, NOW)
    expect(new TextDecoder().decode(rawRfc5322)).toContain('line1\r\nline2\r\nline3')
  })

  test('two calls produce distinct Message-Ids', () => {
    const a = buildOutboundRfc5322({ from: 'a@x.test', to: ['b@y.test'], subject: 's', body: 'b' }, NOW)
    const b = buildOutboundRfc5322({ from: 'a@x.test', to: ['b@y.test'], subject: 's', body: 'b' }, NOW)
    expect(a.messageId).not.toBe(b.messageId)
  })

  test('rejects a from address with no domain, and empty recipients', () => {
    expect(() => buildOutboundRfc5322({ from: 'not-an-address', to: ['b@y.test'], subject: 's', body: 'b' })).toThrow()
    expect(() => buildOutboundRfc5322({ from: 'a@x.test', to: [], subject: 's', body: 'b' })).toThrow()
  })

  test('round-trips through the existing header reader', () => {
    const { rawRfc5322, messageId } = buildOutboundRfc5322({
      from: 'a@x.test', to: ['b@y.test'], subject: 'round trip', body: 'body text',
      inReplyTo: 'parent@y.test', references: ['parent@y.test'],
    }, NOW)
    const summary = readRfc5322HeaderSummary(rawRfc5322)
    expect(summary.subject).toBe('round trip')
    expect(summary.messageId).toBe(messageId)
    expect(summary.inReplyTo).toBe('parent@y.test')
    expect(summary.references).toEqual(['parent@y.test'])
    expect(summary.sentAt).toBe(NOW.toISOString())
  })
})
