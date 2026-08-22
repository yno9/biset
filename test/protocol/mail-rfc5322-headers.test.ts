import { describe, expect, test } from 'bun:test'
import { readRfc5322HeaderSummary } from '../../src/mail/rfc5322-headers.ts'

describe('endpoint RFC 5322 header summary', () => {
  test('reads unfolded display fields and bounded threading identifiers without parsing a MIME body', () => {
    const raw = new TextEncoder().encode([
      'Message-ID: <child@example.test>',
      'In-Reply-To: <parent@example.test>',
      'References: <root@example.test> <parent@example.test>',
      'Subject: a folded',
      ' subject',
      'Date: Fri, 22 Aug 2026 12:34:56 +0900',
      '',
      'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"',
      '',
    ].join('\r\n'))
    expect(readRfc5322HeaderSummary(raw)).toEqual({
      messageId: 'child@example.test',
      inReplyTo: 'parent@example.test',
      references: ['root@example.test', 'parent@example.test'],
      subject: 'a folded subject',
      sentAt: '2026-08-22T03:34:56.000Z',
    })
  })

  test('treats malformed or non-UTF-8 headers as absent display metadata without touching raw mail', () => {
    expect(readRfc5322HeaderSummary(new Uint8Array([0xff, 0x0a, 0x0a]))).toEqual({ references: [] })
    expect(readRfc5322HeaderSummary(new TextEncoder().encode('Subject: no body separator'))).toEqual({ references: [] })
  })
})
