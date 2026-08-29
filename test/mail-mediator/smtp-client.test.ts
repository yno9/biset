import { describe, expect, test } from 'bun:test'
import {
  advertisesCapability, buildMailFromCommand, dotStuff, groupRecipientsByDomain,
} from '../../src/mail-mediator/smtp-client.ts'

describe('groupRecipientsByDomain', () => {
  test('groups by lowercased domain', () => {
    const groups = groupRecipientsByDomain(['alice@Example.com', 'bob@example.com', 'carol@other.example'])
    expect([...groups.keys()].sort()).toEqual(['example.com', 'other.example'])
    expect(groups.get('example.com')).toEqual(['alice@Example.com', 'bob@example.com'])
    expect(groups.get('other.example')).toEqual(['carol@other.example'])
  })
  test('throws on an address with no domain', () => {
    expect(() => groupRecipientsByDomain(['not-an-address'])).toThrow()
    expect(() => groupRecipientsByDomain(['@no-local-part.example'])).toThrow()
    expect(() => groupRecipientsByDomain(['no-domain@'])).toThrow()
  })
})

describe('dotStuff', () => {
  function enc(s: string): Uint8Array { return new TextEncoder().encode(s) }
  function dec(b: Uint8Array): string { return new TextDecoder().decode(b) }
  test('escapes a leading dot at the start of a line', () => {
    expect(dec(dotStuff(enc('.\r\nhello\r\n..world\r\n')))).toBe('..\r\nhello\r\n...world\r\n')
  })
  test('does not escape a dot mid-line', () => {
    expect(dec(dotStuff(enc('a.b.c\r\n')))).toBe('a.b.c\r\n')
  })
  test('empty input yields empty output', () => {
    expect(dotStuff(new Uint8Array(0))).toEqual(new Uint8Array(0))
  })
})

describe('advertisesCapability', () => {
  const ehlo = '250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 35882577\r\n250 STARTTLS\r\n'
  test.each([
    ['STARTTLS', true],
    ['PIPELINING', true],
    ['SIZE', true],
    ['starttls', true],
    ['CHUNKING', false],
    ['S', false],
  ])('%s -> %s', (keyword, expected) => {
    expect(advertisesCapability(ehlo, keyword)).toBe(expected)
  })
})

describe('buildMailFromCommand', () => {
  test('bare command when neither capability is advertised', () => {
    expect(buildMailFromCommand('a@b.com', '250-hi\r\n250 PIPELINING\r\n')).toBe('MAIL FROM:<a@b.com>\r\n')
  })
  test('adds BODY=8BITMIME and SMTPUTF8 only when advertised, in that order', () => {
    expect(buildMailFromCommand('a@b.com', '250-hi\r\n250-SMTPUTF8\r\n250 8BITMIME\r\n'))
      .toBe('MAIL FROM:<a@b.com> BODY=8BITMIME SMTPUTF8\r\n')
  })
})
