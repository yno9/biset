import { describe, expect, test } from 'bun:test'
import { extractRfc3156EncryptedPacket } from '../../src/mail/rfc3156.ts'

describe('RFC 3156 encrypted packet extraction', () => {
  test('extracts a base64 encoded OpenPGP packet from a strict multipart/encrypted wrapper', () => {
    const raw = [
      'From: sender@example.test',
      'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="next"',
      '',
      'preamble ignored',
      '--next',
      'Content-Type: application/pgp-encrypted',
      '',
      'Version: 1',
      '--next',
      'Content-Type: application/octet-stream',
      'Content-Transfer-Encoding: base64',
      '',
      'AQIDBA==',
      '--next--',
    ].join('\r\n')
    expect(extractRfc3156EncryptedPacket(new TextEncoder().encode(raw))).toEqual(new Uint8Array([1, 2, 3, 4]))
  })

  test('rejects a non-RFC3156 wrapper or an ambiguous multipart layout', () => {
    const nonEncrypted = new TextEncoder().encode('Content-Type: text/plain\r\n\r\nhello')
    expect(() => extractRfc3156EncryptedPacket(nonEncrypted)).toThrow('not RFC 3156')
    const threeParts = new TextEncoder().encode([
      'Content-Type: multipart/encrypted; protocol=application/pgp-encrypted; boundary=b', '',
      '--b', 'Content-Type: application/pgp-encrypted', '', 'Version: 1',
      '--b', 'Content-Type: application/octet-stream', 'Content-Transfer-Encoding: base64', '', 'AQ==',
      '--b', 'Content-Type: application/octet-stream', 'Content-Transfer-Encoding: base64', '', 'AQ==',
      '--b--',
    ].join('\r\n'))
    expect(() => extractRfc3156EncryptedPacket(threeParts)).toThrow('exactly two')
  })
})
