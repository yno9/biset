import { describe, expect, test } from 'vitest'
import { ocbEncrypt } from '../src/client/pgp/ocb.ts'

const hex = (value: string) => Uint8Array.from(value.match(/../g) ?? [], pair => parseInt(pair, 16))
const toHex = (bytes: Uint8Array) => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase()

// RFC 7253 appendix A: AES-128, 128-bit tags, key 000102..0F.
describe('OCB3 (RFC 7253 test vectors)', () => {
  const key = hex('000102030405060708090A0B0C0D0E0F')
  const cases: Array<[nonce: string, associated: string, plaintext: string, expected: string]> = [
    ['BBAA99887766554433221100', '', '', '785407BFFFC8AD9EDCC5520AC9111EE6'],
    ['BBAA99887766554433221101', '0001020304050607', '0001020304050607', '6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009'],
    ['BBAA99887766554433221102', '0001020304050607', '', '81017F8203F081277152FADE694A0A00'],
    ['BBAA99887766554433221103', '', '0001020304050607', '45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9'],
    ['BBAA99887766554433221104', '000102030405060708090A0B0C0D0E0F', '000102030405060708090A0B0C0D0E0F', '571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358'],
  ]
  for (const [nonce, associated, plaintext, expected] of cases) {
    test(`nonce ...${nonce.slice(-2)}: ${plaintext.length / 2} byte message, ${associated.length / 2} byte associated data`, async () => {
      expect(toHex(await ocbEncrypt(key, hex(nonce), hex(associated), hex(plaintext)))).toBe(expected)
    })
  }
})
