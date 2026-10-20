import { describe, expect, test } from 'vitest'
import { basicMessageBodyOf } from '../src/client/didcomm/basicmessage.ts'

const KEYDATA = 'xjMEZ5QkSRYJKwYBBAHaRw8BAQdAsKuiml2Fq41/hfeRhnz/7phL7Imk63rySFbLt6NK3/'

describe('basicMessageBodyOf: the OpenPGP fields a bridged mail carries', () => {
  test('reads the Autocrypt key, the encryption and the signature marks', () => {
    const body = basicMessageBodyOf({ body: { content: 'x', autocrypt: { addr: 'n@4r.ma', keydata: KEYDATA, preferEncrypt: 'mutual' }, encryption: 'openpgp', signature: 'openpgp' } })!
    expect(body.autocrypt).toEqual({ addr: 'n@4r.ma', keydata: KEYDATA, preferEncrypt: 'mutual' })
    expect(body.encryption).toBe('openpgp')
    expect(body.signature).toBe('openpgp')
  })

  test('a preference other than mutual is no preference', () => {
    expect(basicMessageBodyOf({ body: { content: 'x', autocrypt: { addr: 'n@4r.ma', keydata: KEYDATA, preferEncrypt: 'nopreference' } } })!.autocrypt).toEqual({ addr: 'n@4r.ma', keydata: KEYDATA })
  })

  test('anything malformed is dropped, the message itself is still read', () => {
    for (const autocrypt of ['k', null, [], { addr: 'n', keydata: KEYDATA }, { addr: 'n@4r.ma' }, { addr: 'n@4r.ma', keydata: 'not base64!' }, { addr: 'n@4r.ma', keydata: 'A'.repeat(100 * 1024) }]) {
      const body = basicMessageBodyOf({ body: { content: 'x', autocrypt, encryption: 'pgp', signature: true } })!
      expect(body.content).toBe('x')
      expect('autocrypt' in body).toBe(false)
      expect('encryption' in body).toBe(false)
      expect('signature' in body).toBe(false)
    }
  })
})
