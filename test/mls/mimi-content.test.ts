import { describe, expect, test } from 'bun:test'
import { encode as cborEncode, rfc8949EncodeOptions } from 'cborg'
import {
  DISPOSITION_REACTION,
  DISPOSITION_RENDER,
  decodeMimiContent,
  encodeMimiContent,
  MimiContentError,
  type MimiContent,
} from '../../src/mls/mimi-content.ts'

function salt(): Uint8Array {
  return new Uint8Array(16).fill(7)
}

function messageId(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

function plainText(text: string): MimiContent {
  return {
    salt: salt(),
    replaces: null,
    topicId: new Uint8Array(0),
    expires: null,
    inReplyTo: null,
    extensions: {},
    nestedPart: { disposition: DISPOSITION_RENDER, language: 'en', part: { kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode(text) } },
  }
}

describe('MimiContent encode/decode', () => {
  test('round-trips a plain text message', () => {
    const value = plainText('hello group')
    const decoded = decodeMimiContent(encodeMimiContent(value))
    expect(decoded).toEqual(value)
  })

  test('round-trips a reply (inReplyTo set)', () => {
    const value: MimiContent = { ...plainText('sure, sounds good'), inReplyTo: messageId(1) }
    const decoded = decodeMimiContent(encodeMimiContent(value))
    expect(decoded.inReplyTo).toEqual(messageId(1))
  })

  test('round-trips an edit (replaces set, new text body)', () => {
    const value: MimiContent = { ...plainText('corrected text'), replaces: messageId(2) }
    const decoded = decodeMimiContent(encodeMimiContent(value))
    expect(decoded.replaces).toEqual(messageId(2))
    expect(decoded.nestedPart.part).toEqual({ kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode('corrected text') })
  })

  test('round-trips a delete (replaces set, NullPart body)', () => {
    const value: MimiContent = {
      salt: salt(), replaces: messageId(3), topicId: new Uint8Array(0), expires: null, inReplyTo: null, extensions: {},
      nestedPart: { disposition: DISPOSITION_RENDER, language: 'en', part: { kind: 'null' } },
    }
    const decoded = decodeMimiContent(encodeMimiContent(value))
    expect(decoded.nestedPart.part).toEqual({ kind: 'null' })
    expect(decoded.replaces).toEqual(messageId(3))
  })

  test('round-trips a reaction (disposition=reaction, new inReplyTo)', () => {
    const value: MimiContent = { ...plainText('👍'), inReplyTo: messageId(4) }
    value.nestedPart = { disposition: DISPOSITION_REACTION, language: 'en', part: { kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode('👍') } }
    const decoded = decodeMimiContent(encodeMimiContent(value))
    expect(decoded.nestedPart.disposition).toBe(DISPOSITION_REACTION)
    expect(decoded.inReplyTo).toEqual(messageId(4))
  })

  test('round-trips a reaction retraction (replaces set instead of inReplyTo)', () => {
    const value: MimiContent = {
      salt: salt(), replaces: messageId(5), topicId: new Uint8Array(0), expires: null, inReplyTo: null, extensions: {},
      nestedPart: { disposition: DISPOSITION_REACTION, language: 'en', part: { kind: 'null' } },
    }
    const decoded = decodeMimiContent(encodeMimiContent(value))
    expect(decoded.replaces).toEqual(messageId(5))
    expect(decoded.nestedPart.part).toEqual({ kind: 'null' })
  })

  test('round-trips expires and extensions', () => {
    const value: MimiContent = { ...plainText('ephemeral'), expires: { relative: true, time: 3600 }, extensions: { senderUri: 'mimi:u:alice', roomUri: 'mimi:r:group1' } }
    const decoded = decodeMimiContent(encodeMimiContent(value))
    expect(decoded.expires).toEqual({ relative: true, time: 3600 })
    expect(decoded.extensions).toEqual({ senderUri: 'mimi:u:alice', roomUri: 'mimi:r:group1' })
  })

  test('produces deterministic (RFC 8949) bytes for the same value', () => {
    const value = plainText('same content')
    expect(encodeMimiContent(value)).toEqual(encodeMimiContent(value))
  })

  test('rejects wrong-length salt', () => {
    const value = plainText('x')
    expect(() => encodeMimiContent({ ...value, salt: new Uint8Array(15) })).toThrow(MimiContentError)
  })

  test('rejects wrong-length replaces/inReplyTo', () => {
    const value = plainText('x')
    expect(() => encodeMimiContent({ ...value, replaces: new Uint8Array(31) })).toThrow(MimiContentError)
    expect(() => encodeMimiContent({ ...value, inReplyTo: new Uint8Array(33) })).toThrow(MimiContentError)
  })

  test('rejects malformed CBOR', () => {
    expect(() => decodeMimiContent(new Uint8Array([0xff, 0x00]))).toThrow(MimiContentError)
  })

  test('rejects a top-level array of the wrong length', () => {
    // Fewer than 7 elements -- decode a hand-built short CBOR array rather
    // than depend on encodeMimiContent to produce this
    const bytes = cborEncode([salt()], rfc8949EncodeOptions)
    expect(() => decodeMimiContent(bytes)).toThrow(MimiContentError)
  })

  test('rejects ExternalPart (cardinality=2) as not yet supported', () => {
    const nestedPart = [DISPOSITION_RENDER, 'en', 2, 'text/plain', 'https://example.com/f', 0, 0, 0, new Uint8Array(0), new Uint8Array(0), new Uint8Array(0), 1, new Uint8Array(0), '', '']
    const bytes = cborEncode([salt(), null, new Uint8Array(0), null, null, new Map(), nestedPart], rfc8949EncodeOptions)
    expect(() => decodeMimiContent(bytes)).toThrow(/not yet supported/)
  })

  test('rejects a NestedPart with an unknown cardinality', () => {
    const nestedPart = [DISPOSITION_RENDER, 'en', 9]
    const bytes = cborEncode([salt(), null, new Uint8Array(0), null, null, new Map(), nestedPart], rfc8949EncodeOptions)
    expect(() => decodeMimiContent(bytes)).toThrow(/unknown cardinality/)
  })
})
