import { describe, expect, test } from 'bun:test'
import { MimiClientTransport } from '../../src/mls/mimi-client-transport.ts'

describe('MIMI client transport', () => {
  test('keeps normal and anonymous provider origins separate for SSE', () => {
    const transport = new MimiClientTransport({ normalBaseUrl: 'https://normal.example/', anonBaseUrl: 'https://anon.example/' })
    expect(transport.streamUrl('normal', 'a b', 0)).toBe('https://normal.example/v1/mimi/deliveries/stream?token=a%20b&afterSeq=0')
    expect(transport.streamUrl('anon', 't', 7)).toBe('https://anon.example/v1/mimi/deliveries/stream?token=t&afterSeq=7')
  })
})
