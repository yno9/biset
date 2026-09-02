import { describe, expect, test } from 'bun:test'
import { MimiClientTransport } from '../../src/mls/mimi-client-transport.ts'

describe('MIMI client transport', () => {
  test('keeps normal and anonymous provider origins separate for SSE', () => {
    const transport = new MimiClientTransport({ normalBaseUrl: 'https://normal.example/', anonBaseUrl: 'https://anon.example/' })
    expect(transport.streamUrl('normal', 'a b', 0)).toBe('https://normal.example/v1/mimi/deliveries/stream?token=a%20b&afterSeq=0')
    expect(transport.streamUrl('anon', 't', 7)).toBe('https://anon.example/v1/mimi/deliveries/stream?token=t&afterSeq=7')
  })

  test('routes the isolated Self/Vault room to its configured normal-mode deployment', () => {
    const transport = new MimiClientTransport({ normalBaseUrl: 'https://normal.example/', anonBaseUrl: 'https://anon.example/', selfBaseUrl: 'https://self.example/' })
    expect(transport.streamUrl('self', 't', 7)).toBe('https://self.example/v1/mimi/deliveries/stream?token=t&afterSeq=7')
  })

  test('uses the selected provider for initial franking-agent discovery', async () => {
    const calls: string[] = []
    const transport = new MimiClientTransport({
      normalBaseUrl: 'https://normal.example/', anonBaseUrl: 'https://anon.example/', selfBaseUrl: 'https://self.example/',
      fetch: async input => { calls.push(String(input)); return new Response(JSON.stringify({ frankingSignatureKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', credential: 'AQ' })) },
    })
    await transport.frankingAgent('self', 'mimi://self.example/r/vault-test')
    expect(calls).toEqual(['https://self.example/v1/mimi/franking-agent/mimi%3A%2F%2Fself.example%2Fr%2Fvault-test'])
  })
})
