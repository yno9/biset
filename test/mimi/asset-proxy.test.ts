import { describe, expect, test } from 'bun:test'
import { MimiAssetProxy } from '../../src/server/mimi/asset-proxy.ts'

describe('MIMI asset proxy', () => {
  test('allows only configured HTTPS hosts, rejects redirects, and bounds response size', async () => {
    const proxy = new MimiAssetProxy({ allowedAssetHosts: ['assets.example'], maxBytes: 3, fetchImpl: async (input, init) => { expect(input.toString()).toBe('https://assets.example/a'); expect(init?.redirect).toBe('error'); return new Response(new Uint8Array([1, 2, 3]), { headers: { 'content-type': 'application/octet-stream' } }) } })
    expect(new Uint8Array(await (await proxy.download('https://assets.example/a')).arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]))
    await expect(proxy.download('https://attacker.example/a')).rejects.toThrow('allowed')
    await expect(proxy.download('http://assets.example/a')).rejects.toThrow('allowed')
  })
})
