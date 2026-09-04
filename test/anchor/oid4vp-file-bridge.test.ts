import { describe, expect, test } from 'bun:test'
import { handleBisetOid4vpBridgeMessage } from '../../src/oid4vp/file-bridge.ts'
import type { BisetOid4vpWallet } from '../../src/oid4vp/wallet.ts'

describe('file OID4VP bridge boundary', () => {
  test('accepts only the exact Anchor popup and returns its completion URI', async () => {
    const sent: unknown[] = []
    const popup = { postMessage: (value: unknown, origin: string) => sent.push({ value, origin }) } as unknown as Window
    const wallet = { respond: async () => 'https://anchor.biset.md/oid4vp/complete?response_code=approved' } as unknown as BisetOid4vpWallet
    const event = {
      origin: 'https://anchor.biset.md', source: popup,
      data: { type: 'biset.oid4vp.request.v1', requestUri: 'https://anchor.biset.md/oid4vp/request/transaction', bridgeNonce: 'n'.repeat(32) },
    } as MessageEvent<unknown>
    expect(await handleBisetOid4vpBridgeMessage({ event, popup, anchorOrigin: 'https://anchor.biset.md', wallet })).toBe(true)
    expect(sent).toEqual([{
      value: { type: 'biset.oid4vp.complete.v1', bridgeNonce: 'n'.repeat(32), completionUri: 'https://anchor.biset.md/oid4vp/complete?response_code=approved' },
      origin: 'https://anchor.biset.md',
    }])
  })

  test('ignores another source/origin and rejects an off-Anchor request URI', async () => {
    const popup = { postMessage() {} } as unknown as Window
    const wallet = { respond: async () => 'never' } as unknown as BisetOid4vpWallet
    const value = { type: 'biset.oid4vp.request.v1', requestUri: 'https://anchor.biset.md/oid4vp/request/t', bridgeNonce: 'n'.repeat(32) }
    expect(await handleBisetOid4vpBridgeMessage({ event: { origin: 'https://evil.example', source: popup, data: value } as MessageEvent, popup, anchorOrigin: 'https://anchor.biset.md', wallet })).toBe(false)
    await expect(handleBisetOid4vpBridgeMessage({ event: { origin: 'https://anchor.biset.md', source: popup, data: { ...value, requestUri: 'https://evil.example/oid4vp/request/t' } } as MessageEvent, popup, anchorOrigin: 'https://anchor.biset.md', wallet })).rejects.toThrow('not trusted')
  })
})
