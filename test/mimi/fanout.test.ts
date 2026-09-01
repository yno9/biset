import { describe, expect, test } from 'bun:test'
import { MimiFanoutDispatcher, decodeMimiFanoutBatchWire, encodeMimiFanoutBatchWire, fanoutFingerprint } from '../../src/mimi/fanout.ts'
import { MimiProviderTransport } from '../../src/mimi/provider-transport.ts'

const batch = { timestamp: '1770000000000', entries: [{ seq: 1, kind: 'commit' as const, payload: new Uint8Array([1]), epoch: '1', acceptedAt: '2026-09-01T00:00:00.000Z' }] }

describe('MIMI provider fanout', () => {
  test('round-trips a bounded JSON fanout batch with a stable replay fingerprint', async () => {
    const wire = encodeMimiFanoutBatchWire(batch)
    expect(decodeMimiFanoutBatchWire(wire)).toEqual(batch)
    expect(await fanoutFingerprint(wire)).toBe(await fanoutFingerprint(wire))
    expect(await fanoutFingerprint(wire)).not.toBe(await fanoutFingerprint(`${wire} `))
  })

  test('sends notify only through the mTLS-bound provider transport', async () => {
    let url = ''
    const transport = new MimiProviderTransport({ sourceProviderDomain: 'source.example', tls: { cert: 'cert', key: 'key' }, fetchImpl: async (input, init) => { url = input.toString(); expect(new Headers(init?.headers).get('from')).toBe('mimi@source.example'); return new Response(null, { status: 201 }) } })
    await new MimiFanoutDispatcher(transport).send({ providerBaseUrl: 'https://target.example', roomId: 'mimi://target.example/r/one' }, batch)
    expect(url).toBe('https://target.example/notify/mimi%3A%2F%2Ftarget.example%2Fr%2Fone')
  })
})
