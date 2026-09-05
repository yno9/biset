import { describe, expect, test } from 'bun:test'
import { MimiFanoutDispatcher, decodeMimiFanoutBatchWire, encodeMimiFanoutBatchWire, fanoutFingerprint } from '../../src/server/mimi/fanout.ts'
import { MimiProviderTransport } from '../../src/server/mimi/provider-transport.ts'
import { encodeMlsMessage } from '../../src/vendor/mls/index.ts'

const commit = encodeMlsMessage({ version: 'mls10', wireformat: 'mls_public_message', publicMessage: { content: { groupId: new Uint8Array([1]), epoch: 1n, sender: { senderType: 'member', leafIndex: 0 }, authenticatedData: new Uint8Array(), contentType: 'commit', commit: { proposals: [], path: undefined } }, auth: { contentType: 'commit', signature: new Uint8Array(), confirmationTag: new Uint8Array() }, senderType: 'member', membershipTag: new Uint8Array() } })
const batch = { messages: [{ timestamp: '1770000000000', protocol: 'mls10' as const, message: commit }] }

describe('MIMI provider fanout', () => {
  test('round-trips a FanoutMessage batch with a stable replay fingerprint', async () => {
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
