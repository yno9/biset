import { describe, expect, test } from 'bun:test'
import { AccountRouter, localAccountId, parseAccountId, remoteAccountId } from '../../src/local-jmap/accounts.ts'
import type { AccountTransport } from '../../src/local-jmap/transport.ts'

const transport: AccountTransport = {
  async session() { return { apiUrl: 'test://api', downloadUrl: 'test://download', capabilities: {}, accounts: {} } },
  async call() { return {} },
  async download() { return new Uint8Array() },
}

describe('Biset account routing', () => {
  test('uses distinct local-vault and remote-JMAP account ID namespaces', () => {
    expect(localAccountId('did:web:alice.example')).toBe('biset:did:web:alice.example')
    expect(remoteAccountId('fastmail', 'primary')).toBe('remote:fastmail:primary')
    expect(parseAccountId('biset:did:web:alice.example')).toEqual({ kind: 'local-vault', accountId: 'biset:did:web:alice.example', identityId: 'did:web:alice.example' })
    expect(parseAccountId('remote:fastmail:primary')).toEqual({ kind: 'remote-jmap', accountId: 'remote:fastmail:primary', provider: 'fastmail', remoteId: 'primary' })
  })

  test('resolves each UI action to one backend and rejects unregistered or ambiguous IDs', () => {
    const router = new AccountRouter()
    router.registerLocal('did:web:alice.example', transport)
    router.registerRemote('fastmail', 'primary', transport)
    expect(router.resolve('biset:did:web:alice.example').kind).toBe('local-vault')
    expect(router.resolve('remote:fastmail:primary').kind).toBe('remote-jmap')
    expect(() => router.resolve('remote:fastmail:other')).toThrow('not registered')
    expect(() => parseAccountId('remote:fastmail:two:parts')).toThrow('unsupported')
  })
})
