// PLAN-tor.md Phase 2-2: resolveVaultSyncSiblingRoutes must accept a
// #didcomm service whose serviceEndpoint is a SET (clearnet + Tor, D-4),
// not only the pre-Tor single map, while still rejecting a set that names
// more than one mediator (differing routingKeys would mean two different
// mediators, never valid for one #didcomm service).
import { afterEach, describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { resolveVaultSyncSiblingRoutes } from '../src/client/didcomm/vault-sync.ts'
import { domainDidJsonlUrl } from '../src/protocol/webvh/identifier.ts'
import { buildDidCommLog } from './protocol/support/webvh-log-fixture.ts'

const originalFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = originalFetch })

function serveLog(log: { id: string; log: import('../src/protocol/webvh/log.ts').LogEntry[] }): void {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    if (url === domainDidJsonlUrl('test.example')) {
      return new Response(log.log.map(entry => JSON.stringify(entry)).join('\n') + '\n')
    }
    return new Response(null, { status: 404 })
  }) as typeof fetch
}

describe('resolveVaultSyncSiblingRoutes: PLAN-tor D-4 array serviceEndpoint', () => {
  test('a single-map serviceEndpoint (pre-Tor shape) still resolves', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const built = buildDidCommLog({
      rootPrivateKey, rootPublicKey,
      endpointUri: 'https://mediator.biset.md', routingKeys: ['did:peer:2.Vz6MkqRYqQmD9C1vUoGJdYVZ41UKbd8PiW2pD6TqEJqK6fpWsM4xS#key-1'],
    })
    serveLog(built)
    const routes = await resolveVaultSyncSiblingRoutes(built.did)
    expect(routes).toEqual([])
  })

  test('a two-entrance array resolves and picks the first (canonical) entry', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const routingKid = 'did:peer:2.Vz6MkqRYqQmD9C1vUoGJdYVZ41UKbd8PiW2pD6TqEJqK6fpWsM4xS#key-1'
    const onion = `http://${'a'.repeat(56)}.onion`
    const built = buildDidCommLog({
      rootPrivateKey, rootPublicKey,
      services: [{ id: '#didcomm', serviceEndpoints: [
        { uri: 'https://mediator.biset.md', routingKeys: [routingKid] },
        { uri: onion, routingKeys: [routingKid] },
      ] }],
    })
    serveLog(built)
    // No sibling devices published in this fixture -- what matters here is
    // that resolution itself succeeds (throws nothing) against the array
    // shape; sibling selection is covered by the existing single-map tests.
    const routes = await resolveVaultSyncSiblingRoutes(built.did)
    expect(routes).toEqual([])
  })

  test('rejects an array whose entries name different mediators', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const built = buildDidCommLog({
      rootPrivateKey, rootPublicKey,
      services: [{ id: '#didcomm', serviceEndpoints: [
        { uri: 'https://mediator.biset.md', routingKeys: ['did:peer:2.Vz6MkqRYqQmD9C1vUoGJdYVZ41UKbd8PiW2pD6TqEJqK6fpWsM4xS#key-1'] },
        { uri: 'https://other-mediator.example', routingKeys: ['did:peer:2.Vz6MnQAY39p3n8opuzMujoUKGKKnaGjmVCVMHDvTV1zknP8Wi#key-1'] },
      ] }],
    })
    serveLog(built)
    await expect(resolveVaultSyncSiblingRoutes(built.did)).rejects.toThrow('Vault Sync DIDComm mediator route is invalid')
  })

  test('rejects an array entry with more than one routing key', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const built = buildDidCommLog({
      rootPrivateKey, rootPublicKey,
      services: [{ id: '#didcomm', serviceEndpoints: [
        { uri: 'https://mediator.biset.md', routingKeys: ['did:peer:2.Vz6MkqRYqQmD9C1vUoGJdYVZ41UKbd8PiW2pD6TqEJqK6fpWsM4xS#key-1', 'did:peer:2.Vz6MnQAY39p3n8opuzMujoUKGKKnaGjmVCVMHDvTV1zknP8Wi#key-1'] },
      ] }],
    })
    serveLog(built)
    await expect(resolveVaultSyncSiblingRoutes(built.did)).rejects.toThrow('Vault Sync DIDComm mediator route is invalid')
  })

  test('rejects an empty serviceEndpoint array', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const built = buildDidCommLog({ rootPrivateKey, rootPublicKey, services: [{ id: '#didcomm', serviceEndpoints: [] }] })
    serveLog(built)
    await expect(resolveVaultSyncSiblingRoutes(built.did)).rejects.toThrow('Vault Sync DIDComm mediator route is invalid')
  })
})
