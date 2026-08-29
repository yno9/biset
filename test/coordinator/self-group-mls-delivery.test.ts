import { afterEach, describe, expect, test } from 'bun:test'
import { Database } from 'bun:sqlite'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createVaultCoordinatorFetchHandler } from '../../src/coordinator/app.ts'
import type { VaultAccessPrincipal, VaultAccessTokenVerifier } from '../../src/coordinator/auth.ts'
import { createMlsDeliveryHttpHandler } from '../../src/coordinator/mls-delivery-http.ts'
import { Ed25519MlsDsSignatureVerifier } from '../../src/coordinator/mls-delivery-authorizer.ts'
import { SqliteMlsDeliveryService } from '../../src/coordinator/mls-delivery-store.ts'
import { SqliteVaultCoordinatorStore } from '../../src/coordinator/store.ts'
import { encodeMlsGroupCreationWire } from '../../src/protocol/mls-ds-wire.ts'
import { mlsGroupCreationSigningBytes } from '../../src/protocol/signing.ts'

const databases: Database[] = []
afterEach(() => {
  for (const database of databases.splice(0)) database.close()
})

describe('Coordinator Self Group MLS Delivery Service', () => {
  test('serves signed MLS DS controls without coupling them to Vault OIDC', async () => {
    const database = new Database(':memory:')
    databases.push(database)
    const store = new SqliteVaultCoordinatorStore(database)
    const mls = new SqliteMlsDeliveryService(database)
    const secret = new Uint8Array(32).fill(7)
    const publicKey = ed25519.getPublicKey(secret)
    const kid = 'did:webvh:test:alice.example#device-a'
    const verifier = new Ed25519MlsDsSignatureVerifier({ async resolveEd25519PublicKey(value) { return value === kid ? publicKey : undefined } })
    const mlsHandler = createMlsDeliveryHttpHandler(mls, verifier, async () => true)
    const accessTokens: VaultAccessTokenVerifier = { async verify(): Promise<VaultAccessPrincipal> { throw new Error('MLS DS must not invoke Vault OIDC') } }
    const handler = createVaultCoordinatorFetchHandler({ store, accessTokens, mlsDelivery: mlsHandler })

    const unsigned = { version: 1 as const, groupId: 'group-a', identityId: 'did:webvh:test:alice.example', creatorKid: kid, roster: [], createdAt: '2026-08-29T00:00:00.000Z' }
    const deviceCredential = new Uint8Array([1])
    const body = encodeMlsGroupCreationWire({ ...unsigned, deviceCredential, signature: ed25519.sign(mlsGroupCreationSigningBytes(unsigned), secret) })
    const response = await handler(new Request('https://coordinator.example/v1/mls/group/create', { method: 'POST', headers: { 'content-type': 'application/json' }, body }))
    expect(response.status).toBe(201)
    expect(response.headers.get('access-control-allow-origin')).toBe('*')
    expect(await response.json()).toEqual({ roster: [kid] })

    const rejected = await handler(new Request('https://coordinator.example/v1/mls/group/create', { method: 'POST', headers: { 'content-type': 'application/json' }, body: encodeMlsGroupCreationWire({ ...unsigned, groupId: 'group-b', deviceCredential, signature: new Uint8Array(64) }) }))
    expect(rejected.status).toBe(403)
  })

})
