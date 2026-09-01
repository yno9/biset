import { describe, expect, test } from 'bun:test'
import { createMimiDeployment } from '../../src/mimi/deployment.ts'
import { encodeMimiConsentEntryWire } from '../../src/mimi/federation.ts'

const target = 'target.example'
const source = 'source.example'
const headers = { host: target, from: `mimi@${source}`, 'content-type': 'application/json' }

describe('MIMI consent and identifier provider endpoints', () => {
  test('requires a TLS-authenticated peer, durably records consent, and delegates privacy-aware lookup', async () => {
    let lookupSource: string | undefined
    const deployment = createMimiDeployment({
      databasePath: ':memory:', mode: 'normal',
      federation: {
        providerDomain: target,
        authenticatePeer: async () => ({ providerDomain: source }),
        now: () => '2026-09-01T00:00:00.000Z',
        identifierDirectory: { async query(request, peer) { lookupSource = peer; return request.queryElements[0]?.searchValue === 'alice' ? { responseCode: 'success', foundProfiles: [{ stableUri: 'did:web:alice', fields: [{ fieldSource: 'oidcStdClaim', fieldName: 'preferred_username', fieldValue: 'alice' }] }] } : { responseCode: 'notFound', foundProfiles: [] } } },
      },
    })
    const requestEntry = { consentOperation: 'request' as const, requesterUri: 'did:web:requester', targetUri: 'did:web:target', roomId: 'mimi://target.example/r/one' }
    expect((await deployment.fetch(post(`/requestConsent/${target}`, encodeMimiConsentEntryWire(requestEntry)))).status).toBe(201)
    expect(deployment.store.consent(requestEntry.requesterUri, requestEntry.targetUri, requestEntry.roomId)).toEqual({ entry: requestEntry, sourceProvider: source, updatedAt: '2026-09-01T00:00:00.000Z' })

    const grantEntry = { consentOperation: 'grant' as const, requesterUri: requestEntry.requesterUri, targetUri: requestEntry.targetUri, roomId: requestEntry.roomId, clientKeyPackages: [{ reference: new Uint8Array([1]), user: requestEntry.targetUri, client: 'did:web:target#phone', keyPackage: new Uint8Array([2]), publishedAt: '2026-09-01T00:00:00.000Z' }] }
    expect((await deployment.fetch(post(`/updateConsent/${target}`, encodeMimiConsentEntryWire(grantEntry)))).status).toBe(201)
    expect(deployment.store.consent(requestEntry.requesterUri, requestEntry.targetUri, requestEntry.roomId)?.entry).toEqual(grantEntry)

    const queryResponse = await deployment.fetch(post(`/identifierQuery/${target}`, JSON.stringify({ queryElements: [{ searchType: 'nick', searchValue: 'alice' }] })))
    expect(queryResponse.status).toBe(200)
    expect(await queryResponse.json()).toMatchObject({ responseCode: 'success', foundProfiles: [{ stableUri: 'did:web:alice' }] })
    expect(lookupSource).toBe(source)
    deployment.close()
  })

  test('does not accept a provider-only endpoint without mTLS peer verification', async () => {
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal' })
    const response = await deployment.fetch(post(`/requestConsent/${target}`, encodeMimiConsentEntryWire({ consentOperation: 'request', requesterUri: 'did:web:requester', targetUri: 'did:web:target' })))
    expect(response.status).toBe(403)
    deployment.close()
  })
})

function post(path: string, body: string): Request { return new Request(`https://${target}${path}`, { method: 'POST', headers, body }) }
