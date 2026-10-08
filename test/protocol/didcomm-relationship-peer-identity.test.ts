import { describe, expect, test } from 'bun:test'
import { deriveRelationshipPeerIdentity, decodePeerDid2 } from '../../src/protocol/didcomm/peer.ts'

const counterpartyDid = 'did:webvh:QmCounterparty:bob.example'
const secretA = new Uint8Array(32).fill(1)
const secretB = new Uint8Array(32).fill(2)

describe('deriveRelationshipPeerIdentity', () => {
  test('is deterministic: the same seed and counterparty derive the same Y on every device', () => {
    const first = deriveRelationshipPeerIdentity(secretA, counterpartyDid)
    const second = deriveRelationshipPeerIdentity(secretA, counterpartyDid)
    expect(second.did).toBe(first.did)
    expect(second.xPriv).toEqual(first.xPriv)
  })

  test('a different seed for the same counterparty derives a different Y: a seed replacement moves every conversation (§4.5)', () => {
    expect(deriveRelationshipPeerIdentity(secretB, counterpartyDid).did).not.toBe(deriveRelationshipPeerIdentity(secretA, counterpartyDid).did)
  })

  test('different counterparties derive independent peers from the same secret', () => {
    const toBob = deriveRelationshipPeerIdentity(secretA, counterpartyDid)
    const toCarol = deriveRelationshipPeerIdentity(secretA, 'did:webvh:QmCarol:carol.example')
    expect(toCarol.did).not.toBe(toBob.did)
  })

  test('rejects a seed that is not exactly 32 bytes', () => {
    expect(() => deriveRelationshipPeerIdentity(new Uint8Array(16), counterpartyDid)).toThrow('relationship seed must be 32 bytes')
  })

  test('the service names the mediator by DID, and nothing else (§10-1)', () => {
    const derived = deriveRelationshipPeerIdentity(secretA, counterpartyDid, { uri: 'did:web:mediator.biset.md' })
    const endpoint = decodePeerDid2(derived.did).service[0]!.serviceEndpoint
    expect(endpoint.uri).toBe('did:web:mediator.biset.md')
    expect((endpoint as { routing_keys: string[] }).routing_keys).toEqual([])
    // The same keys whatever the service: only the DID string differs.
    expect(deriveRelationshipPeerIdentity(secretA, counterpartyDid).xKid.split('#')[1]).toBe(derived.xKid.split('#')[1])
  })
})
