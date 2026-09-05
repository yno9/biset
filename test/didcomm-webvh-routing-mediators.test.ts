// buildRoutingDoc's mediator-registration branch (ARC.md's 2026-08-27
// redesign, Phase 5): a registered mediator becomes a DIDCommMessaging
// service entry whose `routingKeys` names the mediator's own kid, telling a
// spec-compliant sender to Forward-wrap instead of delivering directly --
// and supersedes the legacy `didCommEndpoint` entry when both are given.
import { describe, expect, test } from 'bun:test'
import { buildRoutingDoc, mimiVaultRoomFromRouting } from '../src/shared/didcomm/webvh-routing.ts'

const DID = 'did:webvh:alice.example'

describe('buildRoutingDoc: mediator registrations', () => {
  test('one registered mediator produces one service entry with routingKeys naming it', () => {
    const doc = buildRoutingDoc(DID, {
      mediators: [{ url: 'https://mediator.example', routingKid: 'did:peer:2.Ez6Mk...#key-1' }],
    })
    expect(doc.service).toHaveLength(1)
    expect(doc.service[0]).toEqual({
      id: `${DID}#didcomm`,
      type: 'DIDCommMessaging',
      serviceEndpoint: { uri: 'https://mediator.example', accept: ['didcomm/v2'], routingKeys: ['did:peer:2.Ez6Mk...#key-1'] },
    })
  })

  test('multiple registered mediators each get their own numbered entry', () => {
    const doc = buildRoutingDoc(DID, {
      mediators: [
        { url: 'https://mediator-a.example', routingKid: 'did:peer:2.Ez6A...#key-1' },
        { url: 'https://mediator-b.example', routingKid: 'did:peer:2.Ez6B...#key-1' },
      ],
    })
    expect(doc.service.map(s => s.id)).toEqual([`${DID}#didcomm-1`, `${DID}#didcomm-2`])
    expect(doc.service.map(s => (s.serviceEndpoint as any).uri)).toEqual(['https://mediator-a.example', 'https://mediator-b.example'])
  })

  test('mediators supersede the legacy direct endpoint when both are given', () => {
    const doc = buildRoutingDoc(DID, {
      didCommEndpoint: 'https://core.example/v1/didcomm/ingress',
      mediators: [{ url: 'https://mediator.example', routingKid: 'did:peer:2.Ez6Mk...#key-1' }],
    })
    expect(doc.service).toHaveLength(1)
    expect((doc.service[0]!.serviceEndpoint as any).uri).toBe('https://mediator.example')
  })

  test('no mediators and no legacy endpoint: no DIDCommMessaging service at all', () => {
    const doc = buildRoutingDoc(DID, {})
    expect(doc.service).toEqual([])
  })

  test('falls back to the legacy direct endpoint (empty routingKeys) when no mediator is registered', () => {
    const doc = buildRoutingDoc(DID, { didCommEndpoint: 'https://core.example/v1/didcomm/ingress' })
    expect(doc.service).toEqual([{
      id: `${DID}#didcomm`,
      type: 'DIDCommMessaging',
      serviceEndpoint: { uri: 'https://core.example/v1/didcomm/ingress', accept: ['didcomm/v2'], routingKeys: [] },
    }])
  })
})

describe('MIMI Vault self-room routing', () => {
  const provider = 'https://mimi-self.example'
  const roomId = 'mimi://mimi-self.example/r/vault-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

  test('accepts only the opaque room URI on the configured HTTPS provider', () => {
    expect(mimiVaultRoomFromRouting({ service: [], mimiVaultRoom: { roomId, providerUrl: provider } }, provider)).toBe(roomId)
    expect(mimiVaultRoomFromRouting({ service: [], mimiVaultRoom: { roomId: 'mimi://else.example/r/vault-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', providerUrl: provider } }, provider)).toBeUndefined()
    expect(mimiVaultRoomFromRouting({ service: [], mimiVaultRoom: { roomId, providerUrl: 'http://mimi-self.example' } }, provider)).toBeUndefined()
  })
})
