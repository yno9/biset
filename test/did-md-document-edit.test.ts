// How a Biset device's DIDComm endpoint is written into its DID document: the
// endpoint names the mediator by DID (DIDComm Messaging v2.1, "Using a DID as
// an endpoint"), and a move between mediators retires the old endpoints.
import { describe, expect, test } from 'bun:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { buildDocumentEdit, retiredMediatorEndpoints, walletConfiguration } from '../src/client/identity/wallet/did-md-oauth.ts'

const DID = 'did:webvh:QmScid:alice.example'
const device = (extra: Record<string, unknown> = {}) => ({
  x25519PublicKey: x25519.getPublicKey(x25519.utils.randomSecretKey()),
  mediatorUrl: 'https://mediator.example', routingKid: 'did:web:mediator.example#key-1', mediatorDid: 'did:web:mediator.example', xKid: `${DID}#k_x`,
  ...extra,
}) as never

const didcommService = (edit: ReturnType<typeof buildDocumentEdit>) => edit.services.find(service => service.id === '#didcomm')!

describe('the DIDComm service of a DID document edit', () => {
  test('by default the endpoint names the mediator by DID: no URL, no routing keys', () => {
    const edit = buildDocumentEdit(DID, walletConfiguration(), device())
    const service = didcommService(edit)
    expect(service.type).toBe('DIDCommMessaging')
    expect(service.serviceEndpoint).toEqual({ uri: 'did:web:mediator.example', accept: ['didcomm/v2'] })
    expect((service as { endpointMode?: string }).endpointMode).toBe('merge') // each device adds its own, never replacing a sibling's
  })

  test('a mediator\'s Tor entrance is not added to the identity\'s document: the mediator\'s own document lists it', () => {
    const edit = buildDocumentEdit(DID, walletConfiguration(), device({ mediatorOnionUrl: 'http://abc.onion' }))
    expect(didcommService(edit).serviceEndpoint).toEqual({ uri: 'did:web:mediator.example', accept: ['didcomm/v2'] })
  })

  test('a configured template can still name the mediator by URL and routing key, with its Tor entrance beside it', () => {
    const legacy = walletConfiguration({ didDocumentServices: [{ purpose: 'didcomm', id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: '$mediatorUrl', accept: ['didcomm/v2'], routingKeys: ['$routingKid'] } }] })
    const url = didcommService(buildDocumentEdit(DID, legacy, device({ routingKid: 'did:peer:2.Ez6L.Vz6M#key-1' }))).serviceEndpoint
    expect(url).toEqual({ uri: 'https://mediator.example', accept: ['didcomm/v2'], routingKeys: ['did:peer:2.Ez6L.Vz6M#key-1'] })
    const withOnion = didcommService(buildDocumentEdit(DID, legacy, device({ routingKid: 'did:peer:2.Ez6L.Vz6M#key-1', mediatorOnionUrl: 'http://abc.onion' }))).serviceEndpoint as Array<Record<string, unknown>>
    expect(withOnion.map(entry => entry.uri)).toEqual(['https://mediator.example', 'http://abc.onion'])
  })

  test('naming the mediator by DID retires the clearnet URL-form endpoint an older document still carries (not the onion one)', () => {
    const edit = buildDocumentEdit(DID, walletConfiguration(), device())
    expect(edit.removeEndpoints).toEqual([
      { serviceId: '#didcomm', match: { uri: 'https://mediator.example' } },
      { serviceId: '#didcomm', match: { uri: 'https://mediator.example/' } },
    ])
    const withOnion = buildDocumentEdit(DID, walletConfiguration(), device({ mediatorOnionUrl: 'http://abc.onion/' }))
    expect(JSON.stringify(withOnion.removeEndpoints)).not.toContain('onion')
  })

  test('a configured URL-form template retires nothing, and a removal already asked for is not repeated', () => {
    const legacy = walletConfiguration({ didDocumentServices: [{ purpose: 'didcomm', id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: '$mediatorUrl', accept: ['didcomm/v2'], routingKeys: ['$routingKid'] } }] })
    expect(buildDocumentEdit(DID, legacy, device()).removeEndpoints).toBeUndefined()
    const asked = { serviceId: '#didcomm', match: { uri: 'https://mediator.example/' } }
    expect(buildDocumentEdit(DID, walletConfiguration(), device(), [], [asked]).removeEndpoints?.filter(removal => removal.match.uri === 'https://mediator.example/')).toEqual([asked])
  })

  test('the device key is added and bound to the service', () => {
    const d = device()
    const edit = buildDocumentEdit(DID, walletConfiguration(), d)
    expect(edit.verificationMethods).toHaveLength(1)
    expect(edit.serviceKeyBindings).toEqual([{ serviceId: '#didcomm', keyIds: [edit.verificationMethods[0]!.id] }])
  })
})

describe('retiredMediatorEndpoints', () => {
  const web = { routingKid: 'did:web:a.example#key-1', mediatorDid: 'did:web:a.example' }
  test('the same mediator keeps what is published', () => {
    expect(retiredMediatorEndpoints(web, web, '#didcomm')).toEqual([])
    expect(retiredMediatorEndpoints(undefined, web, '#didcomm')).toEqual([])
  })
  test('moving to another mediator retires the old DID endpoint, and the old routing key\'s (URL-form) endpoints', () => {
    const other = { routingKid: 'did:web:b.example#key-1', mediatorDid: 'did:web:b.example' }
    expect(retiredMediatorEndpoints(web, other, '#didcomm')).toEqual([
      { serviceId: '#didcomm', match: { routingKeys: ['did:web:a.example#key-1'] } },
      { serviceId: '#didcomm', match: { uri: 'did:web:a.example' } },
    ])
  })
  test('moving from the URL form to the DID form retires the URL form (a device authorized before has no mediatorDid)', () => {
    expect(retiredMediatorEndpoints({ routingKid: 'did:peer:2.Ez6L#key-1' }, web, '#didcomm')).toEqual([
      { serviceId: '#didcomm', match: { routingKeys: ['did:peer:2.Ez6L#key-1'] } },
    ])
  })
})

describe('the rotation key in a document edit', () => {
  test('rides along as an authentication method with its mode, not bound to the DIDComm service', async () => {
    const { rotationKeyEditMethod, ROTATION_KEY_FRAGMENT } = await import('../src/client/didcomm/rotation-key.ts')
    const seed = crypto.getRandomValues(new Uint8Array(32))
    const edit = buildDocumentEdit(DID, walletConfiguration(), device(), [], [], rotationKeyEditMethod(seed, 'ifAbsent'))
    const rotation = edit.verificationMethods.find(method => method.id === ROTATION_KEY_FRAGMENT)!
    expect(rotation).toMatchObject({ controller: DID, relationships: ['authentication'], mode: 'ifAbsent', type: 'Multikey' })
    expect(edit.verificationMethods).toHaveLength(2)
    expect(edit.serviceKeyBindings![0]!.keyIds).not.toContain(ROTATION_KEY_FRAGMENT)
  })
})
