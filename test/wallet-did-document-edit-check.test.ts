import { describe, expect, test } from 'bun:test'
import { endpointsAreRemoved, serviceIsPublished } from '../src/client/identity/wallet/did-document-edit-check.ts'

const clearnet = { uri: 'https://m.example/', accept: ['didcomm/v2'], routingKeys: ['k1'] }
const onion = { ...clearnet, uri: 'http://x.onion/' }
const svc = (serviceEndpoint: unknown) => ({ id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint }) as never

describe('serviceIsPublished', () => {
  test('replace (or no mode): the published service must be exactly the requested one', () => {
    expect(serviceIsPublished(svc(clearnet), svc(clearnet))).toBe(true)
    expect(serviceIsPublished(svc([clearnet, onion]), svc(clearnet))).toBe(false)
    expect(serviceIsPublished(svc(clearnet), { ...svc(clearnet), endpointMode: 'replace' })).toBe(true)
    expect(serviceIsPublished(undefined, svc(clearnet))).toBe(false)
  })
  test('merge: the published service may hold more, and the request-only endpointMode is not part of it', () => {
    const merge = (e: unknown) => ({ ...svc(e), endpointMode: 'merge' }) as never
    expect(serviceIsPublished(svc(clearnet), merge(clearnet))).toBe(true)
    expect(serviceIsPublished(svc([clearnet, onion]), merge(clearnet))).toBe(true)
    expect(serviceIsPublished(svc([clearnet, onion]), merge([clearnet, onion]))).toBe(true)
    expect(serviceIsPublished(svc(clearnet), merge([clearnet, onion]))).toBe(false)
    expect(serviceIsPublished(undefined, merge(clearnet))).toBe(false)
    expect(serviceIsPublished({ ...svc(clearnet), type: 'Other' } as never, merge(clearnet))).toBe(false)
  })
  test('key order does not matter; an endpoint that differs in content does', () => {
    const reordered = { routingKeys: ['k1'], uri: 'https://m.example/', accept: ['didcomm/v2'] }
    expect(serviceIsPublished(svc(reordered), { ...svc(clearnet), endpointMode: 'merge' } as never)).toBe(true)
    expect(serviceIsPublished(svc({ ...clearnet, routingKeys: ['other'] }), { ...svc(clearnet), endpointMode: 'merge' } as never)).toBe(false)
  })
})

describe('endpointsAreRemoved', () => {
  test('true when nothing matches every property, false while a matching endpoint is still published', () => {
    expect(endpointsAreRemoved(svc([clearnet, onion]), { serviceId: '#didcomm', match: { routingKeys: ['k2'] } })).toBe(true)
    expect(endpointsAreRemoved(svc([clearnet, onion]), { serviceId: '#didcomm', match: { routingKeys: ['k1'] } })).toBe(false)
    expect(endpointsAreRemoved(svc([clearnet, onion]), { serviceId: '#didcomm', match: { uri: 'http://x.onion/', routingKeys: ['k2'] } })).toBe(true)
  })
  test('a missing service has nothing left; a string endpoint matches on uri', () => {
    expect(endpointsAreRemoved(undefined, { serviceId: '#didcomm', match: { uri: 'x' } })).toBe(true)
    expect(endpointsAreRemoved(svc('https://a.example'), { serviceId: '#didcomm', match: { uri: 'https://a.example' } })).toBe(false)
  })
})
