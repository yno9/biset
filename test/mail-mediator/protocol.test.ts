import { expect, test, describe } from 'bun:test'
import {
  routeBindBodyToWire, routeBindBodyOf,
  pickupItemToWire, pickupItemOf,
  submitBodyToWire, submitBodyOf,
  type RouteBindBody, type PickupItem, type SubmitBody,
} from '../../src/mail-mediator/protocol.ts'

describe('mail-mediator protocol wire encoding', () => {
  test('route-bind body round-trips through wire JSON', () => {
    const body: RouteBindBody = {
      address: 'y@biset.md',
      relationshipKid: 'did:peer:2.a#key-1',
      pickupPublicKey: new Uint8Array(32).fill(7),
      routeGeneration: 'gen-1',
      expiresAt: '2030-01-01T00:00:00.000Z',
      mailAddressCredential: 'header.payload.signature',
    }
    const wire = JSON.parse(JSON.stringify(routeBindBodyToWire(body)))
    const decoded = routeBindBodyOf(wire)
    expect(decoded).toEqual(body)
  })

  test('route-bind body rejects a malformed pickupPublicKey length', () => {
    const decoded = routeBindBodyOf({
      address: 'y@biset.md',
      relationshipKid: 'did:peer:2.a#key-1',
      pickupPublicKey: Buffer.from([1, 2, 3]).toString('base64url'),
      routeGeneration: 'gen-1',
      expiresAt: '2030-01-01T00:00:00.000Z',
    })
    expect(decoded).toBeNull()
  })

  test('route-bind body rejects missing fields', () => {
    expect(routeBindBodyOf({ address: 'y@biset.md' })).toBeNull()
    expect(routeBindBodyOf(null)).toBeNull()
    expect(routeBindBodyOf('not an object')).toBeNull()
  })

  test('pickup item round-trips through wire JSON', () => {
    const item: PickupItem = {
      spoolId: 'spool-1',
      semanticIngressId: 'sid-1',
      mailFrom: 'sender@example.com',
      encryptedBody: new Uint8Array([1, 2, 3, 4]),
      bodyHash: new Uint8Array([9, 9]),
      createdAt: '2026-01-01T00:00:00.000Z',
    }
    const wire = JSON.parse(JSON.stringify(pickupItemToWire(item)))
    expect(pickupItemOf(wire)).toEqual(item)
  })

  test('submit body round-trips through wire JSON', () => {
    const body: SubmitBody = {
      idempotencyKey: 'idem-1',
      mailFrom: 'y@biset.md',
      rcptTo: ['a@example.com', 'b@example.com'],
      rawRfc5322: new Uint8Array([65, 66, 67]),
    }
    const wire = JSON.parse(JSON.stringify(submitBodyToWire(body)))
    expect(submitBodyOf(wire)).toEqual(body)
  })

  test('submit body rejects an empty recipient list', () => {
    const decoded = submitBodyOf({
      idempotencyKey: 'idem-1',
      mailFrom: 'y@biset.md',
      rcptTo: [],
      rawRfc5322: Buffer.from('x').toString('base64url'),
    })
    expect(decoded).toBeNull()
  })
})
