import { describe, expect, test } from 'bun:test'
import { didCommEndpointWithOnion } from '../src/client/identity/wallet/did-md-oauth.ts'

const clearnet = { uri: 'https://mediator.example/', accept: ['didcomm/v2'], routingKeys: ['did:peer:2.Ez#key-1'] }
const ONION = 'http://abc.onion/'

describe('didCommEndpointWithOnion (the Tor opt-in, PLAN-tor.md D-4/I-5)', () => {
  test('without an onion URL the clearnet single map is published unchanged', () => {
    expect(didCommEndpointWithOnion(clearnet)).toBe(clearnet)
    expect(didCommEndpointWithOnion(clearnet, '')).toBe(clearnet)
  })
  test('with an onion URL: clearnet first, then the same entry at the onion URI (same routingKeys)', () => {
    expect(didCommEndpointWithOnion(clearnet, ONION)).toEqual([clearnet, { ...clearnet, uri: ONION }])
  })
  test('a non-map endpoint (string, already a set) is left alone', () => {
    expect(didCommEndpointWithOnion('urn:biset:vault:0', ONION)).toBe('urn:biset:vault:0')
    const set = [clearnet]
    expect(didCommEndpointWithOnion(set, ONION)).toBe(set)
  })
})
