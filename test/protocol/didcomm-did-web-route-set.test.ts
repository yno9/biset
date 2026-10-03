import { describe, expect, test } from 'bun:test'
import { didWebDidCommRoute, type DidWebDocument } from '../../src/protocol/didcomm/did-web.ts'
import { encodeX25519Multikey } from '../../src/protocol/didcomm/multikey.ts'

const DID = 'did:web:smtp.example'
const key = encodeX25519Multikey(new Uint8Array(32).fill(7))
const base = (serviceEndpoint: unknown): DidWebDocument => ({
  id: DID,
  verificationMethod: [{ id: `${DID}#k1`, type: 'Multikey', controller: DID, publicKeyMultibase: key }],
  keyAgreement: [`${DID}#k1`],
  service: [{ id: `${DID}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint }],
})
const entry = (uri: string) => ({ uri, accept: ['didcomm/v2'], routingKeys: [] })

describe('didWebDidCommRoute with a published set', () => {
  test('reads the canonical entry of a set; a single map is unchanged', () => {
    expect(didWebDidCommRoute(base([entry('http://x.onion'), entry('https://smtp.example')])).uri).toBe('https://smtp.example')
    expect(didWebDidCommRoute(base(entry('https://smtp.example'))).uri).toBe('https://smtp.example')
  })
  test('an onion-only set has no route', () => {
    expect(() => didWebDidCommRoute(base([entry('http://x.onion')]))).toThrow('no DIDComm route')
  })
})
