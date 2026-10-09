// `from_prior` (DID Rotation) signing and every check a receiver makes on it
// (PLAN-refactor.md §4.4, §7-2).
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import type { LogEntry } from '../../src/protocol/webvh/log.ts'
import {
  assertKeyNotStale, createFromPrior, FromPriorError, fromPriorClaims, fromPriorKeyResolver, verifyFromPrior,
} from '../../src/protocol/didcomm/from-prior.ts'
import { b64url } from '../../src/protocol/didcomm/crypto.ts'
import { generatePeerIdentity } from '../../src/protocol/didcomm/peer.ts'
import { encodeMultikey } from '../../src/protocol/webvh/multikey.ts'
import { buildDidCommLog } from './support/webvh-log-fixture.ts'

const rotation = ed25519.keygen()
const root = ed25519.keygen()
const device = x25519.keygen()

function identity(authenticated = true) {
  return buildDidCommLog({
    rootPrivateKey: root.secretKey, rootPublicKey: root.publicKey,
    keyAgreementKeys: [{ fragment: 'k_a', x25519PublicKey: device.publicKey }],
    rawVerificationMethods: [{ fragment: 'didcomm-rotation', publicKeyMultibase: encodeMultikey(rotation.publicKey) }],
    authenticationFragments: authenticated ? ['didcomm-rotation'] : [],
  })
}

const serving = (log: LogEntry[]) => (async () => new Response(log.map(entry => JSON.stringify(entry)).join('\n') + '\n')) as unknown as typeof fetch
const peer = generatePeerIdentity({ uri: 'https://mediator.example' })

describe('from_prior', () => {
  test('a rotation signed by the published authentication key verifies, and names prior and current', async () => {
    const { did, log } = identity()
    const jwt = createFromPrior({ iss: did, sub: peer.did, iat: 1_700_000_000 }, `${did}#didcomm-rotation`, rotation.secretKey)
    expect(fromPriorClaims(jwt)).toMatchObject({ iss: did, sub: peer.did, kid: `${did}#didcomm-rotation` })
    expect(await verifyFromPrior(jwt, peer.did, fromPriorKeyResolver(serving(log)))).toEqual({ prior: did, current: peer.did, kid: `${did}#didcomm-rotation`, iat: 1_700_000_000 })
  })

  test('refuses a key the document has but does not reference from authentication', async () => {
    const { did, log } = identity(false)
    const jwt = createFromPrior({ iss: did, sub: peer.did }, `${did}#didcomm-rotation`, rotation.secretKey)
    await expect(verifyFromPrior(jwt, peer.did, fromPriorKeyResolver(serving(log)))).rejects.toBeInstanceOf(FromPriorError)
  })

  test('refuses another signer, a sub that is not the message\'s from, and a kid of another DID', async () => {
    const { did, log } = identity()
    const resolver = fromPriorKeyResolver(serving(log))
    const forged = createFromPrior({ iss: did, sub: peer.did }, `${did}#didcomm-rotation`, ed25519.keygen().secretKey)
    await expect(verifyFromPrior(forged, peer.did, resolver)).rejects.toThrow('signature does not verify')
    const good = createFromPrior({ iss: did, sub: peer.did }, `${did}#didcomm-rotation`, rotation.secretKey)
    await expect(verifyFromPrior(good, generatePeerIdentity().did, resolver)).rejects.toThrow('sub is not')
    // A header put together by hand, kid on another DID than iss.
    const [, payload, signature] = good.split('.')
    const header = b64url(new TextEncoder().encode(JSON.stringify({ typ: 'JWT', alg: 'EdDSA', kid: `${peer.did}#key-1` })))
    await expect(verifyFromPrior(`${header}.${payload}.${signature}`, peer.did, resolver)).rejects.toThrow('kid must be a DID URL of iss')
  })

  test('honours exp and nbf', async () => {
    const { did, log } = identity()
    const header = b64url(new TextEncoder().encode(JSON.stringify({ typ: 'JWT', alg: 'EdDSA', kid: `${did}#didcomm-rotation` })))
    const sign = (claims: object) => {
      const payload = b64url(new TextEncoder().encode(JSON.stringify({ iss: did, sub: peer.did, iat: 1000, ...claims })))
      return `${header}.${payload}.${b64url(ed25519.sign(new TextEncoder().encode(`${header}.${payload}`), rotation.secretKey))}`
    }
    const resolver = fromPriorKeyResolver(serving(log))
    await expect(verifyFromPrior(sign({ exp: 2000 }), peer.did, resolver, 3000 * 1000)).rejects.toThrow('expired')
    await expect(verifyFromPrior(sign({ nbf: 5000 }), peer.did, resolver, 3000 * 1000)).rejects.toThrow('not yet valid')
    expect((await verifyFromPrior(sign({ exp: 5000, nbf: 2000 }), peer.did, resolver, 3000 * 1000)).current).toBe(peer.did)
  })

  test('a did:peer:2 prior is checked against its own authentication key', async () => {
    const next = generatePeerIdentity()
    const jwt = createFromPrior({ iss: peer.did, sub: next.did }, peer.edKid, peer.edPriv)
    expect((await verifyFromPrior(jwt, next.did, fromPriorKeyResolver(serving([])))).prior).toBe(peer.did)
    await expect(verifyFromPrior(createFromPrior({ iss: peer.did, sub: next.did }, peer.xKid, peer.edPriv), next.did, fromPriorKeyResolver(serving([])))).rejects.toThrow('is not an authentication key')
  })
})

describe('a key published before a device was removed (§7-2)', () => {
  const entry = (keys: string[], published = true) => ({
    versionId: 'x', versionTime: '2026-10-08T00:00:00Z', parameters: {},
    state: {
      id: 'did:webvh:s:a.example', keyAgreement: keys.map(key => `#${key}`),
      authentication: published ? ['#didcomm-rotation'] : [],
      verificationMethod: [{ id: '#didcomm-rotation', publicKeyMultibase: encodeMultikey(rotation.publicKey) }],
    },
  } as unknown as LogEntry)

  test('is refused; one removed with the key\'s own publication, or a device added later, is not', () => {
    expect(() => assertKeyNotStale([entry(['a', 'b']), entry(['a'])], '#didcomm-rotation')).toThrow('before a device was removed')
    expect(() => assertKeyNotStale([entry(['a', 'b'], false), entry(['a'])], '#didcomm-rotation')).not.toThrow()
    expect(() => assertKeyNotStale([entry(['a']), entry(['a', 'b'])], '#didcomm-rotation')).not.toThrow()
    expect(() => assertKeyNotStale([entry(['a'], false)], '#didcomm-rotation')).toThrow('not an authentication key')
  })
})
