// End-to-end: a real packed JWE POSTed to /v1/didcomm/ingress lands in the
// shared IngressStore as protocol:'didcomm', addressed to every trusted
// device of the kid's own identity (CoreIngressAdapter's own invariant --
// an adapter cannot choose which devices receive a body, PLAN.md §1) -- and
// that an unknown recipient kid is rejected before ever reaching the store.
import { describe, expect, test } from 'bun:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { packAuthcrypt } from '../../../src/didcomm/crypto.ts'
import { createDidCommHttpHandler } from '../../../src/core/adapters/didcomm-http.ts'
import { DidCommIngressAdapter } from '../../../src/core/adapters/didcomm.ts'
import { CoreIngressAdapter } from '../../../src/core/adapters/ingress.ts'
import { MemoryIngressStore } from '../../../src/core/mediation/ingress-store.ts'
import type { IngressAuthorizer } from '../../../src/core/mediation/ingress-store.ts'
import { MemoryTrustedDeviceRoster } from '../../../src/core/identity/device-roster.ts'
import type { IngressPullV1 } from '../../../src/protocol/ingress.ts'

const did = 'did:webvh:abc123:alice.test.example'
const kid = `${did}#k_devicehash`

const senderX = x25519.utils.randomSecretKey()
const senderKid = 'did:webvh:def456:bob.test.example#k_senderhash'
const recipientX = x25519.utils.randomSecretKey()
const recipientXPub = x25519.getPublicKey(recipientX)

// Pull/ACK authorization is a separately-tested concern (ingress-store's own
// tests); this test only exercises the offer path, so a permissive stub is
// enough to let a pull() confirm what actually landed.
const permissive: IngressAuthorizer = {
  async verifyPull() { return true },
  async verify() { return true },
}

async function buildHandler() {
  const roster = new MemoryTrustedDeviceRoster()
  await roster.installAcceptedProjection({
    version: 1, identityId: did, selfGroupId: 'self-group-1', epoch: '1', acceptedAt: '2026-08-24T00:00:00.000Z',
    devices: [{ deviceId: kid, deliveryFloor: '1', signingPublicKey: new Uint8Array(32), deviceCredential: new Uint8Array([1]) }],
  })
  const store = new MemoryIngressStore(permissive)
  const coreIngress = new CoreIngressAdapter(roster, store)
  const adapter = new DidCommIngressAdapter(coreIngress)
  const handler = createDidCommHttpHandler(adapter, { roster })
  return { handler, store }
}

const pull: IngressPullV1 = { version: 1, identityId: did, recipientDeviceId: kid, requestedAt: '2026-08-24T00:00:00.000Z', signature: new Uint8Array([1]) }

describe('POST /v1/didcomm/ingress', () => {
  test('a packed JWE for a trusted device kid is accepted and lands in the shared ingress store as protocol:didcomm, addressed to every trusted device', async () => {
    const { handler, store } = await buildHandler()
    const jwe = packAuthcrypt(new TextEncoder().encode('hello'), { kid: senderKid, privateKey: senderX }, { kid, publicKey: recipientXPub })
    const jweBytes = new TextEncoder().encode(JSON.stringify(jwe))

    const res = await handler(new Request('https://core.test.example/v1/didcomm/ingress', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: jweBytes,
    }))
    expect(res.status).toBe(202)

    const pulled = await store.pull(pull)
    expect(pulled).toHaveLength(1)
    expect(pulled[0]?.protocol).toBe('didcomm')
    expect(pulled[0]?.recipientIdentityId).toBe(did)
    expect(pulled[0]?.recipientDeviceSnapshot).toEqual([kid])
    expect(pulled[0]?.protectedPayload).toEqual(jweBytes)
  })

  test('a packed JWE for an unknown recipient kid is rejected before reaching the ingress store', async () => {
    const { handler } = await buildHandler()
    const strangerKid = 'did:webvh:zzz999:stranger.test.example#k_unknown'
    const jwe = packAuthcrypt(new TextEncoder().encode('hello'), { kid: senderKid, privateKey: senderX }, { kid: strangerKid, publicKey: recipientXPub })

    const res = await handler(new Request('https://core.test.example/v1/didcomm/ingress', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(jwe),
    }))
    expect(res.status).toBe(404)
  })

  test('a malformed JWE body is rejected with 400', async () => {
    const { handler } = await buildHandler()
    const res = await handler(new Request('https://core.test.example/v1/didcomm/ingress', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ not: 'a jwe' }),
    }))
    expect(res.status).toBe(400)
  })

  test('rejects methods other than POST/OPTIONS', async () => {
    const { handler } = await buildHandler()
    const res = await handler(new Request('https://core.test.example/v1/didcomm/ingress'))
    expect(res.status).toBe(405)
  })
})
