// DIDComm Messaging v2.1 "Message Layer Addressing Consistency": the plaintext
// `from` of an authcrypt message MUST match the encryption layer's `skid`.
// Found 2026-10-02: the mediator authorized by `from` alone, so a client that
// authenticated with its own key could name another client in `from` and
// deregister that client's key (dropping its queue).
import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../src/protocol/didcomm/peer.ts'
import { createMediator } from '../src/server/mediator/server.ts'
import { SqliteMediatorStore } from '../src/server/mediator/sqlite-store.ts'
import { packAuthcrypt, packAnoncrypt, didCommPost } from '../src/protocol/didcomm/crypto.ts'
import { addressedTo, assertFromMatchesSender, buildPlaintext, DidCommSenderMismatchError } from '../src/protocol/didcomm/message.ts'
import { unpackQueuedMessage } from '../src/protocol/didcomm/mediator-pickup.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)
type Peer = ReturnType<typeof generatePeerIdentity>

describe('assertFromMatchesSender', () => {
  const kid = 'did:webvh:Qm1:alice.example#k_abc'
  test('accepts a `from` that is the DID of the authenticated sender kid', () => {
    expect(() => assertFromMatchesSender({ from: 'did:webvh:Qm1:alice.example' }, kid)).not.toThrow()
  })
  test('rejects a missing `from`, a `from` with a fragment, and another DID', () => {
    expect(() => assertFromMatchesSender({}, kid)).toThrow(DidCommSenderMismatchError)
    expect(() => assertFromMatchesSender({ from: kid }, kid)).toThrow('without a fragment')
    expect(() => assertFromMatchesSender({ from: 'did:webvh:Qm2:mallory.example' }, kid)).toThrow('does not match')
  })
})

describe('addressedTo', () => {
  test('an absent `to` means "only you"; otherwise the own DID must be listed (fragments ignored)', () => {
    expect(addressedTo({}, 'did:a#k1')).toBe(true)
    expect(addressedTo({ to: ['did:a'] }, 'did:a#k1')).toBe(true)
    expect(addressedTo({ to: ['did:a#k2'] }, 'did:a#k1')).toBe(true)
    expect(addressedTo({ to: ['did:b'] }, 'did:a#k1')).toBe(false)
  })
})

function harness() {
  const store = SqliteMediatorStore.memory()
  const mediator = store.loadIdentity('https://mediator.test.example')
  const { handle } = createMediator({ mediator, store })
  const post = (body: unknown) => handle(new Request('https://mediator.test.example/', didCommPost(body)), new URL('https://mediator.test.example/'))
  const send = (sender: Peer, claimedFrom: string, type: string, body: unknown) => {
    const plaintext = buildPlaintext(type, body, claimedFrom, mediator.did)
    return post(packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: sender.xKid, privateKey: sender.xPriv }, [{ kid: mediator.xKid, publicKey: mediator.xPub }]))
  }
  const forwardTo = (kid: string, inner: unknown) => {
    const fwd = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next: kid }); fwd.attachments = [{ id: crypto.randomUUID(), data: { json: inner } }]
    return post(packAnoncrypt(utf8(JSON.stringify(fwd)), [{ kid: mediator.xKid, publicKey: mediator.xPub }]))
  }
  return { send, forwardTo }
}

describe('mediator', () => {
  test('a client authenticating as itself but claiming another client in `from` is refused, and the victim stays registered', async () => {
    const { send, forwardTo } = harness()
    const victim = generatePeerIdentity(); const attacker = generatePeerIdentity(); const alice = generatePeerIdentity()
    await send(victim, victim.did, 'https://didcomm.org/coordinate-mediation/2.0/mediate-request', {})
    await send(victim, victim.did, 'https://didcomm.org/coordinate-mediation/2.0/keylist-update', { device: 'victim-device', updates: [{ recipient_did: victim.did, action: 'add' }] })
    const inner = packAuthcrypt(utf8('{}'), { kid: alice.xKid, privateKey: alice.xPriv }, [{ kid: victim.xKid, publicKey: victim.xPub }])
    expect((await forwardTo(victim.xKid, inner))!.status).toBe(202)

    for (const [type, body] of [
      ['https://didcomm.org/coordinate-mediation/2.0/keylist-update', { device: 'victim-device', updates: [{ recipient_did: victim.did, action: 'remove' }] }],
      ['https://didcomm.org/messagepickup/3.0/messages-received', { device: 'victim-device', message_id_list: ['anything'] }],
      ['https://didcomm.org/messagepickup/3.0/delivery-request', { recipient_did: victim.did, device: 'victim-device', limit: 10 }],
    ] as const) {
      const res = await send(attacker, victim.did, type, body)
      expect(res!.status).toBe(400)
      expect(await res!.text()).toContain('does not match the authenticated sender')
    }
    expect((await forwardTo(victim.xKid, inner))!.status).toBe(202)
  })
})

describe('client delivery (unpackQueuedMessage)', () => {
  test('a queued message whose `from` differs from its sender is not delivered; a consistent one is', async () => {
    const bob = generatePeerIdentity(); const alice = generatePeerIdentity(); const mallory = generatePeerIdentity()
    const pack = (claimedFrom: string) => packAuthcrypt(utf8(JSON.stringify(buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content: 'hi' }, claimedFrom, bob.did))),
      { kid: mallory.xKid, privateKey: mallory.xPriv }, [{ kid: bob.xKid, publicKey: bob.xPub }])
    const own = { did: bob.did, xKid: bob.xKid, xPriv: bob.xPriv }
    const resolve = async () => mallory.xPub
    expect(await unpackQueuedMessage(pack(alice.did), 'q1', own, resolve)).toBeUndefined()
    const ok = await unpackQueuedMessage(pack(mallory.did), 'q2', own, resolve)
    expect(ok?.senderKid).toBe(mallory.xKid)
  })
})
