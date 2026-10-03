// P1 end to end: a sender resolves a did:webvh recipient with two devices,
// encrypts ONE message to both keyAgreement keys, Forwards it to the
// recipient's DID, and the mediator copies it into both device inboxes --
// each device opens it with its own key.
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { sendFrontDoorMessage } from '../src/client/didcomm/front-door-send.ts'
import { registerWithMediator } from '../src/client/didcomm/mediator-sync.ts'
import { pickupDeliver, acknowledgeMessages } from '../src/protocol/didcomm/mediator-pickup.ts'
import { mediatorInbox } from '../src/protocol/didcomm/mediator-device.ts'
import { decodePeerDid2, generatePeerIdentity, publicKeyOf } from '../src/protocol/didcomm/peer.ts'
import { serializeLog } from '../src/protocol/webvh/log.ts'
import { buildDidCommLog } from './protocol/support/webvh-log-fixture.ts'
import { freshMediator, MEDIATOR_URL } from './support/mediator.ts'

describe('multi-device delivery', () => {
  test('one front-door message reaches every device of the recipient DID', async () => {
    const { mediator, handle, store } = freshMediator()
    const root = ed25519.utils.randomSecretKey()
    const phoneX = x25519.utils.randomSecretKey()
    const laptopX = x25519.utils.randomSecretKey()
    const { did, log } = buildDidCommLog({
      rootPrivateKey: root,
      rootPublicKey: ed25519.getPublicKey(root),
      keyAgreementKeys: [
        { fragment: 'k_phone', x25519PublicKey: x25519.getPublicKey(phoneX) },
        { fragment: 'k_laptop', x25519PublicKey: x25519.getPublicKey(laptopX) },
      ],
      endpointUri: MEDIATOR_URL,
      routingKeys: [mediator.xKid],
      domain: 'bob.test.example',
    })
    const fetchImpl = (async (input, init) => {
      const url = new URL(String(input))
      if (url.origin === MEDIATOR_URL) return (await handle(new Request(url, init), url)) ?? new Response('not found', { status: 404 })
      if (url.hostname === 'bob.test.example' && url.pathname.endsWith('/did.jsonl')) return new Response(serializeLog(log))
      return new Response(`unexpected request: ${url}`, { status: 500 })
    }) as typeof fetch

    const phone = mediatorInbox({ did, xKid: `${did}#k_phone`, xPriv: phoneX }, crypto.getRandomValues(new Uint8Array(32)))
    const laptop = mediatorInbox({ did, xKid: `${did}#k_laptop`, xPriv: laptopX }, crypto.getRandomValues(new Uint8Array(32)))
    const info = await registerWithMediator(MEDIATOR_URL, phone, fetchImpl)
    await registerWithMediator(MEDIATOR_URL, laptop, fetchImpl)

    const alice = generatePeerIdentity()
    const sent = await sendFrontDoorMessage(did, 'https://didcomm.org/basicmessage/2.0/message', { content: 'to both' }, { fromKid: alice.xKid, x25519PrivateKey: alice.xPriv, fetch: fetchImpl })
    expect(sent).toEqual({ ok: true })
    expect(store.stats()).toMatchObject({ queuedMessages: 1, pendingDeliveries: 2 })

    const aliceKey = async (kid: string) => publicKeyOf(decodePeerDid2(kid.split('#', 1)[0]!), kid)
    for (const device of [phone, laptop]) {
      const delivered = await pickupDeliver(info, device, aliceKey, 10, fetchImpl)
      expect(delivered).toHaveLength(1)
      expect((delivered[0]!.plaintext as { body: { content: string } }).body.content).toBe('to both')
      expect(delivered[0]!.rawJwe.recipients.map(r => r.header.kid).sort()).toEqual([`${did}#k_laptop`, `${did}#k_phone`])
      await acknowledgeMessages(info, device, [delivered[0]!.ackId], fetchImpl)
    }
    expect(store.stats()).toMatchObject({ queuedMessages: 0, pendingDeliveries: 0 })
  })
})
