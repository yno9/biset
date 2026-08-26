import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { BASIC_MESSAGE } from '../src/didcomm/basicmessage.ts'
import { pickupDeliver } from '../src/didcomm/mediator-pickup.ts'
import { registerWithMediator } from '../src/didcomm/mediator-sync.ts'
import { decodePeerDid2, generatePeerIdentity, publicKeyOf } from '../src/didcomm/peer.ts'
import { RELATIONSHIP_ACCEPT, RELATIONSHIP_INIT, relationshipBodyOf, relationshipMediatorService } from '../src/didcomm/relationship.ts'
import {
  initiateRelationship,
  sendRelationshipAccept,
  sendRelationshipMessage,
} from '../src/didcomm/send-message.ts'
import type { DidCommPlaintext } from '../src/didcomm/message.ts'
import { encodeX25519Multikey } from '../src/didcomm/multikey.ts'
import { createMediator } from '../src/mediator/server.ts'
import { ConnectionStore } from '../src/mediator/connections.ts'
import type { ContactKeyV1 } from '../src/vault/contact-key.ts'
import { buildGenesisLog } from './protocol/support/webvh-log-fixture.ts'

describe('private DIDComm relationship handshake', () => {
  test('moves continuing traffic off both public front-door kids and registers only unlinkable did:peer relationship clients', async () => {
    const mediatorUrl = `https://relationship-mediator-${crypto.randomUUID()}.test.example`
    const mediator = generatePeerIdentity({ uri: mediatorUrl, accept: ['didcomm/v2'] })
    const connections = new ConnectionStore()

    const aliceRoot = ed25519.utils.randomSecretKey()
    const { did: aliceDid, log: aliceLog } = buildGenesisLog(aliceRoot, ed25519.getPublicKey(aliceRoot), [])
    const aliceFrontX = x25519.utils.randomSecretKey()
    const aliceFrontKid = `${aliceDid}#k_alice-front-door`
    const bobDid = 'did:webvh:123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijk:Bob.example'
    const bobFrontX = x25519.utils.randomSecretKey()
    const bobFrontKid = `${bobDid}#k_bob-front-door`

    const { handle } = createMediator({
      mediator,
      connections,
      async resolveDidWebvh(_did, kid) {
        if (kid === aliceFrontKid) return x25519.getPublicKey(aliceFrontX)
        if (kid === bobFrontKid) return x25519.getPublicKey(bobFrontX)
        return null
      },
    })
    const routingJson = {
      service: [{
        id: `${aliceDid}#didcomm`,
        type: 'DIDCommMessaging',
        serviceEndpoint: { uri: mediatorUrl, accept: ['didcomm/v2'], routingKeys: [mediator.xKid] },
      }],
      keyAgreementVerificationMethod: [{
        id: aliceFrontKid,
        type: 'Multikey',
        controller: aliceDid,
        publicKeyMultibase: encodeX25519Multikey(x25519.getPublicKey(aliceFrontX)),
      }],
    }
    const fetchImpl = (async (input, init) => {
      const url = new URL(String(input))
      if (url.origin === mediatorUrl) return (await handle(new Request(url, init), url)) ?? new Response('not found', { status: 404 })
      if (url.pathname.endsWith('/did.jsonl')) return new Response(aliceLog.map(value => JSON.stringify(value)).join('\n') + '\n')
      if (url.pathname.endsWith('/routing.json')) return Response.json(routingJson)
      return new Response(`unexpected request: ${url}`, { status: 500 })
    }) as typeof fetch
    const realFetch = globalThis.fetch
    globalThis.fetch = fetchImpl
    try {
      const aliceFront = { did: aliceDid, xKid: aliceFrontKid, xPriv: aliceFrontX }
      await registerWithMediator(mediatorUrl, aliceFront, fetchImpl)

      // Bob enrolls his private kid BEFORE INIT, making Alice's ACCEPT
      // deliverable without exposing Bob's public DID in that registration.
      const initiated = await initiateRelationship(aliceDid, {
        fromKid: bobFrontKid,
        x25519PrivateKey: bobFrontX,
        fetch: fetchImpl,
      })
      expect(initiated.ok).toBe(true)
      if (!initiated.ok) throw new Error(initiated.error)
      const bobRelationship = initiated.pending.peer
      expect(connections.listKeys(bobRelationship.did)).toEqual([bobRelationship.xKid])
      expect(connections.listKeys(bobDid)).toEqual([])

      const initDelivered = await pickupDeliver(mediatorInfo(), aliceFront, async kid => {
        if (kid !== bobFrontKid) throw new Error(`unexpected INIT sender ${kid}`)
        return x25519.getPublicKey(bobFrontX)
      }, 10, fetchImpl)
      expect(initDelivered).toHaveLength(1)
      const init = initDelivered[0]!.plaintext as DidCommPlaintext
      expect(init.type).toBe(RELATIONSHIP_INIT)
      const initBody = relationshipBodyOf(init)!

      const route = relationshipMediatorService(initBody.relationshipKid)
      const aliceRelationship = generatePeerIdentity({ uri: route.url, routingKeys: [route.routingKid] })
      await registerWithMediator(route.url, { did: aliceRelationship.did, xKid: aliceRelationship.xKid, xPriv: aliceRelationship.xPriv }, fetchImpl)
      const aliceContact: ContactKeyV1 = {
        version: 1,
        kind: 'contact-key',
        identityId: aliceDid,
        counterpartyDid: bobDid,
        ownRelationshipKid: aliceRelationship.xKid,
        ownX25519PrivateKey: aliceRelationship.xPriv,
        ownEd25519PrivateKey: aliceRelationship.edPriv,
        counterpartyRelationshipKid: initBody.relationshipKid,
        counterpartyPublicKey: initBody.publicKey,
        createdAt: '2026-08-27T00:00:00.000Z',
      }
      expect((await sendRelationshipAccept(aliceContact, fetchImpl)).ok).toBe(true)

      const acceptDelivered = await pickupDeliver(mediatorInfo(), {
        did: bobRelationship.did,
        xKid: bobRelationship.xKid,
        xPriv: bobRelationship.xPriv,
      }, peerKey, 10, fetchImpl)
      expect(acceptDelivered).toHaveLength(1)
      expect((acceptDelivered[0]!.plaintext as DidCommPlaintext).type).toBe(RELATIONSHIP_ACCEPT)
      expect(acceptDelivered[0]!.senderKid).toBe(aliceRelationship.xKid)
      expect(acceptDelivered[0]!.rawJwe.recipients[0]?.header.kid).toBe(bobRelationship.xKid)
      const acceptBody = relationshipBodyOf(acceptDelivered[0]!.plaintext as DidCommPlaintext)!

      const bobContact: ContactKeyV1 = {
        version: 1,
        kind: 'contact-key',
        identityId: bobDid,
        counterpartyDid: aliceDid,
        ownRelationshipKid: bobRelationship.xKid,
        ownX25519PrivateKey: bobRelationship.xPriv,
        ownEd25519PrivateKey: bobRelationship.edPriv,
        counterpartyRelationshipKid: acceptBody.relationshipKid,
        counterpartyPublicKey: acceptBody.publicKey,
        createdAt: '2026-08-27T00:00:01.000Z',
      }
      expect((await sendRelationshipMessage(bobContact, 'only private kids from here', undefined, fetchImpl)).ok).toBe(true)

      const continuing = await pickupDeliver(mediatorInfo(), {
        did: aliceRelationship.did,
        xKid: aliceRelationship.xKid,
        xPriv: aliceRelationship.xPriv,
      }, peerKey, 10, fetchImpl)
      expect(continuing).toHaveLength(1)
      expect((continuing[0]!.plaintext as DidCommPlaintext).type).toBe(BASIC_MESSAGE)
      expect((continuing[0]!.plaintext as DidCommPlaintext).body).toMatchObject({ content: 'only private kids from here' })
      expect(continuing[0]!.senderKid).toBe(bobRelationship.xKid)
      expect(continuing[0]!.rawJwe.recipients[0]?.header.kid).toBe(aliceRelationship.xKid)
      expect(JSON.stringify(continuing[0]!.rawJwe)).not.toContain(aliceFrontKid)
      expect(JSON.stringify(continuing[0]!.rawJwe)).not.toContain(bobFrontKid)

      // The public Alice connection remains only for first contact. Each
      // relationship registration is owned by its own self-certifying peer
      // DID; neither public identity is present in that ownership record.
      expect(connections.listKeys(aliceDid)).toEqual([aliceFrontKid])
      expect(connections.listKeys(aliceRelationship.did)).toEqual([aliceRelationship.xKid])
      expect(connections.listKeys(bobRelationship.did)).toEqual([bobRelationship.xKid])
      expect(aliceRelationship.did).not.toContain(aliceDid)
      expect(bobRelationship.did).not.toContain(bobDid)
    } finally {
      globalThis.fetch = realFetch
    }

    function mediatorInfo() {
      return { url: mediatorUrl, did: mediator.did, xKid: mediator.xKid, xPub: mediator.xPub }
    }
    async function peerKey(kid: string): Promise<Uint8Array> {
      const did = kid.split('#', 1)[0]!
      return publicKeyOf(decodePeerDid2(did), kid)
    }
  })
})
