// Full-mesh DIDComm group chat, exercised at the same level
// mediator-relationship-handshake.test.ts already does: real identities,
// a real (in-process) mediator, driving send-message.ts's functions
// directly rather than through main.ts (which has no test seam for this).
// Establishes THREE pairwise relationships (Alice<->Bob, Alice<->Carol,
// Bob<->Carol -- the actual mesh, not just Alice's own two), then verifies
// a GROUP_INVITE reaches every invitee with the full roster and a
// GROUP_MESSAGE fans out to every other member with the same groupId/
// content and a DIFFERENT senderKid per recipient (the property
// group-chat.ts's own dedupe scheme depends on).
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { acknowledgeMessages, pickupDeliver, type DeliveredMessage } from '../src/shared/didcomm/mediator-pickup.ts'
import type { DidCommSender, MediatorInfo } from '../src/shared/didcomm/mediator-transport.ts'
import { registerWithMediator } from '../src/shared/didcomm/mediator-sync.ts'
import { decodePeerDid2, generatePeerIdentity, publicKeyOf } from '../src/shared/didcomm/peer.ts'
import { relationshipBodyOf, relationshipMediatorService } from '../src/shared/didcomm/relationship.ts'
import { initiateRelationship, sendRelationshipAccept, sendGroupInvite, sendGroupChatMessage } from '../src/shared/didcomm/send-message.ts'
import { groupInviteBodyOf, groupMessageBodyOf, isGroupInvite, isGroupMessage } from '../src/shared/didcomm/group-chat.ts'
import type { DidCommPlaintext } from '../src/shared/didcomm/message.ts'
import { encodeX25519Multikey } from '../src/shared/didcomm/multikey.ts'
import { createMediator } from '../src/server/didcomm-mediator/server.ts'
import { ConnectionStore } from '../src/server/didcomm-mediator/connections.ts'
import type { ContactKeyV1 } from '../src/client/store/vault/contact-key.ts'
import { buildGenesisLog } from './protocol/support/webvh-log-fixture.ts'

interface Identity { did: string; domain: string; frontKid: string; frontX: Uint8Array; log: unknown[] }

/** Pickup 3.0 delivery is non-destructive -- the mediator keeps every
 * returned message queued until acknowledged (mediator-pickup.ts's own
 * header). This test picks up the SAME kid more than once across the
 * mesh-bootstrap loop and the later invite/message steps, so every pickup
 * here acks what it received, matching how a real client behaves (unlike
 * mediator-relationship-handshake.test.ts, which only ever picks up each
 * kid once and so never needed to). */
async function deliverAndAck(mediator: MediatorInfo, own: DidCommSender, resolveSenderKey: Parameters<typeof pickupDeliver>[2], limit: number, fetchImpl: typeof fetch): Promise<DeliveredMessage[]> {
  const delivered = await pickupDeliver(mediator, own, resolveSenderKey, limit, fetchImpl)
  if (delivered.length) await acknowledgeMessages(mediator, own, delivered.map(d => d.ackId), fetchImpl)
  return delivered
}

function makeIdentity(name: string): Identity {
  const root = ed25519.utils.randomSecretKey()
  const domain = `${name}.test.example`
  const { did, log } = buildGenesisLog(root, ed25519.getPublicKey(root), [], domain)
  const frontX = x25519.utils.randomSecretKey()
  return { did, domain, frontKid: `${did}#k_${name}-front-door`, frontX, log }
}

describe('DIDComm group chat mesh', () => {
  test('a GROUP_INVITE reaches every invitee with the full roster, and a GROUP_MESSAGE fans out to every other member', async () => {
    const mediatorUrl = `https://group-mesh-mediator-${crypto.randomUUID()}.test.example`
    const mediator = generatePeerIdentity({ uri: mediatorUrl, accept: ['didcomm/v2'] })
    const connections = new ConnectionStore()

    const alice = makeIdentity('alice')
    const bob = makeIdentity('bob')
    const carol = makeIdentity('carol')
    const identities = [alice, bob, carol]

    const { handle } = createMediator({
      mediator,
      connections,
      async resolveDidWebvh(_did, kid) {
        const owner = identities.find(id => id.frontKid === kid)
        return owner ? x25519.getPublicKey(owner.frontX) : null
      },
    })
    const routingJsonFor = (identity: Identity) => ({
      service: [{ id: `${identity.did}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: mediatorUrl, accept: ['didcomm/v2'], routingKeys: [mediator.xKid] } }],
      keyAgreementVerificationMethod: [{ id: identity.frontKid, type: 'Multikey', controller: identity.did, publicKeyMultibase: encodeX25519Multikey(x25519.getPublicKey(identity.frontX)) }],
    })
    const fetchImpl = (async (input, init) => {
      const url = new URL(String(input))
      if (url.origin === mediatorUrl) return (await handle(new Request(url, init), url)) ?? new Response('not found', { status: 404 })
      const owner = identities.find(id => url.hostname === id.domain)
      if (url.pathname.endsWith('/did.jsonl') && owner) return new Response(owner.log.map(value => JSON.stringify(value)).join('\n') + '\n')
      if (url.pathname.endsWith('/routing.json') && owner) return Response.json(routingJsonFor(owner))
      return new Response(`unexpected request: ${url}`, { status: 500 })
    }) as typeof fetch
    const realFetch = globalThis.fetch
    globalThis.fetch = fetchImpl
    try {
      for (const identity of identities) {
        await registerWithMediator(mediatorUrl, { did: identity.did, xKid: identity.frontKid, xPriv: identity.frontX }, fetchImpl)
      }

      // Establish the ACTUAL mesh: Alice<->Bob, Alice<->Carol, Bob<->Carol.
      const contacts = new Map<string, Map<string, ContactKeyV1>>() // holderDid -> counterpartyDid -> ContactKeyV1
      const pairs: [Identity, Identity][] = [[alice, bob], [alice, carol], [bob, carol]]
      for (const [from, to] of pairs) {
        const initiated = await initiateRelationship(to.did, { fromKid: from.frontKid, x25519PrivateKey: from.frontX, fetch: fetchImpl })
        expect(initiated.ok).toBe(true)
        if (!initiated.ok) throw new Error(initiated.error)
        const fromPeer = initiated.pending.peer

        const delivered = await deliverAndAck({ url: mediatorUrl, did: mediator.did, xKid: mediator.xKid, xPub: mediator.xPub }, { did: to.did, xKid: to.frontKid, xPriv: to.frontX }, async kid => {
          if (kid !== from.frontKid) throw new Error(`unexpected INIT sender ${kid}`)
          return x25519.getPublicKey(from.frontX)
        }, 10, fetchImpl)
        expect(delivered).toHaveLength(1)
        const initBody = relationshipBodyOf(delivered[0]!.plaintext as DidCommPlaintext)!

        const route = relationshipMediatorService(initBody.relationshipKid)
        const toPeer = generatePeerIdentity({ uri: route.url, routingKeys: [route.routingKid] })
        await registerWithMediator(route.url, { did: toPeer.did, xKid: toPeer.xKid, xPriv: toPeer.xPriv }, fetchImpl)
        const toContact: ContactKeyV1 = {
          version: 1, kind: 'contact-key', identityId: to.did, counterpartyDid: from.did,
          ownRelationshipKid: toPeer.xKid, ownX25519PrivateKey: toPeer.xPriv, ownEd25519PrivateKey: toPeer.edPriv,
          counterpartyRelationshipKid: initBody.relationshipKid, counterpartyPublicKey: initBody.publicKey, createdAt: '2026-09-02T00:00:00.000Z',
        }
        expect((await sendRelationshipAccept(toContact, fetchImpl)).ok).toBe(true)

        const acceptDelivered = await deliverAndAck({ url: mediatorUrl, did: mediator.did, xKid: mediator.xKid, xPub: mediator.xPub }, { did: fromPeer.did, xKid: fromPeer.xKid, xPriv: fromPeer.xPriv }, peerKey, 10, fetchImpl)
        expect(acceptDelivered).toHaveLength(1)
        const acceptBody = relationshipBodyOf(acceptDelivered[0]!.plaintext as DidCommPlaintext)!
        const fromContact: ContactKeyV1 = {
          version: 1, kind: 'contact-key', identityId: from.did, counterpartyDid: to.did,
          ownRelationshipKid: fromPeer.xKid, ownX25519PrivateKey: fromPeer.xPriv, ownEd25519PrivateKey: fromPeer.edPriv,
          counterpartyRelationshipKid: acceptBody.relationshipKid, counterpartyPublicKey: acceptBody.publicKey, createdAt: '2026-09-02T00:00:01.000Z',
        }
        setContact(contacts, from.did, to.did, fromContact)
        setContact(contacts, to.did, from.did, toContact)
      }

      // Alice creates the group and invites Bob and Carol.
      const groupId = 'mesh-test-group'
      const members = [alice.did, bob.did, carol.did]
      const aliceToBob = contacts.get(alice.did)!.get(bob.did)!
      const aliceToCarol = contacts.get(alice.did)!.get(carol.did)!
      expect((await sendGroupInvite(aliceToBob, { groupId, members, name: 'Mesh Test' }, fetchImpl)).ok).toBe(true)
      expect((await sendGroupInvite(aliceToCarol, { groupId, members, name: 'Mesh Test' }, fetchImpl)).ok).toBe(true)

      const bobPeer = { did: aliceToBob.counterpartyRelationshipKid.split('#', 1)[0]!, xKid: aliceToBob.counterpartyRelationshipKid, xPriv: contacts.get(bob.did)!.get(alice.did)!.ownX25519PrivateKey }
      const carolPeer = { did: aliceToCarol.counterpartyRelationshipKid.split('#', 1)[0]!, xKid: aliceToCarol.counterpartyRelationshipKid, xPriv: contacts.get(carol.did)!.get(alice.did)!.ownX25519PrivateKey }

      const bobInvite = await deliverAndAck({ url: mediatorUrl, did: mediator.did, xKid: mediator.xKid, xPub: mediator.xPub }, bobPeer, peerKey, 10, fetchImpl)
      expect(bobInvite).toHaveLength(1)
      const bobInvitePlaintext = bobInvite[0]!.plaintext as DidCommPlaintext
      expect(isGroupInvite(bobInvitePlaintext)).toBe(true)
      expect(groupInviteBodyOf(bobInvitePlaintext)).toEqual({ groupId, members, name: 'Mesh Test' })
      const bobSenderKidForInvite = bobInvite[0]!.senderKid

      const carolInvite = await deliverAndAck({ url: mediatorUrl, did: mediator.did, xKid: mediator.xKid, xPub: mediator.xPub }, carolPeer, peerKey, 10, fetchImpl)
      expect(carolInvite).toHaveLength(1)
      const carolInvitePlaintext = carolInvite[0]!.plaintext as DidCommPlaintext
      expect(isGroupInvite(carolInvitePlaintext)).toBe(true)
      expect(groupInviteBodyOf(carolInvitePlaintext)).toEqual({ groupId, members, name: 'Mesh Test' })

      // Alice fans out a GROUP_MESSAGE to Bob and Carol.
      expect((await sendGroupChatMessage(aliceToBob, { groupId, content: 'hello mesh', sentAt: '2026-09-02T00:10:00.000Z' }, fetchImpl, { id: 'msg-1', sentAt: '2026-09-02T00:10:00.000Z' })).ok).toBe(true)
      expect((await sendGroupChatMessage(aliceToCarol, { groupId, content: 'hello mesh', sentAt: '2026-09-02T00:10:00.000Z' }, fetchImpl, { id: 'msg-1', sentAt: '2026-09-02T00:10:00.000Z' })).ok).toBe(true)

      const bobMessage = await deliverAndAck({ url: mediatorUrl, did: mediator.did, xKid: mediator.xKid, xPub: mediator.xPub }, bobPeer, peerKey, 10, fetchImpl)
      expect(bobMessage).toHaveLength(1)
      const bobMessagePlaintext = bobMessage[0]!.plaintext as DidCommPlaintext
      expect(isGroupMessage(bobMessagePlaintext)).toBe(true)
      expect(groupMessageBodyOf(bobMessagePlaintext)).toEqual({ groupId, content: 'hello mesh', sentAt: '2026-09-02T00:10:00.000Z' })

      const carolMessage = await deliverAndAck({ url: mediatorUrl, did: mediator.did, xKid: mediator.xKid, xPub: mediator.xPub }, carolPeer, peerKey, 10, fetchImpl)
      expect(carolMessage).toHaveLength(1)
      const carolMessagePlaintext = carolMessage[0]!.plaintext as DidCommPlaintext
      expect(isGroupMessage(carolMessagePlaintext)).toBe(true)
      expect(groupMessageBodyOf(carolMessagePlaintext)).toEqual({ groupId, content: 'hello mesh', sentAt: '2026-09-02T00:10:00.000Z' })

      // Same logical message (same `id`), but each recipient authenticates
      // Alice under a DIFFERENT pairwise relationship kid -- confirms the
      // dedupe scheme (keyed by senderKid + message id) never collides
      // across recipients of the same fan-out send.
      expect(bobMessage[0]!.senderKid).not.toBe(carolMessage[0]!.senderKid)
      expect(bobSenderKidForInvite).toBe(bobMessage[0]!.senderKid)
    } finally {
      globalThis.fetch = realFetch
    }

    function setContact(map: Map<string, Map<string, ContactKeyV1>>, holder: string, counterparty: string, contact: ContactKeyV1): void {
      if (!map.has(holder)) map.set(holder, new Map())
      map.get(holder)!.set(counterparty, contact)
    }
    async function peerKey(kid: string): Promise<Uint8Array> {
      const did = kid.split('#', 1)[0]!
      return publicKeyOf(decodePeerDid2(did), kid)
    }
  })
})
