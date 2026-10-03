// A relationship from first contact to the move a device removal forces,
// end to end: real relationship managers, a real mediator, real front-door
// sends against both identities' signed did:webvh logs.
//
// The threat it pins: a removed device keeps every old relationship key
// (shared by all of an identity's devices). Until the counterparty handles
// the move it can still speak for the identity -- that window cannot be
// closed without the counterparty -- but from the move on it cannot: the
// move is a front-door INIT (a key it no longer has in the DID document),
// and the counterparty stops accepting the old did:peer once it has handled
// the move. Nothing legitimately sent before the move is lost: the
// counterparty takes what is already queued from the old did:peer first.
import { afterEach, describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { decodePeerDid2, publicKeyOf } from '../src/protocol/didcomm/peer.ts'
import { mediatorInbox } from '../src/protocol/didcomm/mediator-device.ts'
import type { MediatorInboxClient } from '../src/protocol/didcomm/mediator-transport.ts'
import { acknowledgeMessages, pickupDeliver, type DeliveredMessage } from '../src/protocol/didcomm/mediator-pickup.ts'
import { resolveDidCommSenderKey } from '../src/protocol/didcomm/webvh-resolve.ts'
import type { DidCommPlaintext } from '../src/protocol/didcomm/message.ts'
import { registerWithMediator } from '../src/client/didcomm/mediator-sync.ts'
import { RELATIONSHIP_INIT, relationshipBodyToWire } from '../src/client/didcomm/relationship.ts'
import { sendRelationshipMessage } from '../src/client/didcomm/send-message.ts'
import { sendFrontDoorMessage } from '../src/client/didcomm/front-door-send.ts'
import { createWalletRelationshipManager, type WalletRelationshipManager } from '../src/client/identity/wallet/relationship.ts'
import { contactKeyRef, type ContactKeyV1 } from '../src/client/store/vault/contact-key.ts'
import { selectUnsuperseded } from '../src/client/store/vault/credential-store.ts'
import { buildDidCommLog } from './protocol/support/webvh-log-fixture.ts'
import { freshMediator, MEDIATOR_URL } from './support/mediator.ts'

/** An in-memory ContactKey store with ContactKeyReader's selection rules. */
function contactStore() {
  const records: ContactKeyV1[] = []
  const newest = (values: ContactKeyV1[]) => [...values].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))[0] ?? null
  const store = {
    records,
    async store(contact: ContactKeyV1) { records.push(contact) },
    async readAll() { return [...records] },
    async currentFor(counterpartyDid: string) {
      const values = records.filter(value => value.counterpartyDid === counterpartyDid)
      return values.length ? selectUnsuperseded(values, { kidOf: contactKeyRef, supersededKidOf: value => value.supersedes ? contactKeyRef(value.supersedes) : undefined, duplicateMessage: 'dup', ambiguousMessage: 'ambiguous' }) : null
    },
    async currentForCounterpartyKid(kid: string) {
      const named = newest(records.filter(value => value.counterpartyRelationshipKid === kid))
      const current = named ? await store.currentFor(named.counterpartyDid) : null
      return current?.counterpartyRelationshipKid === kid ? current : null
    },
  }
  return store
}

const peerKey = async (kid: string) => publicKeyOf(decodePeerDid2(kid.split('#', 1)[0]!), kid)
const realFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = realFetch })

describe('a relationship moves after a device removal', () => {
  test('first contact, then a move: the removed device speaks for the identity until the move and never after; nothing sent before it is lost', async () => {
    const { mediator, handle, store: mediatorStore } = freshMediator()
    const logs = new Map<string, string>()
    globalThis.fetch = (async (input, init) => {
      const url = new URL(String(input))
      if (url.origin === MEDIATOR_URL) return (await handle(new Request(url, init), url)) ?? new Response('not found', { status: 404 })
      const log = url.pathname === '/.well-known/did.jsonl' ? logs.get(url.host) : undefined
      return log ? new Response(log) : new Response('not found', { status: 404 })
    }) as typeof fetch

    type Party = Awaited<ReturnType<typeof party>>
    async function party(domain: string) {
      const root = ed25519.utils.randomSecretKey()
      const frontX = x25519.utils.randomSecretKey()
      const { did, log } = buildDidCommLog({
        rootPrivateKey: root, rootPublicKey: ed25519.getPublicKey(root), domain,
        keyAgreementKeys: [{ fragment: 'k_front', x25519PublicKey: x25519.getPublicKey(frontX) }],
        endpointUri: MEDIATOR_URL, routingKeys: [mediator.xKid],
      })
      logs.set(domain, log.map(entry => JSON.stringify(entry)).join('\n') + '\n')
      const deviceSecret = crypto.getRandomValues(new Uint8Array(32))
      const front = mediatorInbox({ did, xKid: `${did}#k_front`, xPriv: frontX }, deviceSecret)
      await registerWithMediator(MEDIATOR_URL, front)
      const contacts = contactStore()
      const seed = { current: { seed: crypto.getRandomValues(new Uint8Array(32)), seedId: `${domain}-seed-1` } }
      const inboxes = new Map<string, MediatorInboxClient>()
      const accepted: string[] = []
      const rejected: string[] = []
      const self = {
        did, front, contacts, seed, inboxes, accepted, rejected,
        manager: undefined as unknown as WalletRelationshipManager,
        /** Front-door traffic: INIT and ACCEPT, through the manager. */
        async takeFrontDoor() {
          await take(front, kid => resolveDidCommSenderKey(kid), message => self.manager.handleMessage(message, front.xKid, MEDIATOR_URL))
        },
        /** Relationship traffic: accepted only from a CURRENT counterparty kid. */
        async takeRelationship(ownKid: string) {
          await take(inboxes.get(ownKid)!, peerKey, async message => {
            const content = String((message.plaintext as DidCommPlaintext & { body: { content: string } }).body.content)
            if (await contacts.currentForCounterpartyKid(message.senderKid)) accepted.push(content)
            else rejected.push(content)
          })
        },
      }
      self.manager = createWalletRelationshipManager({
        identityId: did,
        frontDoor: { xKid: front.xKid, x25519PrivateKey: frontX },
        relationshipSeed: { require: async () => seed.current },
        mediatorDeviceSecret: deviceSecret,
        reader: contacts,
        sink: contacts,
        startWatch: (kid, xPriv, peerDid) => { inboxes.set(kid, mediatorInbox({ did: peerDid, xKid: kid, xPriv }, deviceSecret)) },
        drainInbox: ownKid => self.takeRelationship(ownKid),
      })
      return self
    }

    /** Pickup, handle, acknowledge -- everything queued for `inbox`. */
    async function take(inbox: MediatorInboxClient, resolve: (kid: string) => Promise<Uint8Array>, handleOne: (message: DeliveredMessage) => Promise<void>) {
      const info = { url: MEDIATOR_URL, did: mediator.did, xKid: mediator.xKid, xPub: mediator.xPub }
      for (;;) {
        const delivered = await pickupDeliver(info, inbox, resolve, 10)
        const status = mediatorStore.count(inbox.did, inbox.device)
        for (const message of delivered) await handleOne(message)
        await acknowledgeMessages(info, inbox, delivered.map(message => message.ackId))
        // Whatever could not be opened was skipped; acknowledge it too, as
        // the live client does for a PermanentDeliveryError.
        if (delivered.length === status) break
        const left = mediatorStore.peek(inbox.did, inbox.device, 100).map(m => m.id)
        await acknowledgeMessages(info, inbox, left)
        break
      }
    }

    const alice = await party('alice.example')
    const bob = await party('bob.example')

    // First contact: Bob's INIT and Alice's ACCEPT, both over front doors.
    const waiting = bob.manager.ensureContact(alice.did)
    await until(() => mediatorStore.count(alice.front.did, alice.front.device) > 0)
    await alice.takeFrontDoor()
    await bob.takeFrontDoor()
    const bobContact = await waiting
    const aliceOld = (await alice.contacts.currentFor(bob.did))!
    expect(bobContact.counterpartyRelationshipKid).toBe(aliceOld.ownRelationshipKid)
    expect(aliceOld.counterpartyRelationshipKid).toBe(bobContact.ownRelationshipKid)

    // Traffic now runs between the two did:peers only.
    expect((await sendRelationshipMessage(bobContact, 'hello alice')).ok).toBe(true)
    await alice.takeRelationship(aliceOld.ownRelationshipKid)
    expect(alice.accepted).toEqual(['hello alice'])

    // Alice removes a device. It keeps Alice's old relationship (`aliceOld`);
    // Alice's remaining devices get a new seed it never sees.
    const removed = aliceOld
    alice.seed.current = { seed: crypto.getRandomValues(new Uint8Array(32)), seedId: 'alice.example-seed-2' }

    // While Bob is offline, both the remaining device and the removed one
    // send from the old did:peer (they hold the same key).
    expect((await sendRelationshipMessage(aliceOld, 'legit, before the move')).ok).toBe(true)
    expect((await sendRelationshipMessage(removed, 'removed device, before the move')).ok).toBe(true)

    // The removed device cannot move the relationship itself: a front-door
    // INIT needs a key Alice's DID document lists, and it has none (its
    // front-door key was removed; here, one that was never listed).
    const outsiderX = x25519.utils.randomSecretKey()
    await sendFrontDoorMessage(bob.did, RELATIONSHIP_INIT, relationshipBodyToWire({ relationshipKid: removed.ownRelationshipKid, publicKey: x25519.getPublicKey(removed.ownX25519PrivateKey) }), { fromKid: `${alice.did}#k_removed`, x25519PrivateKey: outsiderX })

    // A remaining device of Alice moves the relationship (its next send, or
    // the move after removal): re-INIT from a key in Alice's DID document.
    const moving = alice.manager.ensureContact(bob.did)
    await until(() => mediatorStore.count(bob.front.did, bob.front.device) > 1)
    // Bob handles the move: first everything queued from Alice's old
    // did:peer (still Alice's then), then the move itself.
    await bob.takeFrontDoor()
    expect(bob.accepted).toEqual(['legit, before the move', 'removed device, before the move'])
    await alice.takeFrontDoor()
    const aliceNew = await moving
    expect(aliceNew).toMatchObject({ seedId: 'alice.example-seed-2', supersedes: { ownRelationshipKid: aliceOld.ownRelationshipKid, counterpartyRelationshipKid: aliceOld.counterpartyRelationshipKid } })
    expect(aliceNew.ownRelationshipKid).not.toBe(aliceOld.ownRelationshipKid)
    expect((await bob.contacts.currentFor(alice.did))!.counterpartyRelationshipKid).toBe(aliceNew.ownRelationshipKid)

    // From now on the removed device's old did:peer is not Alice to Bob.
    expect((await sendRelationshipMessage(removed, 'removed device, after the move')).ok).toBe(true)
    expect((await sendRelationshipMessage(aliceNew, 'alice, after the move')).ok).toBe(true)
    await bob.takeRelationship(bobContact.ownRelationshipKid)
    expect(bob.rejected).toEqual(['removed device, after the move'])
    expect(bob.accepted.at(-1)).toBe('alice, after the move')
    // Nothing left queued to redeliver.
    expect(mediatorStore.count(bob.inboxes.get(bobContact.ownRelationshipKid)!.did, bob.inboxes.get(bobContact.ownRelationshipKid)!.device)).toBe(0)
  })
})

async function until(condition: () => boolean, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('condition did not become ready')
    await new Promise(resolve => setTimeout(resolve, 5))
  }
}
