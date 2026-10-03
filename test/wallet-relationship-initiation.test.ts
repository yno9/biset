import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../src/protocol/didcomm/peer.ts'
import { relationshipBodyToWire } from '../src/client/didcomm/relationship.ts'
import { createWalletRelationshipManager, type WalletRelationshipManagerOptions } from '../src/client/identity/wallet/relationship.ts'
import { PermanentDeliveryError } from '../src/protocol/didcomm/mediator-pickup.ts'
import type { ContactKeyV1 } from '../src/client/store/vault/contact-key.ts'

const mediatorUrl = 'https://wallet-relationship.test.example'
const walletDid = 'did:webvh:wallet:alice.test.example'
const counterpartyDid = 'did:webvh:wallet:bob.test.example'
/** The counterparty's front-door key: an ACCEPT comes over its front door. */
const counterpartyFrontDoor = `${counterpartyDid}#k_bob`
const ACCEPT = 'https://biset.md/relationship/1.0/accept'

const peer = () => generatePeerIdentity({ uri: mediatorUrl, routingKeys: ['did:peer:2.routing#key-1'] })
const seed = (seedId: string) => ({ async require() { return { seed: new Uint8Array(32).fill(seedId.length), seedId } } })

function manager(options: Partial<WalletRelationshipManagerOptions> & Pick<WalletRelationshipManagerOptions, 'reader' | 'sink' | 'initiate'>) {
  return createWalletRelationshipManager({
    identityId: walletDid,
    frontDoor: { xKid: `${walletDid}#k_wallet`, x25519PrivateKey: new Uint8Array(32).fill(7) },
    relationshipSeed: seed('seed-1'),
    mediatorDeviceSecret: new Uint8Array(32).fill(8),
    startWatch() {},
    ...options,
  })
}

function accept(from: string, relationship: ReturnType<typeof peer>) {
  return {
    ackId: 'accept', rawJwe: {} as never, senderKid: from,
    plaintext: { type: ACCEPT, body: relationshipBodyToWire({ relationshipKid: relationship.xKid, publicKey: relationship.xPub }) },
  }
}

function contactWith(own: ReturnType<typeof peer>, remote: ReturnType<typeof peer>, seedId: string): ContactKeyV1 {
  return {
    version: 1, kind: 'contact-key', identityId: walletDid, counterpartyDid,
    ownRelationshipKid: own.xKid, ownX25519PrivateKey: own.xPriv, ownEd25519PrivateKey: own.edPriv,
    counterpartyRelationshipKid: remote.xKid, counterpartyPublicKey: remote.xPub,
    createdAt: '2026-09-05T12:00:00.000Z', seedId,
  }
}

describe('Wallet DIDComm relationship', () => {
  test('initiates once, watches its private receiver, and persists the front-door ACCEPT as the contact a waiting send uses', async () => {
    const pendingPeer = peer()
    const counterpartyPeer = peer()
    const contacts: ContactKeyV1[] = []
    const watched: Array<{ kid: string; did: string; url: string }> = []
    let initiations = 0
    const relationships = manager({
      reader: { async currentFor(did) { return contacts.findLast(contact => contact.counterpartyDid === did) ?? null } },
      sink: { async store(contact) { contacts.push(contact) } },
      initiate: async did => {
        initiations += 1
        expect(did).toBe(counterpartyDid)
        return { ok: true, pending: { counterpartyDid: did, peer: pendingPeer, mediatorUrl } }
      },
      startWatch(kid, _privateKey, did, url) { watched.push({ kid, did, url }) },
      now: () => new Date('2026-09-05T12:00:00.000Z'),
    })

    const waitingContact = relationships.ensureContact(counterpartyDid)
    await waitFor(() => initiations === 1)
    expect(watched).toEqual([{ kid: pendingPeer.xKid, did: pendingPeer.did, url: mediatorUrl }])

    await relationships.handleMessage(accept(counterpartyFrontDoor, counterpartyPeer), `${walletDid}#k_wallet`, mediatorUrl)

    const contact = await waitingContact
    expect(contact).toMatchObject({
      identityId: walletDid, counterpartyDid, seedId: 'seed-1',
      ownRelationshipKid: pendingPeer.xKid, counterpartyRelationshipKid: counterpartyPeer.xKid,
    })
    expect(contact.supersedes).toBeUndefined()
    expect(await relationships.ensureContact(counterpartyDid)).toEqual(contact)
    expect(initiations).toBe(1)
  })

  test('an ACCEPT from a did:peer is refused for good: only a key in the counterparty\'s DID document can answer an INIT', async () => {
    // Its mediator knows the INIT's did:peer and could otherwise answer
    // first with a did:peer of its own, sitting in the middle of the
    // relationship from then on.
    const pendingPeer = peer()
    const impostor = peer()
    let initiated = false
    const relationships = manager({
      reader: { async currentFor() { return null } },
      sink: { async store() { throw new Error('must not store an ACCEPT that is not from the front door') } },
      initiate: async did => { initiated = true; return { ok: true, pending: { counterpartyDid: did, peer: pendingPeer, mediatorUrl } } },
    })
    void relationships.ensureContact(counterpartyDid).catch(() => {})
    await waitFor(() => initiated)
    await expect(relationships.handleMessage(accept(impostor.xKid, impostor), pendingPeer.xKid, mediatorUrl)).rejects.toBeInstanceOf(PermanentDeliveryError)
  })

  test('an ACCEPT from someone this side never initiated with is dropped as permanent', async () => {
    const relationships = manager({
      reader: { async currentFor() { return null } },
      sink: { async store() { throw new Error('must not store') } },
      initiate: async () => { throw new Error('must not initiate') },
    })
    await expect(relationships.handleMessage(accept('did:webvh:wallet:mallory.test.example#k_m', peer()), `${walletDid}#k_wallet`, mediatorUrl)).rejects.toBeInstanceOf(PermanentDeliveryError)
  })

  test('persists a late ACCEPT after the caller timed out waiting for it', async () => {
    const pendingPeer = peer()
    const counterpartyPeer = peer()
    const contacts: ContactKeyV1[] = []
    const relationships = manager({
      reader: { async currentFor(did) { return contacts.findLast(contact => contact.counterpartyDid === did) ?? null } },
      sink: { async store(contact) { contacts.push(contact) } },
      initiate: async did => ({ ok: true, pending: { counterpartyDid: did, peer: pendingPeer, mediatorUrl } }),
      timeoutMs: 1,
    })
    await expect(relationships.ensureContact(counterpartyDid)).rejects.toThrow(`relationship handshake with ${counterpartyDid} timed out`)
    await relationships.handleMessage(accept(counterpartyFrontDoor, counterpartyPeer), `${walletDid}#k_wallet`, mediatorUrl)
    expect(contacts).toHaveLength(1)
    expect(contacts[0]!.counterpartyRelationshipKid).toBe(counterpartyPeer.xKid)
  })

  test('an INIT left unanswered past the wait is sent again on the next attempt (its ACCEPT was lost or dropped)', async () => {
    const pendingPeer = peer()
    const counterpartyPeer = peer()
    const contacts: ContactKeyV1[] = []
    let initiations = 0
    const relationships = manager({
      reader: { async currentFor(did) { return contacts.findLast(contact => contact.counterpartyDid === did) ?? null } },
      sink: { async store(contact) { contacts.push(contact) } },
      initiate: async did => { initiations += 1; return { ok: true, pending: { counterpartyDid: did, peer: pendingPeer, mediatorUrl } } },
      timeoutMs: 5,
    })
    await expect(relationships.ensureContact(counterpartyDid)).rejects.toThrow('timed out')
    await new Promise(resolve => setTimeout(resolve, 10))
    const retried = relationships.ensureContact(counterpartyDid)
    await waitFor(() => initiations === 2)
    await relationships.handleMessage(accept(counterpartyFrontDoor, counterpartyPeer), `${walletDid}#k_wallet`, mediatorUrl)
    expect((await retried).counterpartyRelationshipKid).toBe(counterpartyPeer.xKid)
  })

  test('a crossing INIT reuses its stored contact when ACCEPT arrives instead of duplicating it', async () => {
    const ownPeer = peer()
    const remotePeer = peer()
    const existing = contactWith(ownPeer, remotePeer, 'seed-1')
    let contact: ContactKeyV1 | null = null
    let stores = 0
    let initiated = false
    const relationships = manager({
      reader: { async currentFor() { return contact } },
      sink: { async store() { stores += 1 } },
      initiate: async did => { initiated = true; return { ok: true, pending: { counterpartyDid: did, peer: ownPeer, mediatorUrl } } },
    })
    const waiting = relationships.ensureContact(counterpartyDid)
    await waitFor(() => initiated)
    // The crossing remote INIT was handled while our own initiation waited.
    contact = existing
    await relationships.handleMessage(accept(counterpartyFrontDoor, remotePeer), `${walletDid}#k_wallet`, mediatorUrl)
    expect(await waiting).toEqual(existing)
    expect(stores).toBe(0)
  })

  test('a relationship from an older seed (a device was removed) is moved before anything is sent on it: re-INIT, and the ACCEPT supersedes it', async () => {
    const oldOwn = peer()
    const oldRemote = peer()
    const newOwn = peer()
    const newRemote = peer()
    const contacts: ContactKeyV1[] = [contactWith(oldOwn, oldRemote, 'seed-old')]
    const drained: string[] = []
    let initiations = 0
    const relationships = manager({
      relationshipSeed: seed('seed-new'),
      reader: { async currentFor(did) { return contacts.findLast(contact => contact.counterpartyDid === did) ?? null } },
      sink: { async store(contact) { contacts.push(contact) } },
      initiate: async did => { initiations += 1; return { ok: true, pending: { counterpartyDid: did, peer: newOwn, mediatorUrl } } },
      drainInbox: async ownKid => { drained.push(ownKid) },
    })
    const waiting = relationships.ensureContact(counterpartyDid)
    await waitFor(() => initiations === 1)
    // The counterparty answered from a did:peer of its own it had not used
    // with us: what it sent from the old one is taken first.
    await relationships.handleMessage(accept(counterpartyFrontDoor, newRemote), `${walletDid}#k_wallet`, mediatorUrl)
    const moved = await waiting
    expect(moved).toMatchObject({ seedId: 'seed-new', ownRelationshipKid: newOwn.xKid, counterpartyRelationshipKid: newRemote.xKid })
    expect(moved.supersedes).toEqual({ ownRelationshipKid: oldOwn.xKid, counterpartyRelationshipKid: oldRemote.xKid })
    expect(drained).toEqual([oldOwn.xKid])
  })

  test('nothing is sent without a usable seed: a removed device, or one still waiting for the seed, cannot even start', async () => {
    const relationships = manager({
      relationshipSeed: { async require() { throw new Error('This device was removed from your account.') } },
      reader: { async currentFor() { return contactWith(peer(), peer(), 'seed-1') } },
      sink: { async store() { throw new Error('must not store') } },
      initiate: async () => { throw new Error('must not initiate') },
    })
    await expect(relationships.ensureContact(counterpartyDid)).rejects.toThrow('removed')
  })
})

async function waitFor(condition: () => boolean, timeoutMs = 1000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('condition did not become ready')
    await new Promise(resolve => setTimeout(resolve, 1))
  }
}
