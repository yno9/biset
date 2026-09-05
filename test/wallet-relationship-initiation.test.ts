import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../src/didcomm/peer.ts'
import { relationshipBodyToWire } from '../src/didcomm/relationship.ts'
import { createWalletRelationshipManager } from '../src/wallet/relationship.ts'
import type { ContactKeyV1 } from '../src/vault/contact-key.ts'

const mediatorUrl = 'https://wallet-relationship.test.example'
const walletDid = 'did:webvh:wallet:alice.test.example'
const counterpartyDid = 'did:webvh:wallet:bob.test.example'

describe('Wallet-initiated DIDComm relationship', () => {
  test('initiates once, watches its private receiver, and persists the ACCEPT as the contact used by the waiting send', async () => {
    const pendingPeer = generatePeerIdentity({ uri: mediatorUrl, routingKeys: ['did:peer:2.routing#key-1'] })
    const counterpartyPeer = generatePeerIdentity({ uri: mediatorUrl, routingKeys: ['did:peer:2.routing#key-1'] })
    const contacts: ContactKeyV1[] = []
    const watched: Array<{ kid: string; did: string; url: string }> = []
    let initiations = 0
    const manager = createWalletRelationshipManager({
      identityId: walletDid,
      frontDoor: {
        xKid: `${walletDid}#k_wallet`,
        x25519PrivateKey: new Uint8Array(32).fill(7),
      },
      reader: {
        async currentFor(did) { return contacts.find(contact => contact.counterpartyDid === did) ?? null },
        async forOwnKid(kid) { return contacts.find(contact => contact.ownRelationshipKid === kid) ?? null },
      },
      sink: { async store(contact) { contacts.push(contact) } },
      initiate: async did => {
        initiations += 1
        expect(did).toBe(counterpartyDid)
        return { ok: true, pending: { counterpartyDid: did, peer: pendingPeer, mediatorUrl } }
      },
      startWatch(kid, _privateKey, did, url) { watched.push({ kid, did, url }) },
      now: () => new Date('2026-09-05T12:00:00.000Z'),
    })

    const waitingContact = manager.ensureContact(counterpartyDid)
    await waitFor(() => initiations === 1)
    expect(initiations).toBe(1)
    expect(watched).toEqual([{ kid: pendingPeer.xKid, did: pendingPeer.did, url: mediatorUrl }])

    await manager.handleMessage({
      ackId: 'accept-1',
      rawJwe: {} as never,
      senderKid: counterpartyPeer.xKid,
      plaintext: {
        type: 'https://biset.md/relationship/1.0/accept',
        body: relationshipBodyToWire({ relationshipKid: counterpartyPeer.xKid, publicKey: counterpartyPeer.xPub }),
      },
    }, pendingPeer.xKid, mediatorUrl)

    const contact = await waitingContact
    expect(contact).toMatchObject({
      identityId: walletDid,
      counterpartyDid,
      ownRelationshipKid: pendingPeer.xKid,
      counterpartyRelationshipKid: counterpartyPeer.xKid,
      createdAt: '2026-09-05T12:00:00.000Z',
    })
    expect(contacts).toHaveLength(1)
    expect(await manager.ensureContact(counterpartyDid)).toEqual(contact)
    expect(initiations).toBe(1)
  })

  test('rejects an ACCEPT that is not authenticated by the relationship kid it claims', async () => {
    const pendingPeer = generatePeerIdentity({ uri: mediatorUrl, routingKeys: ['did:peer:2.routing#key-1'] })
    const claimedPeer = generatePeerIdentity({ uri: mediatorUrl, routingKeys: ['did:peer:2.routing#key-1'] })
    const differentPeer = generatePeerIdentity({ uri: mediatorUrl, routingKeys: ['did:peer:2.routing#key-1'] })
    let initiated = false
    const manager = createWalletRelationshipManager({
      identityId: walletDid,
      frontDoor: { xKid: `${walletDid}#k_wallet`, x25519PrivateKey: new Uint8Array(32).fill(7) },
      reader: { async currentFor() { return null }, async forOwnKid() { return null } },
      sink: { async store() { throw new Error('must not store an unauthenticated ACCEPT') } },
      initiate: async did => {
        initiated = true
        return { ok: true, pending: { counterpartyDid: did, peer: pendingPeer, mediatorUrl } }
      },
      startWatch() {},
    })
    void manager.ensureContact(counterpartyDid).catch(() => {})
    await waitFor(() => initiated)

    await expect(manager.handleMessage({
      ackId: 'accept-wrong-sender', rawJwe: {} as never, senderKid: differentPeer.xKid,
      plaintext: {
        type: 'https://biset.md/relationship/1.0/accept',
        body: relationshipBodyToWire({ relationshipKid: claimedPeer.xKid, publicKey: claimedPeer.xPub }),
      },
    }, pendingPeer.xKid, mediatorUrl)).rejects.toThrow('relationship accept sender does not match its relationship kid')
  })
})

async function waitFor(ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 1_000
  while (!ready()) {
    if (Date.now() >= deadline) throw new Error('condition did not become ready')
    await new Promise(resolve => setTimeout(resolve, 1))
  }
}
