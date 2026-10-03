// DIDComm v2.1 DID Rotation for pairwise relationships: one side moves to a
// new did:peer (after removing a device), proves it with `from_prior`, and
// the other side follows -- end to end through a real mediator.
import { afterEach, describe, expect, test } from 'bun:test'
import { decodePeerDid2, deriveRelationshipPeerIdentity, generatePeerIdentity, publicKeyOf } from '../src/protocol/didcomm/peer.ts'
import { signFromPrior, verifyFromPrior } from '../src/protocol/didcomm/from-prior.ts'
import { mediatorInbox } from '../src/protocol/didcomm/mediator-device.ts'
import { pickupDeliver, acknowledgeMessages } from '../src/protocol/didcomm/mediator-pickup.ts'
import { registerWithMediator } from '../src/client/didcomm/mediator-sync.ts'
import { sendRelationshipMessage } from '../src/client/didcomm/send-message.ts'
import { acceptCounterpartyRotation, rotateOwnRelationships } from '../src/client/identity/wallet/relationship-rotation.ts'
import { contactKeyRef, type ContactKeyV1 } from '../src/client/store/vault/contact-key.ts'
import { selectUnsuperseded } from '../src/client/store/vault/credential-store.ts'
import { freshMediator, MEDIATOR_URL } from './support/mediator.ts'

describe('from_prior', () => {
  const prior = generatePeerIdentity()
  const next = generatePeerIdentity()
  const jwt = signFromPrior({ did: prior.did, edKid: prior.edKid, edPrivateKey: prior.edPriv }, next.did, 1_790_000_000)

  test('verifies against the prior did:peer and the carrying message\'s sender', () => {
    expect(verifyFromPrior(jwt, next.did)).toEqual({ iss: prior.did, sub: next.did, iat: 1_790_000_000 })
  })

  test('refuses a different sender, a forged signature, and a key the prior DID does not own', () => {
    expect(() => verifyFromPrior(jwt, generatePeerIdentity().did)).toThrow('different DID')
    const [h, p, sig] = jwt.split('.')
    expect(() => verifyFromPrior(`${h}.${p}.${sig!.slice(0, -4)}AAAA`, next.did)).toThrow()
    const stranger = generatePeerIdentity()
    expect(() => signFromPrior({ did: prior.did, edKid: stranger.edKid, edPrivateKey: stranger.edPriv }, next.did)).toThrow('belong to the prior DID')
    const forged = signFromPrior({ did: stranger.did, edKid: stranger.edKid, edPrivateKey: stranger.edPriv }, next.did)
    expect(verifyFromPrior(forged, next.did).iss).toBe(stranger.did)
  })
})

/** An in-memory ContactKey store with the reader's selection rules. */
function contactStore() {
  const records: ContactKeyV1[] = []
  const newest = (values: ContactKeyV1[]) => [...values].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))[0] ?? null
  return {
    records,
    async store(contact: ContactKeyV1) { records.push(contact) },
    async readAll() { return [...records] },
    async currentFor(counterpartyDid: string) {
      const values = records.filter(value => value.counterpartyDid === counterpartyDid)
      return values.length ? selectUnsuperseded(values, { kidOf: contactKeyRef, supersededKidOf: value => value.supersedes ? contactKeyRef(value.supersedes) : undefined, duplicateMessage: 'dup', ambiguousMessage: 'ambiguous' }) : null
    },
    async forCounterpartyKid(kid: string) { return newest(records.filter(value => value.counterpartyRelationshipKid === kid)) },
    async forOwnKid(kid: string) { return newest(records.filter(value => value.ownRelationshipKid === kid)) },
  }
}

const realFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = realFetch })

describe('relationship rotation through a mediator', () => {
  test('Bob rotates; Alice follows from from_prior; both directions then use Bob\'s new DID', async () => {
    const { mediator, handle } = freshMediator()
    globalThis.fetch = (async (input, init) => {
      const url = new URL(String(input))
      return (await handle(new Request(url, init), url)) ?? new Response('not found', { status: 404 })
    }) as typeof fetch
    const info = { url: MEDIATOR_URL, did: mediator.did, xKid: mediator.xKid, xPub: mediator.xPub }
    const service = { uri: MEDIATOR_URL, accept: ['didcomm/v2'], routingKeys: [mediator.xKid] }
    const aliceDid = 'did:webvh:alice:alice.example'
    const bobDid = 'did:webvh:bob:bob.example'
    const aliceDevice = crypto.getRandomValues(new Uint8Array(32))
    const bobDevice = crypto.getRandomValues(new Uint8Array(32))

    // An established relationship: Bob's side derived from his first seed.
    const seed0 = crypto.getRandomValues(new Uint8Array(32))
    const bobPeer = deriveRelationshipPeerIdentity(seed0, aliceDid, mediator.xKid)
    const alicePeer = generatePeerIdentity(service)
    const bob = contactStore()
    const alice = contactStore()
    await bob.store({ version: 1, kind: 'contact-key', identityId: bobDid, counterpartyDid: aliceDid, ownRelationshipKid: bobPeer.xKid, ownX25519PrivateKey: bobPeer.xPriv, ownEd25519PrivateKey: bobPeer.edPriv, counterpartyRelationshipKid: alicePeer.xKid, counterpartyPublicKey: alicePeer.xPub, createdAt: '2026-10-01T00:00:00.000Z' })
    await alice.store({ version: 1, kind: 'contact-key', identityId: aliceDid, counterpartyDid: bobDid, ownRelationshipKid: alicePeer.xKid, ownX25519PrivateKey: alicePeer.xPriv, ownEd25519PrivateKey: alicePeer.edPriv, counterpartyRelationshipKid: bobPeer.xKid, counterpartyPublicKey: bobPeer.xPub, createdAt: '2026-10-01T00:00:00.000Z' })
    const aliceInbox = mediatorInbox({ did: alicePeer.did, xKid: alicePeer.xKid, xPriv: alicePeer.xPriv }, aliceDevice)
    await registerWithMediator(MEDIATOR_URL, aliceInbox)

    // Bob removed a device: a new seed, every relationship moves.
    const seed1 = crypto.getRandomValues(new Uint8Array(32))
    const watched: string[] = []
    const rotate = () => rotateOwnRelationships({ identityId: bobDid, seed: seed1, mediatorDeviceSecret: bobDevice, reader: bob, sink: bob, startWatch: kid => { watched.push(kid) } })
    expect(await rotate()).toEqual({ rotated: [aliceDid], unchanged: [], failed: [] })
    const bobNow = (await bob.currentFor(aliceDid))!
    expect(bobNow.ownRelationshipKid).toBe(deriveRelationshipPeerIdentity(seed1, aliceDid, mediator.xKid).xKid)
    expect(bobNow.supersedes).toEqual({ ownRelationshipKid: bobPeer.xKid, counterpartyRelationshipKid: alicePeer.xKid })
    expect(watched).toEqual([bobNow.ownRelationshipKid])
    // Idempotent: a rerun (crash before the removal marker cleared) is a no-op.
    expect(await rotate()).toEqual({ rotated: [], unchanged: [aliceDid], failed: [] })

    // Alice receives the notice from an unknown DID; from_prior links it.
    const peerKey = async (kid: string) => publicKeyOf(decodePeerDid2(kid.split('#', 1)[0]!), kid)
    const [notice] = await pickupDeliver(info, aliceInbox, peerKey)
    expect(notice!.senderKid).toBe(bobNow.ownRelationshipKid)
    expect((notice!.plaintext as { from_prior?: string }).from_prior).toBe(bobNow.fromPrior)
    expect(await acceptCounterpartyRotation({ message: notice!, reader: alice, sink: alice })).toBe(true)
    expect(await acceptCounterpartyRotation({ message: notice!, reader: alice, sink: alice })).toBe(false)
    await acknowledgeMessages(info, aliceInbox, [notice!.ackId])
    const aliceNow = (await alice.currentFor(bobDid))!
    expect(aliceNow.counterpartyRelationshipKid).toBe(bobNow.ownRelationshipKid)

    // Alice -> Bob now reaches Bob's NEW inbox; Bob -> Alice keeps carrying from_prior.
    expect((await sendRelationshipMessage(aliceNow, 'to your new DID')).ok).toBe(true)
    const bobNewInbox = mediatorInbox({ did: bobNow.ownRelationshipKid.split('#', 1)[0]!, xKid: bobNow.ownRelationshipKid, xPriv: bobNow.ownX25519PrivateKey }, bobDevice)
    const [toBob] = await pickupDeliver(info, bobNewInbox, peerKey)
    expect((toBob!.plaintext as { body: { content: string } }).body.content).toBe('to your new DID')
    expect((await sendRelationshipMessage(bobNow, 'from my new DID')).ok).toBe(true)
    const [toAlice] = await pickupDeliver(info, aliceInbox, peerKey)
    expect((toAlice!.plaintext as { from_prior?: string }).from_prior).toBe(bobNow.fromPrior)
    expect(await acceptCounterpartyRotation({ message: toAlice!, reader: alice, sink: alice })).toBe(false)
  })
})
