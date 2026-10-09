// DID Rotation between biset identities (PLAN-refactor.md §4.3, §12.5): the
// route each message takes, what ingress learns from `from_prior`, and the
// device-side manager that asks, starts and confirms a move.
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { equalBytes, sha256Bytes } from '../../src/protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'
import { packAuthcrypt } from '../../src/protocol/didcomm/crypto.ts'
import { buildPlaintext, type DidCommPlaintext } from '../../src/protocol/didcomm/message.ts'
import { createFromPrior, fromPriorKeyResolver, verifyFromPrior } from '../../src/protocol/didcomm/from-prior.ts'
import { PING, PING_RESPONSE } from '../../src/protocol/didcomm/trust-ping.ts'
import { DISCOVER_FEATURES_DISCLOSE, DISCOVER_FEATURES_QUERIES } from '../../src/protocol/didcomm/mediator-protocol.ts'
import { decodePeerDid2, publicKeyOf } from '../../src/protocol/didcomm/peer.ts'
import type { LogEntry } from '../../src/protocol/webvh/log.ts'
import { BASIC_MESSAGE, didCommThreadId } from '../../src/client/didcomm/basicmessage.ts'
import { DidCommIngressProjector } from '../../src/client/didcomm/ingress-projector.ts'
import { PermanentDeliveryError } from '../../src/protocol/didcomm/mediator-pickup.ts'
import { audienceOfCopy, chooseRoute, ownRotationIdentity } from '../../src/client/didcomm/did-rotation.ts'
import { createRotationManager, RETIRED_Y_WATCH_MS } from '../../src/client/didcomm/rotation-manager.ts'
import { rotationSigningKey, ROTATION_KEY_FRAGMENT } from '../../src/client/didcomm/rotation-key.ts'
import {
  applyContactSet, didContactPatch, ownRotationPatch, rotationPatch, DIDCOMM_CONTACT_PROPERTY, type ContactSetPayload, type LocalJmapContactCard,
} from '../../src/client/store/projection/contacts.ts'
import { createSegmentKey, decryptVaultObject } from '../../src/client/store/vault/objects.ts'
import type { VaultEventAuthor } from '../../src/client/store/vault/events.ts'
import { buildDidCommLog } from './support/webvh-log-fixture.ts'
import { freshMediatorFetch } from '../support/mediator.ts'
import { mediatorInbox } from '../../src/protocol/didcomm/mediator-device.ts'
import { registerWithMediator } from '../../src/client/didcomm/mediator-sync.ts'
import { pickupDeliver } from '../../src/protocol/didcomm/mediator-pickup.ts'
import { sendFrontDoorMessage } from '../../src/client/didcomm/front-door-send.ts'

const MEDIATOR = 'did:web:mediator.example'

/** A biset identity: a did:webvh with one front-door device key and the
 * rotation key of its seed published under authentication. */
function identity(domain: string) {
  const root = ed25519.keygen()
  const device = x25519.keygen()
  const seed = crypto.getRandomValues(new Uint8Array(32))
  const { did, log } = buildDidCommLog({
    rootPrivateKey: root.secretKey, rootPublicKey: root.publicKey, domain,
    keyAgreementKeys: [{ fragment: 'k_a', x25519PublicKey: device.publicKey }],
    rawVerificationMethods: [{ fragment: ROTATION_KEY_FRAGMENT.slice(1), publicKeyMultibase: rotationSigningKey(seed).publicKeyMultibase }],
    authenticationFragments: [ROTATION_KEY_FRAGMENT.slice(1)],
  })
  return { did, log, seed, kid: `${did}#k_a`, x: device }
}
const alice = identity('alice.example')
const bob = identity('bob.example')
const logs = new Map<string, LogEntry[]>([[alice.did, alice.log], [bob.did, bob.log]])
const serving = (async (url: string) => {
  const entry = [...logs.entries()].find(([did]) => url.includes(did.split(':').at(-1)!))
  return entry ? new Response(entry[1].map(value => JSON.stringify(value)).join('\n') + '\n') : new Response('', { status: 404 })
}) as unknown as typeof fetch
const verify = (jwt: string, from: string) => verifyFromPrior(jwt, from, fromPriorKeyResolver(serving))

/** Bob's did:peer for Alice, and Alice's for Bob. */
const bobY = ownRotationIdentity(bob.seed, alice.did, MEDIATOR)
const aliceY = ownRotationIdentity(alice.seed, bob.did, MEDIATOR)

function cards(...writes: ContactSetPayload[]): LocalJmapContactCard[] {
  const byId = new Map<string, LocalJmapContactCard>()
  for (const write of writes) {
    const card = applyContactSet(byId.get(write.cardId), write)
    if (card) byId.set(card.id, card); else byId.delete(write.cardId)
  }
  return [...byId.values()]
}
const bobCard = didContactPatch(bob.did)
const aliceCard = didContactPatch(alice.did)

describe('the route of a message', () => {
  const context = (contactCards: LocalJmapContactCard[], seed = alice.seed) => ({
    identityDid: alice.did, frontDoor: { fromKid: alice.kid, x25519PrivateKey: alice.x.secretKey }, cards: contactCards, rotation: { seed, mediatorDid: MEDIATOR },
  })

  test('without a move, from the front door to the public DID', () => {
    expect(chooseRoute(bob.did, context([]))).toEqual({ toDid: bob.did, fromKid: alice.kid, x25519PrivateKey: alice.x.secretKey })
  })

  test('to the counterparty\'s newest DID once it moved', () => {
    const contactCards = cards(bobCard, rotationPatch(bobCard.cardId, { did: 'did:peer:2.old', prior: bob.did, iat: 1 }), rotationPatch(bobCard.cardId, { did: bobY.did, prior: bob.did, iat: 2 }))
    expect(chooseRoute(bob.did, context(contactCards)).toDid).toBe(bobY.did)
  })

  test('from this identity\'s Y once started, with a from_prior that verifies until the move is confirmed', async () => {
    const started = cards(bobCard, ownRotationPatch(bobCard.cardId, aliceY.did, 'startedAt', '2026-10-08T00:00:00Z'))
    const route = chooseRoute(bob.did, context(started))
    expect(route).toMatchObject({ fromKid: aliceY.xKid, toDid: bob.did })
    expect(await verify(route.fromPrior!, aliceY.did)).toMatchObject({ prior: alice.did, current: aliceY.did })
    const confirmed = cards(bobCard, ownRotationPatch(bobCard.cardId, aliceY.did, 'startedAt', '2026-10-08T00:00:00Z'), ownRotationPatch(bobCard.cardId, aliceY.did, 'confirmedAt', '2026-10-08T00:01:00Z'))
    expect(chooseRoute(bob.did, context(confirmed)).fromPrior).toBeUndefined()
  })

  test('a Y started under an older seed is not used: the front door instead', () => {
    const started = cards(bobCard, ownRotationPatch(bobCard.cardId, aliceY.did, 'startedAt', '2026-10-08T00:00:00Z'))
    expect(chooseRoute(bob.did, context(started, crypto.getRandomValues(new Uint8Array(32)))).fromKid).toBe(alice.kid)
  })
})

describe('a group message to a participant that moved (Message Layer Addressing Consistency)', () => {
  const carol = 'did:webvh:QmCarol:carol.example'
  test('the copy to the moved participant names it by the DID it is encrypted to; the others stay named by their public DIDs', () => {
    expect(audienceOfCopy([bob.did, carol], bob.did, bobY.did)).toEqual([bobY.did, carol])
    expect(audienceOfCopy([bob.did, carol], carol, carol)).toEqual([bob.did, carol])
  })
})

describe('ingress of a moved counterparty', () => {
  const signer: VaultEventAuthor = {
    deviceId: 'device-a',
    async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
    async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
  }
  const segmentKey = createSegmentKey()
  const keys = new Map<string, Uint8Array>([[alice.kid, alice.x.secretKey], [aliceY.xKid, aliceY.xPriv]])

  function projector(contactCards: LocalJmapContactCard[]) {
    let seq = 0
    return new DidCommIngressProjector({
      identityId: alice.did, actorDeviceId: 'device-a',
      resolveOwnKey: kid => keys.has(kid) ? { kid, x25519PrivateKey: keys.get(kid)! } : null,
      async resolveSenderKey(kid) {
        if (kid.startsWith('did:peer:2.')) return publicKeyOf(decodePeerDid2(kid.split('#')[0]!), kid)
        if (kid === bob.kid) return bob.x.publicKey
        throw new Error(`unknown ${kid}`)
      },
      async alreadyProcessed() { return false },
      async nextActorSeq() { return ++seq },
      async initialParents() { return [] },
      async activeSegment() { return { segmentId: 'segment-1', segmentKey } },
      async currentSnapshot() { return { state: 's', mailboxes: [], emails: [], contactCards } },
      signer,
      verifyFromPrior: verify,
      now: () => new Date('2026-10-08T00:05:00.000Z'),
    })
  }
  function envelope(plaintext: DidCommPlaintext, from: { kid: string; key: Uint8Array }, to: { kid: string; publicKey: Uint8Array }): IngressEnvelopeV1 {
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: from.kid, privateKey: from.key }, [to])
    const payload = new TextEncoder().encode(JSON.stringify(jwe))
    return {
      version: 1, ingressId: crypto.randomUUID(), protocol: 'didcomm', recipientIdentityId: alice.did, recipientDeviceSnapshot: [], createdAt: '2026-10-08T00:00:00Z', expiresAt: '2026-10-09T00:00:00Z',
      transportMetadata: {}, sourceEvidence: new Uint8Array([1]), protectedPayload: payload, protectedPayloadHash: sha256Bytes(payload),
    }
  }
  const toAliceFrontDoor = { kid: alice.kid, publicKey: alice.x.publicKey }
  const fromBobY = { kid: bobY.xKid, key: bobY.xPriv }
  const signedRotation = (iat = 100) => createFromPrior({ iss: bob.did, sub: bobY.did, iat }, `${bob.did}${ROTATION_KEY_FRAGMENT}`, rotationSigningKey(bob.seed).privateKey)

  test('a message from Bob\'s did:peer with a verified from_prior is Bob\'s, and Alice\'s card for Bob learns the move', async () => {
    const message = buildPlaintext(BASIC_MESSAGE, { content: 'hi from my private DID' }, bobY.did, alice.did, { fromPrior: signedRotation() })
    const result = await projector([]).verifyAndProject(envelope(message, fromBobY, toAliceFrontDoor))
    expect(result.projection.emails).toMatchObject([{ from: [{ email: bob.did }], threadId: didCommThreadId(alice.did, bob.did) }])
    expect(result.projection.contactCards[0]![DIDCOMM_CONTACT_PROPERTY]).toEqual({ rotations: { [bobY.did]: { prior: bob.did, iat: 100 } } })
  })

  test('a from_prior that does not verify is refused for good', async () => {
    const forged = createFromPrior({ iss: bob.did, sub: bobY.did, iat: 100 }, `${bob.did}${ROTATION_KEY_FRAGMENT}`, ed25519.keygen().secretKey)
    const message = buildPlaintext(BASIC_MESSAGE, { content: 'trust me' }, bobY.did, alice.did, { fromPrior: forged })
    await expect(projector([]).verifyAndProject(envelope(message, fromBobY, toAliceFrontDoor))).rejects.toBeInstanceOf(PermanentDeliveryError)
  })

  test('without from_prior, the card names the sender -- two devices holding it record the same message identically', async () => {
    const known = cards(bobCard, rotationPatch(bobCard.cardId, { did: bobY.did, prior: bob.did, iat: 100 }))
    const message = buildPlaintext(BASIC_MESSAGE, { content: 'second message' }, bobY.did, alice.did)
    const one = await projector(known).verifyAndProject(envelope(message, fromBobY, toAliceFrontDoor))
    const two = await projector(known).verifyAndProject(envelope(message, fromBobY, toAliceFrontDoor))
    expect(one.projection.emails).toMatchObject([{ from: [{ email: bob.did }] }])
    expect(two.projection.emails.map(email => [email.id, email.threadId, email.from])).toEqual(one.projection.emails.map(email => [email.id, email.threadId, email.from]))
  })

  test('a group copy naming Alice by her Y is hers, recorded with her public DID -- the same on every device', async () => {
    const carol = 'did:webvh:QmCarol:carol.example'
    const known = cards(bobCard, rotationPatch(bobCard.cardId, { did: bobY.did, prior: bob.did, iat: 100 }))
    const message = buildPlaintext(BASIC_MESSAGE, { content: 'hello group' }, bob.did, [aliceY.did, carol], { thid: 'group-9' })
    const toAliceY = { kid: aliceY.xKid, publicKey: aliceY.xPub }
    const one = await projector(known).verifyAndProject(envelope(message, { kid: bob.kid, key: bob.x.secretKey }, toAliceY))
    const two = await projector(known).verifyAndProject(envelope(message, { kid: bob.kid, key: bob.x.secretKey }, toAliceY))
    expect(one.projection.emails[0]!.to).toEqual([{ email: alice.did }, { email: carol }])
    expect(two.projection.emails[0]!.to).toEqual(one.projection.emails[0]!.to)
    // Someone else's did:peer in `to` does not make the message Alice's.
    const notMine = buildPlaintext(BASIC_MESSAGE, { content: 'not for you' }, bob.did, ['did:peer:2.someone-else', carol], { thid: 'group-9' })
    await expect(projector(known).verifyAndProject(envelope(notMine, { kid: bob.kid, key: bob.x.secretKey }, toAliceY))).rejects.toThrow('does not name this identity')
  })

  test('a DID Bob has since moved away from is refused for good', async () => {
    const moved = cards(bobCard, rotationPatch(bobCard.cardId, { did: bobY.did, prior: bob.did, iat: 100 }), rotationPatch(bobCard.cardId, { did: 'did:peer:2.newer', prior: bob.did, iat: 200 }))
    const message = buildPlaintext(BASIC_MESSAGE, { content: 'from the old DID' }, bobY.did, alice.did)
    await expect(projector(moved).verifyAndProject(envelope(message, fromBobY, toAliceFrontDoor))).rejects.toBeInstanceOf(PermanentDeliveryError)
  })

  test('Bob writing to Alice\'s Y confirms Alice\'s move (and a ping-response is enough)', async () => {
    const started = cards(bobCard, ownRotationPatch(bobCard.cardId, aliceY.did, 'startedAt', '2026-10-08T00:00:00Z'))
    const answer = buildPlaintext(PING_RESPONSE, {}, bob.did, aliceY.did, { thid: 'ping-1' })
    const result = await projector(started).verifyAndProject(envelope(answer, { kid: bob.kid, key: bob.x.secretKey }, { kid: aliceY.xKid, publicKey: aliceY.xPub }))
    expect(result.events.map(event => event.kind)).toEqual(['didcomm.control', 'contact.set'])
    const own = (result.projection.contactCards[0]![DIDCOMM_CONTACT_PROPERTY] as { own: Record<string, object> }).own
    expect(own[aliceY.did]).toEqual({ startedAt: '2026-10-08T00:00:00Z', confirmedAt: '2026-10-08T00:05:00.000Z' })
    const written = JSON.parse(new TextDecoder().decode(await decryptVaultObject(segmentKey, result.objects.at(-1)!)))
    expect(written.kind).toBe('contact.set')
  })
})

describe('the rotation manager', () => {
  function manager(initial: LocalJmapContactCard[] = [], extra: { storedSeeds?: Uint8Array[]; now?: Date } = {}) {
    let contactCards = initial
    const sent: Array<{ toDid: string; type: string; body: unknown; options: { fromKid: string; fromPrior?: string; thid?: string } }> = []
    const watched: string[] = []
    const value = createRotationManager({
      identityDid: alice.did,
      frontDoor: { fromKid: alice.kid, x25519PrivateKey: alice.x.secretKey },
      async cards() { return contactCards },
      async rotation() { return { seed: alice.seed, mediatorDid: MEDIATOR } },
      async commit(writes) { contactCards = cards(...[...contactCards.map(card => ({ cardId: card.id, patch: Object.fromEntries(Object.entries(card).filter(([key]) => key !== 'id')) }) as ContactSetPayload), ...writes]) },
      async send(toDid, type, body, options) { sent.push({ toDid, type, body, options }); return { ok: true } },
      async watch(peer) { watched.push(peer.did) },
      ...(extra.storedSeeds ? { storedSeeds: async () => extra.storedSeeds! } : {}),
      now: () => extra.now ?? new Date('2026-10-08T00:00:00Z'),
    })
    return { value, sent, watched, cards: () => contactCards }
  }

  test('answers a Discover Features query for from_prior, from the key it reached', async () => {
    const { value, sent } = manager()
    const query = buildPlaintext(DISCOVER_FEATURES_QUERIES, { queries: [{ 'feature-type': 'header', match: 'from_prior' }, { 'feature-type': 'protocol', match: 'https://didcomm.org/basicmessage/*' }] }, bob.did, alice.did)
    expect(await value.handleDiscoverFeatures(query, bob.kid, alice.kid)).toBe(true)
    expect(sent).toEqual([{ toDid: bob.did, type: DISCOVER_FEATURES_DISCLOSE, body: { disclosures: [{ 'feature-type': 'protocol', id: 'https://didcomm.org/basicmessage/2.0' }, { 'feature-type': 'header', id: 'from_prior' }] }, options: expect.objectContaining({ fromKid: alice.kid, thid: query.id }) }])
  })

  test('ignores a Discover Features message whose sender is not authenticated (anoncrypt)', async () => {
    const { value, sent, watched } = manager()
    const query = buildPlaintext(DISCOVER_FEATURES_QUERIES, { queries: [{ 'feature-type': 'header', match: 'from_prior' }] }, bob.did, alice.did)
    expect(await value.handleDiscoverFeatures(query, 'anoncrypt', alice.kid)).toBe(true)
    const disclose = buildPlaintext(DISCOVER_FEATURES_DISCLOSE, { disclosures: [{ 'feature-type': 'header', id: 'from_prior' }] }, bob.did, alice.did)
    expect(await value.handleDiscoverFeatures(disclose, 'anoncrypt', alice.kid)).toBe(true)
    expect(sent).toEqual([])
    expect(watched).toEqual([])
  })

  test('asks once per counterparty, and a disclosure of from_prior starts the move: inbox first, then the card, then a ping from Y', async () => {
    const { value, sent, watched, cards: current } = manager()
    await value.offer(bob.did)
    await value.offer(bob.did)
    expect(sent.map(message => message.type)).toEqual([DISCOVER_FEATURES_QUERIES])
    const disclose = buildPlaintext(DISCOVER_FEATURES_DISCLOSE, { disclosures: [{ 'feature-type': 'header', id: 'from_prior' }] }, bob.did, alice.did)
    await value.handleDiscoverFeatures(disclose, bob.kid, alice.kid)
    expect(watched).toEqual([aliceY.did])
    expect(current()[0]![DIDCOMM_CONTACT_PROPERTY]).toEqual({ own: { [aliceY.did]: { startedAt: '2026-10-08T00:00:00.000Z' } } })
    const ping = sent.at(-1)!
    expect(ping).toMatchObject({ toDid: bob.did, type: PING, options: { fromKid: aliceY.xKid } })
    expect(await verify(ping.options.fromPrior!, aliceY.did)).toMatchObject({ prior: alice.did })
    expect(value.ownKey(aliceY.xKid)?.x25519PrivateKey).toEqual(aliceY.xPriv)
    // Started already: nothing more is announced (no ping ping-pong).
    await value.start(bob.did)
    expect(sent.filter(message => message.type === PING)).toHaveLength(1)
  })

  test('a sibling\'s started move is picked up on sync: its inbox watched, its key known', async () => {
    const { value, watched } = manager(cards(aliceCard, bobCard, ownRotationPatch(bobCard.cardId, aliceY.did, 'startedAt', '2026-10-08T00:00:00Z')))
    await value.sync(); await value.sync()
    expect(watched).toEqual([aliceY.did])
    expect(value.ownKey(aliceY.xKid)).not.toBeNull()
    expect(await value.counterpartyOf(bob.kid)).toBe(bob.did)
  })
})

describe('after a device removal replaced the seed (§4.5)', () => {
  const oldSeed = crypto.getRandomValues(new Uint8Array(32))
  const oldY = ownRotationIdentity(oldSeed, bob.did, MEDIATOR)

  function manager(contactCards: LocalJmapContactCard[], now = new Date('2026-10-08T00:00:00Z')) {
    let current = contactCards
    const sent: Array<{ toDid: string; type: string; options: { fromKid: string; fromPrior?: string } }> = []
    const watched: string[] = []
    const value = createRotationManager({
      identityDid: alice.did,
      frontDoor: { fromKid: alice.kid, x25519PrivateKey: alice.x.secretKey },
      async cards() { return current },
      async rotation() { return { seed: alice.seed, mediatorDid: MEDIATOR } },
      async storedSeeds() { return [oldSeed, alice.seed] },
      async commit(writes) { current = cards(...current.map(card => ({ cardId: card.id, patch: Object.fromEntries(Object.entries(card).filter(([key]) => key !== 'id')) }) as ContactSetPayload), ...writes) },
      async send(toDid, type, _body, options) { sent.push({ toDid, type, options }); return { ok: true } },
      async watch(peer) { watched.push(peer.did) },
      now: () => now,
    })
    return { value, sent, watched, cards: () => current }
  }
  const movedWithOldSeed = () => cards(bobCard,
    ownRotationPatch(bobCard.cardId, oldY.did, 'startedAt', '2026-09-01T00:00:00Z'), ownRotationPatch(bobCard.cardId, oldY.did, 'confirmedAt', '2026-09-01T00:01:00Z'))

  test('a Y the current seed does not derive is moved from again: to the new Y, with a from_prior from the public DID; the old Y is still read', async () => {
    const { value, sent, watched, cards: current } = manager(movedWithOldSeed())
    await value.sync()
    await until(() => sent.length > 0)
    expect(watched).toContain(aliceY.did)
    expect(watched).toContain(oldY.did)
    expect(value.ownKey(oldY.xKid)?.x25519PrivateKey).toEqual(oldY.xPriv)
    expect(sent).toMatchObject([{ toDid: bob.did, type: PING, options: { fromKid: aliceY.xKid } }])
    expect(await verify(sent[0]!.options.fromPrior!, aliceY.did)).toMatchObject({ prior: alice.did, current: aliceY.did })
    expect((current()[0]![DIDCOMM_CONTACT_PROPERTY] as { own: Record<string, object> }).own[aliceY.did]).toEqual({ startedAt: '2026-10-08T00:00:00.000Z' })
    // Once is enough: a later sync does not move again.
    await value.sync()
    expect(sent).toHaveLength(1)
  })

  test('the old Y is read for 30 days after the move from it started, not longer', async () => {
    const later = cards(bobCard,
      ownRotationPatch(bobCard.cardId, oldY.did, 'startedAt', '2026-09-01T00:00:00Z'),
      ownRotationPatch(bobCard.cardId, aliceY.did, 'startedAt', '2026-09-02T00:00:00Z'))
    const within = manager(later, new Date('2026-09-20T00:00:00Z'))
    await within.value.sync()
    expect(within.watched.sort()).toEqual([aliceY.did, oldY.did].sort())
    const after = manager(later, new Date(Date.parse('2026-09-02T00:00:00Z') + RETIRED_Y_WATCH_MS))
    await after.value.sync()
    expect(after.watched).toEqual([aliceY.did])
    expect(after.value.ownKey(oldY.xKid)).toBeNull()
  })

  test('the counterparty refuses a move signed with a key the document no longer publishes (what a removed device holds)', async () => {
    const removed = createFromPrior({ iss: alice.did, sub: oldY.did, iat: 300 }, `${alice.did}${ROTATION_KEY_FRAGMENT}`, rotationSigningKey(oldSeed).privateKey)
    await expect(verify(removed, oldY.did)).rejects.toThrow('signature does not verify')
  })
})

describe('through a real mediator', () => {
  test('a message to Alice\'s Y -- a did:peer whose service names the mediator by its did:web -- reaches Y\'s registered inbox', async () => {
    const { mediatorIdentity, fetchImpl, url } = freshMediatorFetch()
    const y = ownRotationIdentity(alice.seed, bob.did, mediatorIdentity.did)
    expect(decodePeerDid2(y.did).service[0]!.serviceEndpoint.uri).toBe(mediatorIdentity.did)
    const inbox = mediatorInbox({ did: y.did, xKid: y.xKid, xPriv: y.xPriv }, new Uint8Array(32).fill(7))
    const info = await registerWithMediator(url, inbox, fetchImpl)

    const sent = await sendFrontDoorMessage(y.did, BASIC_MESSAGE, { content: 'to your private DID' }, { fromKid: bob.kid, x25519PrivateKey: bob.x.secretKey, fetch: fetchImpl })
    expect(sent).toEqual({ ok: true })
    const delivered = await pickupDeliver(info, inbox, async kid => { if (kid !== bob.kid) throw new Error(kid); return bob.x.publicKey }, 10, fetchImpl)
    expect(delivered.map(message => (message.plaintext as DidCommPlaintext).body)).toEqual([{ content: 'to your private DID' }])
    expect((delivered[0]!.plaintext as DidCommPlaintext).to).toEqual([y.did])
  })
})

async function until(condition: () => boolean, deadlineMs = 2000): Promise<void> {
  const deadline = Date.now() + deadlineMs
  while (!condition() && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 5))
}
