// End-to-end coverage for the Mail Mediator dispatch (src/mail-mediator/
// server.ts): route-bind (front-door authenticated), pickup-request,
// messages-received, submit, submit-status-request -- all driven over the
// same createMailMediator({ ... }).handle(req, url) entrypoint a real HTTP
// server would call. Mirrors test/mediator-server.test.ts's request()
// helper shape.
import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../../src/didcomm/peer.ts'
import { createMailMediator } from '../../src/mail-mediator/server.ts'
import { SpoolStore } from '../../src/mail-mediator/spool-store.ts'
import { packAuthcrypt, unpackAuthcrypt, parseJwe } from '../../src/didcomm/crypto.ts'
import { buildPlaintext, type DidCommPlaintext } from '../../src/didcomm/message.ts'
import { routeBindBodyToWire, submitBodyToWire, type RecipientSubmitStatus } from '../../src/mail-mediator/protocol.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)
const fromUtf8 = (b: Uint8Array) => new TextDecoder().decode(b)

const ADDRESS = 'y@biset.md'

function freshMailMediator(overrides: Partial<Parameters<typeof createMailMediator>[0]> = {}) {
  const mediator = generatePeerIdentity({ uri: 'https://mail-mediator.test.example', accept: ['didcomm/v2'] })
  const frontDoor = generatePeerIdentity()
  const spool = overrides.spool ?? new SpoolStore()
  const { handle } = createMailMediator({
    mediator,
    spool,
    resolveMailOperationalKid: async kid => (kid === frontDoor.xKid ? { address: ADDRESS, publicKey: frontDoor.xPub } : null),
    submitOutbound: async () => [],
    ...overrides,
  })
  const post = (body: unknown) => handle(new Request('https://mail-mediator.test.example/', { method: 'POST', body: JSON.stringify(body) }), new URL('https://mail-mediator.test.example/'))
  return { mediator, frontDoor, spool, post, handle }
}

async function request(
  post: (body: unknown) => Promise<Response | null>,
  mediator: ReturnType<typeof generatePeerIdentity>,
  sender: ReturnType<typeof generatePeerIdentity>,
  type: string, body: unknown,
): Promise<{ plaintext: DidCommPlaintext; status: number }> {
  const plaintext = buildPlaintext(type, body, sender.did, mediator.did)
  const jwe = packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: sender.xKid, privateKey: sender.xPriv }, { kid: mediator.xKid, publicKey: mediator.xPub })
  const res = await post(jwe)
  expect(res).not.toBeNull()
  if (res!.status !== 200) return { plaintext: { id: '', typ: '', type: '', body: undefined }, status: res!.status }
  const replyJwe = parseJwe(await res!.json())
  expect(replyJwe).not.toBeNull()
  const { plaintext: replyBytes } = await unpackAuthcrypt(replyJwe!, { kid: sender.xKid, privateKey: sender.xPriv }, async () => mediator.xPub)
  return { plaintext: JSON.parse(fromUtf8(replyBytes)), status: res!.status }
}

describe('Mail Mediator (route-bind + pickup + ack + submit)', () => {
  test('route-bind from the front-door kid binds a relationship kid', async () => {
    const { mediator, frontDoor, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    const { plaintext } = await request(post, mediator, frontDoor, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z',
    }))
    expect(plaintext.type).toBe('https://biset.md/mail-mediator/1.0/route-bind-result')
    expect((plaintext.body as any).accepted).toBe(true)
    expect((plaintext.body as any).address).toBe(ADDRESS)
  })

  test('route-bind from a relationship kid (not front-door) is refused', async () => {
    const { mediator, frontDoor, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    await request(post, mediator, frontDoor, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z',
    }))
    const other = generatePeerIdentity()
    const { plaintext, status } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: other.xKid, pickupPublicKey: other.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z',
    }))
    expect(status).toBe(200)
    expect(plaintext.type).toBe('https://didcomm.org/report-problem/2.0/problem-report')
    expect((plaintext.body as any).code).toContain('front-door')
  })

  test('route-bind claiming an address the front-door kid does not own is refused', async () => {
    const { mediator, frontDoor, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    const { plaintext } = await request(post, mediator, frontDoor, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: 'someone-else@biset.md', relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z',
    }))
    expect((plaintext.body as any).code).toContain('front-door')
  })

  test('full round-trip: bind, pickup a spooled message, and ack it', async () => {
    const { mediator, frontDoor, spool, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    await request(post, mediator, frontDoor, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z',
    }))

    spool.enqueue({
      address: ADDRESS, semanticIngressId: 'sid-1', mailFrom: 'sender@example.com',
      encryptedBody: new Uint8Array([1, 2, 3]), bodyHash: new Uint8Array([9, 9]),
      createdAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-02-01T00:00:00.000Z',
    })

    const pickup = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/pickup-request', { address: ADDRESS, limit: 10 })
    expect(pickup.plaintext.type).toBe('https://biset.md/mail-mediator/1.0/pickup')
    const items = (pickup.plaintext.body as any).items
    expect(items).toHaveLength(1)
    expect(items[0].semanticIngressId).toBe('sid-1')

    const ack = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/messages-received', { address: ADDRESS, spoolIds: [items[0].spoolId] })
    expect((ack.plaintext.body as any).items).toHaveLength(0)

    const pickupAgain = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/pickup-request', { address: ADDRESS, limit: 10 })
    expect((pickupAgain.plaintext.body as any).items).toHaveLength(0)
  })

  test('pickup-request from an unbound kid cannot even be authenticated (401, unopened)', async () => {
    // A kid that was never bound (front-door or relationship) has no key
    // this mediator can resolve, so the request fails to decrypt at all --
    // there is no plaintext to read a "not-bound" problem-report out of.
    const { mediator, post } = freshMailMediator()
    const stranger = generatePeerIdentity()
    const { status } = await request(post, mediator, stranger, 'https://biset.md/mail-mediator/1.0/pickup-request', { address: ADDRESS })
    expect(status).toBe(401)
  })

  test('submit accepts immediately (in-flight) then submit-status-request reports the completed result', async () => {
    let resolveOutbound!: (results: { recipient: string; status: RecipientSubmitStatus }[]) => void
    const outboundDone = new Promise<{ recipient: string; status: RecipientSubmitStatus }[]>(resolve => { resolveOutbound = resolve })
    const { mediator, frontDoor, post } = freshMailMediator({
      submitOutbound: async () => outboundDone,
    })
    const relationship = generatePeerIdentity()
    await request(post, mediator, frontDoor, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z',
    }))

    const submit = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit', submitBodyToWire({
      idempotencyKey: 'idem-1', mailFrom: ADDRESS, rcptTo: ['a@example.com'], rawRfc5322: new Uint8Array([1, 2, 3]),
    }))
    expect((submit.plaintext.body as any).state).toBe('in-flight')

    const pendingStatus = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit-status-request', { idempotencyKey: 'idem-1' })
    expect((pendingStatus.plaintext.body as any).state).toBe('in-flight')

    resolveOutbound([{ recipient: 'a@example.com', status: 'accepted' }])
    await outboundDone

    // submitOutbound's .then() runs on a microtask after this await; give
    // it one more tick to land before asserting completion.
    await Promise.resolve()

    const completedStatus = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit-status-request', { idempotencyKey: 'idem-1' })
    expect((completedStatus.plaintext.body as any).state).toBe('completed')
    expect((completedStatus.plaintext.body as any).results).toEqual([{ recipient: 'a@example.com', status: 'accepted' }])
  })

  test('submit with a mailFrom that does not match the bound address is refused', async () => {
    const { mediator, frontDoor, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    await request(post, mediator, frontDoor, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z',
    }))
    const { plaintext } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit', submitBodyToWire({
      idempotencyKey: 'idem-1', mailFrom: 'someone-else@biset.md', rcptTo: ['a@example.com'], rawRfc5322: new Uint8Array([1]),
    }))
    expect((plaintext.body as any).code).toContain('from-mismatch')
  })

  test('submit-status-request for an unknown idempotency key is refused', async () => {
    const { mediator, frontDoor, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    await request(post, mediator, frontDoor, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z',
    }))
    const { plaintext } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit-status-request', { idempotencyKey: 'missing' })
    expect((plaintext.body as any).code).toContain('unknown-submission')
  })

  test('a rotated (new) route generation revokes the old relationship kid', async () => {
    const { mediator, frontDoor, post } = freshMailMediator()
    const oldRelationship = generatePeerIdentity()
    await request(post, mediator, frontDoor, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: oldRelationship.xKid, pickupPublicKey: oldRelationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z',
    }))
    const newRelationship = generatePeerIdentity()
    await request(post, mediator, frontDoor, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: newRelationship.xKid, pickupPublicKey: newRelationship.xPub,
      routeGeneration: 'gen-2', expiresAt: '2030-01-01T00:00:00.000Z',
    }))
    // The old relationship kid is no longer resolvable at all (route-store
    // dropped it, and it was never the front-door kid) -- same unopened
    // 401 as the "never bound" case, not a readable problem-report.
    const { status } = await request(post, mediator, oldRelationship, 'https://biset.md/mail-mediator/1.0/pickup-request', { address: ADDRESS })
    expect(status).toBe(401)
    const okPickup = await request(post, mediator, newRelationship, 'https://biset.md/mail-mediator/1.0/pickup-request', { address: ADDRESS })
    expect((okPickup.plaintext.body as any).items).toEqual([])
  })
})
