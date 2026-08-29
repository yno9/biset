// End-to-end coverage for the Mail Mediator dispatch (src/mail-mediator/
// server.ts): route-bind (VC-authorized, from the relationship identity
// itself), pickup-request, messages-received, submit, submit-status-request
// -- all driven over the same createMailMediator({ ... }).handle(req, url)
// entrypoint a real HTTP server would call. Mirrors
// test/mediator-server.test.ts's request() helper shape.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { generatePeerIdentity } from '../../src/didcomm/peer.ts'
import { createMailMediator } from '../../src/mail-mediator/server.ts'
import { SpoolStore } from '../../src/mail-mediator/spool-store.ts'
import { packAuthcrypt, unpackAuthcrypt, parseJwe } from '../../src/didcomm/crypto.ts'
import { buildPlaintext, type DidCommPlaintext } from '../../src/didcomm/message.ts'
import { routeBindBodyToWire, submitBodyToWire, type RecipientSubmitStatus } from '../../src/mail-mediator/protocol.ts'
import { issueBisetMailAddressCredential, verifyBisetMailAddressCredential } from '../../src/oid4vp/mail-address-profile.ts'
import { ContactHistoryStore } from '../../src/mail-mediator/contact-history-store.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)
const fromUtf8 = (b: Uint8Array) => new TextDecoder().decode(b)

const ADDRESS = 'y@biset.md'
const ANCHOR_ISSUER = 'https://anchor.test.example'
const ANCHOR_SIGNING_KEY_ID = `${ANCHOR_ISSUER}/oid4vp/jwks#mail-address-credential-eddsa-1`
const ANCHOR_SIGNING_PRIVATE_KEY = ed25519.utils.randomSecretKey()
const ANCHOR_SIGNING_PUBLIC_KEY = ed25519.getPublicKey(ANCHOR_SIGNING_PRIVATE_KEY)

function vcFor(relationshipDid: string, address = ADDRESS): string {
  const now = new Date()
  return issueBisetMailAddressCredential({
    issuer: ANCHOR_ISSUER, signingKeyId: ANCHOR_SIGNING_KEY_ID, signingPrivateKey: ANCHOR_SIGNING_PRIVATE_KEY,
    address, relationshipDid, validFrom: new Date(now.getTime() - 60_000), validUntil: new Date(now.getTime() + 3_600_000),
  })
}

function freshMailMediator(overrides: Partial<Parameters<typeof createMailMediator>[0]> = {}) {
  const mediator = generatePeerIdentity({ uri: 'https://mail-mediator.test.example', accept: ['didcomm/v2'] })
  const spool = overrides.spool ?? new SpoolStore()
  const { handle } = createMailMediator({
    mediator,
    spool,
    verifyMailAddressCredential: (token, now) => {
      const claims = verifyBisetMailAddressCredential(token, { issuer: ANCHOR_ISSUER, signingKeyId: ANCHOR_SIGNING_KEY_ID, signingPublicKey: ANCHOR_SIGNING_PUBLIC_KEY, now: new Date(now) })
      return { address: claims.credentialSubject.address, relationshipDid: claims.cnf.relationshipDid }
    },
    submitOutbound: async () => [],
    ...overrides,
  })
  const post = (body: unknown) => handle(new Request('https://mail-mediator.test.example/', { method: 'POST', body: JSON.stringify(body) }), new URL('https://mail-mediator.test.example/'))
  return { mediator, spool, post, handle }
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

async function bind(
  post: (body: unknown) => Promise<Response | null>, mediator: ReturnType<typeof generatePeerIdentity>,
  relationship: ReturnType<typeof generatePeerIdentity>, routeGeneration: string, address = ADDRESS, credentialFor = relationship,
) {
  return request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
    address, relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
    routeGeneration, expiresAt: '2030-01-01T00:00:00.000Z', mailAddressCredential: vcFor(credentialFor.did, address),
  }))
}

describe('Mail Mediator (route-bind + pickup + ack + submit)', () => {
  test('route-bind from the relationship identity itself, with a valid VC, binds it', async () => {
    const { mediator, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    const { plaintext } = await bind(post, mediator, relationship, 'gen-1')
    expect(plaintext.type).toBe('https://biset.md/mail-mediator/1.0/route-bind-result')
    expect((plaintext.body as any).accepted).toBe(true)
    expect((plaintext.body as any).address).toBe(ADDRESS)
  })

  test('route-bind with a VC issued for a DIFFERENT relationship identity is refused', async () => {
    const { mediator, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    const someoneElse = generatePeerIdentity()
    // The VC's cnf.relationshipDid names someoneElse, not the actual
    // authcrypt sender -- a forged claim, not merely unverified.
    const { plaintext } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z', mailAddressCredential: vcFor(someoneElse.did),
    }))
    expect(plaintext.type).toBe('https://didcomm.org/report-problem/2.0/problem-report')
    expect((plaintext.body as any).code).toContain('credential-mismatch')
  })

  test('route-bind whose VC names a different address than the request claims is refused', async () => {
    const { mediator, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    const { plaintext } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z', mailAddressCredential: vcFor(relationship.did, 'someone-else@biset.md'),
    }))
    expect((plaintext.body as any).code).toContain('credential-mismatch')
  })

  test('route-bind with a credential signed by an untrusted issuer is refused', async () => {
    const { mediator, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    const forgedIssuerKey = ed25519.utils.randomSecretKey()
    const now = new Date()
    const forgedVc = issueBisetMailAddressCredential({
      issuer: ANCHOR_ISSUER, signingKeyId: ANCHOR_SIGNING_KEY_ID, signingPrivateKey: forgedIssuerKey,
      address: ADDRESS, relationshipDid: relationship.did, validFrom: new Date(now.getTime() - 60_000), validUntil: new Date(now.getTime() + 3_600_000),
    })
    const { plaintext } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/route-bind', routeBindBodyToWire({
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z', mailAddressCredential: forgedVc,
    }))
    expect((plaintext.body as any).code).toContain('credential-invalid')
  })

  test('full round-trip: bind, pickup a spooled message, and ack it', async () => {
    const { mediator, spool, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    await bind(post, mediator, relationship, 'gen-1')

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

  test('pickup-request from an unbound (but self-certifying) kid is refused with a readable problem-report', async () => {
    // Unlike the old front-door design, a did:peer:2 kid is ALWAYS
    // self-certifying -- unpack never fails for an unknown sender, so
    // the mediator can and does answer with a readable not-bound
    // problem-report instead of an unopened 401.
    const { mediator, post } = freshMailMediator()
    const stranger = generatePeerIdentity()
    const { plaintext, status } = await request(post, mediator, stranger, 'https://biset.md/mail-mediator/1.0/pickup-request', { address: ADDRESS })
    expect(status).toBe(200)
    expect((plaintext.body as any).code).toContain('not-bound')
  })

  test('submit accepts immediately (in-flight) then submit-status-request reports the completed result', async () => {
    let resolveOutbound!: (results: { recipient: string; status: RecipientSubmitStatus }[]) => void
    const outboundDone = new Promise<{ recipient: string; status: RecipientSubmitStatus }[]>(resolve => { resolveOutbound = resolve })
    const { mediator, post } = freshMailMediator({
      submitOutbound: async () => outboundDone,
    })
    const relationship = generatePeerIdentity()
    await bind(post, mediator, relationship, 'gen-1')

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
    const { mediator, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    await bind(post, mediator, relationship, 'gen-1')
    const { plaintext } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit', submitBodyToWire({
      idempotencyKey: 'idem-1', mailFrom: 'someone-else@biset.md', rcptTo: ['a@example.com'], rawRfc5322: new Uint8Array([1]),
    }))
    expect((plaintext.body as any).code).toContain('from-mismatch')
  })

  test('submit-status-request for an unknown idempotency key is refused', async () => {
    const { mediator, post } = freshMailMediator()
    const relationship = generatePeerIdentity()
    await bind(post, mediator, relationship, 'gen-1')
    const { plaintext } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit-status-request', { idempotencyKey: 'missing' })
    expect((plaintext.body as any).code).toContain('unknown-submission')
  })

  test('a rotated (new) route generation revokes the old relationship kid', async () => {
    const { mediator, post } = freshMailMediator()
    const oldRelationship = generatePeerIdentity()
    await bind(post, mediator, oldRelationship, 'gen-1')
    const newRelationship = generatePeerIdentity()
    await bind(post, mediator, newRelationship, 'gen-2')
    // The old relationship kid is no longer bound to any address, but
    // it's still a valid did:peer:2, so this comes back as a readable
    // not-bound problem-report, not an unopened 401.
    const { plaintext, status } = await request(post, mediator, oldRelationship, 'https://biset.md/mail-mediator/1.0/pickup-request', { address: ADDRESS })
    expect(status).toBe(200)
    expect((plaintext.body as any).code).toContain('not-bound')
    const okPickup = await request(post, mediator, newRelationship, 'https://biset.md/mail-mediator/1.0/pickup-request', { address: ADDRESS })
    expect((okPickup.plaintext.body as any).items).toEqual([])
  })
})

describe('Mail Mediator outbound recipient allowlist', () => {
  test('with no allowlist configured, any recipient is accepted (unchanged default behavior)', async () => {
    const { mediator, post } = freshMailMediator({ submitOutbound: async record => record.rcptTo.map(recipient => ({ recipient, status: 'accepted' as const })) })
    const relationship = generatePeerIdentity()
    await bind(post, mediator, relationship, 'gen-1')
    const { plaintext } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit', submitBodyToWire({
      idempotencyKey: 'idem-1', mailFrom: ADDRESS, rcptTo: ['anyone@anywhere.example'], rawRfc5322: new Uint8Array([1]),
    }))
    expect((plaintext.body as any).state).toBe('in-flight')
  })

  test('a recipient under an allowed domain is accepted', async () => {
    const { mediator, post } = freshMailMediator({
      allowedRecipientDomains: ['biset.md'],
      submitOutbound: async record => record.rcptTo.map(recipient => ({ recipient, status: 'accepted' as const })),
    })
    const relationship = generatePeerIdentity()
    await bind(post, mediator, relationship, 'gen-1')
    const { plaintext } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit', submitBodyToWire({
      idempotencyKey: 'idem-1', mailFrom: ADDRESS, rcptTo: ['someone@biset.md'], rawRfc5322: new Uint8Array([1]),
    }))
    expect((plaintext.body as any).state).toBe('in-flight')
  })

  test('a recipient neither under an allowed domain nor a known contact is refused outright when it is the only one', async () => {
    const { mediator, post } = freshMailMediator({ allowedRecipientDomains: ['biset.md'] })
    const relationship = generatePeerIdentity()
    await bind(post, mediator, relationship, 'gen-1')
    const { plaintext } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit', submitBodyToWire({
      idempotencyKey: 'idem-1', mailFrom: ADDRESS, rcptTo: ['stranger@outside.example'], rawRfc5322: new Uint8Array([1]),
    }))
    expect((plaintext.body as any).code).toContain('recipient-not-allowed')
  })

  test('a known contact (recorded via contactHistory) is accepted even outside the allowed domain', async () => {
    const contactHistory = new ContactHistoryStore()
    contactHistory.record(ADDRESS, 'friend@outside.example')
    const { mediator, post } = freshMailMediator({
      allowedRecipientDomains: ['biset.md'], contactHistory,
      submitOutbound: async record => record.rcptTo.map(recipient => ({ recipient, status: 'accepted' as const })),
    })
    const relationship = generatePeerIdentity()
    await bind(post, mediator, relationship, 'gen-1')
    const { plaintext } = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit', submitBodyToWire({
      idempotencyKey: 'idem-1', mailFrom: ADDRESS, rcptTo: ['friend@outside.example'], rawRfc5322: new Uint8Array([1]),
    }))
    expect((plaintext.body as any).state).toBe('in-flight')
  })

  test('a mix of allowed and disallowed recipients: allowed ones dispatch, disallowed ones report permanent-failure', async () => {
    const { mediator, post } = freshMailMediator({
      allowedRecipientDomains: ['biset.md'],
      submitOutbound: async record => record.rcptTo.map(recipient => ({ recipient, status: 'accepted' as const })),
    })
    const relationship = generatePeerIdentity()
    await bind(post, mediator, relationship, 'gen-1')
    await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit', submitBodyToWire({
      idempotencyKey: 'idem-1', mailFrom: ADDRESS, rcptTo: ['ok@biset.md', 'stranger@outside.example'], rawRfc5322: new Uint8Array([1]),
    }))
    await Promise.resolve()
    const status = await request(post, mediator, relationship, 'https://biset.md/mail-mediator/1.0/submit-status-request', { idempotencyKey: 'idem-1' })
    expect((status.plaintext.body as any).state).toBe('completed')
    const results = (status.plaintext.body as any).results
    expect(results).toContainEqual({ recipient: 'ok@biset.md', status: 'accepted' })
    expect(results).toContainEqual({ recipient: 'stranger@outside.example', status: 'permanent-failure', detail: 'recipient not allowed' })
  })
})
