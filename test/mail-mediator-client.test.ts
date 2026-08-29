// End-to-end coverage for the CLIENT side of the Mail Mediator protocol
// (src/didcomm/mail-mediator-client.ts), driven against the same
// createMailMediator handler test/mail-mediator/server.test.ts exercises
// directly, but through the client library a real device would use. The
// mediator's HTTP surface is faked as a fetch that dispatches straight
// into the in-process handler, same pattern as test/mediator-client.test.ts.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { generatePeerIdentity } from '../src/didcomm/peer.ts'
import { createMailMediator } from '../src/mail-mediator/server.ts'
import { SpoolStore } from '../src/mail-mediator/spool-store.ts'
import type { DidCommSender } from '../src/didcomm/mediator-transport.ts'
import {
  bindMailRoute, pickupMail, acknowledgeMail, submitMail, submitMailStatus,
} from '../src/didcomm/mail-mediator-client.ts'
import { fetchMediatorInfo } from '../src/didcomm/mediator-transport.ts'
import type { RecipientResult } from '../src/mail-mediator/submission-store.ts'
import { issueBisetMailAddressCredential, verifyBisetMailAddressCredential } from '../src/oid4vp/mail-address-profile.ts'

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

function freshMailMediatorFetch() {
  const url = `https://mail-mediator-${crypto.randomUUID()}.test.example`
  const mediatorIdentity = generatePeerIdentity({ uri: url, accept: ['didcomm/v2'] })
  const spool = new SpoolStore()
  let submitOutbound: (record: { rcptTo: string[] }) => Promise<RecipientResult[]> = async record =>
    record.rcptTo.map(recipient => ({ recipient, status: 'accepted' as const }))
  const { handle } = createMailMediator({
    mediator: mediatorIdentity,
    spool,
    verifyMailAddressCredential: (token, now) => {
      const claims = verifyBisetMailAddressCredential(token, { issuer: ANCHOR_ISSUER, signingKeyId: ANCHOR_SIGNING_KEY_ID, signingPublicKey: ANCHOR_SIGNING_PUBLIC_KEY, now: new Date(now) })
      return { address: claims.credentialSubject.address, relationshipDid: claims.cnf.relationshipDid }
    },
    submitOutbound: record => submitOutbound(record),
  })
  const fetchImpl: typeof fetch = async (input, init) => {
    const reqUrl = new URL(String(input))
    const res = await handle(new Request(reqUrl, init), reqUrl)
    return res ?? new Response('not found', { status: 404 })
  }
  return { url, spool, setSubmitOutbound(fn: typeof submitOutbound) { submitOutbound = fn }, fetchImpl }
}

describe('mail-mediator client library (mail-mediator-client.ts)', () => {
  test('bindMailRoute + pickupMail + acknowledgeMail: full round trip', async () => {
    const { url, spool, fetchImpl } = freshMailMediatorFetch()
    const relationshipPeer = generatePeerIdentity()
    const relationship: DidCommSender = { did: relationshipPeer.did, xKid: relationshipPeer.xKid, xPriv: relationshipPeer.xPriv }
    const mediator = await fetchMediatorInfo(url, fetchImpl)

    const bindResult = await bindMailRoute(mediator, relationship, {
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationshipPeer.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z', mailAddressCredential: vcFor(relationshipPeer.did),
    }, fetchImpl)
    expect(bindResult.accepted).toBe(true)
    expect(bindResult.address).toBe(ADDRESS)

    spool.enqueue({
      address: ADDRESS, semanticIngressId: 'sid-1', mailFrom: 'sender@example.com',
      encryptedBody: new Uint8Array([1, 2, 3]), bodyHash: new Uint8Array([9, 9]),
      createdAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-02-01T00:00:00.000Z',
    })

    const picked = await pickupMail(mediator, relationship, 10, fetchImpl)
    expect(picked.address).toBe(ADDRESS)
    expect(picked.items).toHaveLength(1)
    expect(picked.items[0]!.encryptedBody).toEqual(new Uint8Array([1, 2, 3]))

    await acknowledgeMail(mediator, relationship, ADDRESS, [picked.items[0]!.spoolId], fetchImpl)
    const pickedAgain = await pickupMail(mediator, relationship, 10, fetchImpl)
    expect(pickedAgain.items).toHaveLength(0)
  })

  test('submitMail then submitMailStatus reports the completed result once outbound dispatch resolves', async () => {
    const { url, setSubmitOutbound, fetchImpl } = freshMailMediatorFetch()
    const relationshipPeer = generatePeerIdentity()
    const relationship: DidCommSender = { did: relationshipPeer.did, xKid: relationshipPeer.xKid, xPriv: relationshipPeer.xPriv }
    const mediator = await fetchMediatorInfo(url, fetchImpl)

    await bindMailRoute(mediator, relationship, {
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationshipPeer.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z', mailAddressCredential: vcFor(relationshipPeer.did),
    }, fetchImpl)

    let resolveOutbound!: (results: RecipientResult[]) => void
    const outboundDone = new Promise<RecipientResult[]>(resolve => { resolveOutbound = resolve })
    setSubmitOutbound(async () => outboundDone)

    const submitResult = await submitMail(mediator, relationship, {
      idempotencyKey: 'idem-1', mailFrom: ADDRESS, rcptTo: ['a@example.com'], rawRfc5322: new Uint8Array([1, 2, 3]),
    }, fetchImpl)
    expect(submitResult.state).toBe('in-flight')

    resolveOutbound([{ recipient: 'a@example.com', status: 'accepted' }])
    await outboundDone
    await Promise.resolve()

    const status = await submitMailStatus(mediator, relationship, 'idem-1', fetchImpl)
    expect(status.state).toBe('completed')
    expect(status.results).toEqual([{ recipient: 'a@example.com', status: 'accepted' }])
  })

  test('bindMailRoute with a VC for a different relationship identity is refused', async () => {
    const { url, fetchImpl } = freshMailMediatorFetch()
    const relationship = generatePeerIdentity()
    const someoneElse = generatePeerIdentity()
    const mediator = await fetchMediatorInfo(url, fetchImpl)
    await expect(bindMailRoute(mediator, { did: relationship.did, xKid: relationship.xKid, xPriv: relationship.xPriv }, {
      address: ADDRESS, relationshipKid: relationship.xKid, pickupPublicKey: relationship.xPub,
      routeGeneration: 'gen-1', expiresAt: '2030-01-01T00:00:00.000Z', mailAddressCredential: vcFor(someoneElse.did),
    }, fetchImpl)).rejects.toThrow()
  })
})
