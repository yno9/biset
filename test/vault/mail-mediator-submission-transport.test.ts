// MailMediatorSubmissionTransport, driven against a real in-process Mail
// Mediator (submit-status-request polling included) and a fake Anchor
// mail-address-credential endpoint, with the same in-memory Vault
// reader/sink shape as test/identity/mail-relationship.test.ts.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { generatePeerIdentity } from '../../src/didcomm/peer.ts'
import { createMailMediator } from '../../src/mail-mediator/server.ts'
import { MailRelationshipCredentialReader } from '../../src/vault/mail-relationship-credential-reader.ts'
import { MailRelationshipCredentialVaultSink } from '../../src/vault/mail-relationship-credential-sink.ts'
import { MailMediatorSubmissionTransport } from '../../src/vault/mail-mediator-submission-transport.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import { equalBytes } from '../../src/protocol/canonical.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import type { RecipientResult } from '../../src/mail-mediator/submission-store.ts'
import { issueBisetMailAddressCredential, verifyBisetMailAddressCredential } from '../../src/oid4vp/mail-address-profile.ts'

const segmentId = 'segment-1'
const segmentKey = createSegmentKey()
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}
const ADDRESS = 'y@biset.md'
const ANCHOR_ISSUER = 'https://anchor.test.example'
const ANCHOR_SIGNING_KEY_ID = `${ANCHOR_ISSUER}/oid4vp/jwks#mail-address-credential-eddsa-1`

function freshMailMediatorAndAnchor(submitOutbound: (record: { rcptTo: string[] }) => Promise<RecipientResult[]>) {
  const anchorSigningPrivateKey = ed25519.utils.randomSecretKey()
  const anchorSigningPublicKey = ed25519.getPublicKey(anchorSigningPrivateKey)
  const identityDid = `did:webvh:${'1'.repeat(46)}:e6d5.biset.md`

  const mediatorUrl = `https://mail-mediator-${crypto.randomUUID()}.test.example`
  const mediatorIdentity = generatePeerIdentity({ uri: mediatorUrl, accept: ['didcomm/v2'] })
  const { handle } = createMailMediator({
    mediator: mediatorIdentity,
    verifyMailAddressCredential: (token, now) => {
      const claims = verifyBisetMailAddressCredential(token, { issuer: ANCHOR_ISSUER, signingKeyId: ANCHOR_SIGNING_KEY_ID, signingPublicKey: anchorSigningPublicKey, now: new Date(now) })
      return { address: claims.credentialSubject.address, relationshipDid: claims.cnf.relationshipDid }
    },
    submitOutbound: record => submitOutbound(record),
  })

  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input)
    if (url === `${ANCHOR_ISSUER}/oid4vp/mail-address-credential/challenge`) {
      return Response.json({ challenge: 'fixed-test-challenge', expires_at: new Date(Date.now() + 300_000).toISOString() })
    }
    if (url === `${ANCHOR_ISSUER}/oid4vp/mail-address-credential/issue`) {
      const body = JSON.parse(String(init?.body)) as { relationship_did: string }
      const now = new Date()
      const credential = issueBisetMailAddressCredential({
        issuer: ANCHOR_ISSUER, signingKeyId: ANCHOR_SIGNING_KEY_ID, signingPrivateKey: anchorSigningPrivateKey,
        address: ADDRESS, relationshipDid: body.relationship_did, validFrom: new Date(now.getTime() - 60_000), validUntil: new Date(now.getTime() + 3_600_000),
      })
      return Response.json({ credential, expires_at: new Date(now.getTime() + 3_600_000).toISOString() }, { status: 201 })
    }
    const reqUrl = new URL(url)
    const res = await handle(new Request(reqUrl, init), reqUrl)
    return res ?? new Response('not found', { status: 404 })
  }
  return { identityDid, mediatorUrl, anchorBaseUrl: ANCHOR_ISSUER, fetchImpl }
}

function makeReaderSink(identityId: string): { reader: MailRelationshipCredentialReader; sink: MailRelationshipCredentialVaultSink } {
  const records: Array<{ event: any; object: any }> = []
  const objects = new Map<string, any>()

  const reader = new MailRelationshipCredentialReader({
    identityId,
    objects: { async readObject(_identityId, objectId) { return objects.get(objectId) } },
    events: { async readCredentialEvents() { return records.map(r => ({ ...r.event, identityId, targetIds: [...r.event.targetIds], objectRefs: [...r.event.objectRefs], parents: [...r.event.parents], signature: r.event.signature.slice() })) } },
    segmentKeys: { async resolveSegmentKey() { return segmentKey.slice() } },
    verifier: signer,
  })

  const sink = new MailRelationshipCredentialVaultSink({
    identityId, actorDeviceId: 'device-a',
    async nextActorSeq() { return records.length + 1 },
    async initialParents() { return records.length === 0 ? [] : ['event-1'] },
    async activeSegment() {
      const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(7), segmentKey, { identityId, selfGroupId: 'self-group-1', segmentId, sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: 'device-a', grantedAt: '2026-08-21T00:00:00.000Z' }, signer)
      return { segmentId, segmentKey, keyWraps: [wrap] }
    },
    async currentSnapshot() { return { state: 'state-1', mailboxes: [], emails: [] } },
    signer,
    committer: {
      async commitLocalMutation(input: any) {
        objects.set(input.objects[0].objectId, input.objects[0])
        records.push({ event: input.events[0], object: input.objects[0] } as any)
        return 'committed'
      },
    },
  })

  return { reader, sink }
}

describe('MailMediatorSubmissionTransport', () => {
  test('submit binds a relationship on first use, then polls submit-status-request to a completed accepted result', async () => {
    const { identityDid, mediatorUrl, anchorBaseUrl, fetchImpl } = freshMailMediatorAndAnchor(async record =>
      record.rcptTo.map(recipient => ({ recipient, status: 'accepted' as const })))
    const { reader, sink } = makeReaderSink(identityDid)
    const transport = new MailMediatorSubmissionTransport({
      mediatorUrl, identityDid, anchorBaseUrl, relationshipReader: reader, relationshipSink: sink, fetch: fetchImpl, pollIntervalMs: 5,
    })

    const result = await transport.submit({
      version: 1, identityId: identityDid, deviceId: 'device-a', mailFrom: ADDRESS, rcptTo: ['a@example.com'],
      rawRfc5322: new Uint8Array([1, 2, 3]), submittedAt: '2026-01-01T00:00:00.000Z', signature: new Uint8Array([9]),
    })
    expect(result.status).toBe('accepted')
  })

  test('a rejected recipient is reported as temporary-failure with detail', async () => {
    const { identityDid, mediatorUrl, anchorBaseUrl, fetchImpl } = freshMailMediatorAndAnchor(async record =>
      record.rcptTo.map(recipient => ({ recipient, status: 'permanent-failure' as const, detail: 'no such user' })))
    const { reader, sink } = makeReaderSink(identityDid)
    const transport = new MailMediatorSubmissionTransport({
      mediatorUrl, identityDid, anchorBaseUrl, relationshipReader: reader, relationshipSink: sink, fetch: fetchImpl, pollIntervalMs: 5,
    })

    const result = await transport.submit({
      version: 1, identityId: identityDid, deviceId: 'device-a', mailFrom: ADDRESS, rcptTo: ['a@example.com'],
      rawRfc5322: new Uint8Array([1, 2, 3]), submittedAt: '2026-01-01T00:00:00.000Z', signature: new Uint8Array([9]),
    })
    expect(result.status).toBe('temporary-failure')
    expect(result.detail).toContain('a@example.com')
    expect(result.detail).toContain('no such user')
  })

  test('resubmitting identical content reuses the same idempotency key (no duplicate dispatch)', async () => {
    let dispatchCount = 0
    const { identityDid, mediatorUrl, anchorBaseUrl, fetchImpl } = freshMailMediatorAndAnchor(async record => {
      dispatchCount++
      return record.rcptTo.map(recipient => ({ recipient, status: 'accepted' as const }))
    })
    const { reader, sink } = makeReaderSink(identityDid)
    const transport = new MailMediatorSubmissionTransport({
      mediatorUrl, identityDid, anchorBaseUrl, relationshipReader: reader, relationshipSink: sink, fetch: fetchImpl, pollIntervalMs: 5,
    })
    const request = {
      version: 1 as const, identityId: identityDid, deviceId: 'device-a', mailFrom: ADDRESS, rcptTo: ['a@example.com'],
      rawRfc5322: new Uint8Array([1, 2, 3]), submittedAt: '2026-01-01T00:00:00.000Z', signature: new Uint8Array([9]),
    }
    await transport.submit(request)
    await transport.submit({ ...request, submittedAt: '2026-01-01T01:00:00.000Z' })
    expect(dispatchCount).toBe(1)
  })
})
