import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import type { OpenPgpPrivateCredentialV1 } from '../../src/vault/openpgp-credential.ts'
import { OpenPgpCredentialReader } from '../../src/vault/openpgp-credential-reader.ts'
import { OpenPgpCredentialVaultSink } from '../../src/vault/openpgp-credential-sink.ts'
import { enableOpenPgpMail } from '../../src/mail/enable-openpgp.ts'
import { fetchRouting } from '../../src/didcomm/webvh-routing.ts'
import { encodeMultikey } from '../../src/identity/webvh/multikey.ts'
import { fakeAnchor, jcsMultihashBase58 } from './support/webvh-log-fixture.ts'

const identityId = `did:webvh:${jcsMultihashBase58('enable-openpgp-test')}:alice.example`
const mailAddress = 'alice@example.com'
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

async function harness() {
  const objects = new Map<string, any>()
  const events: any[] = []
  const segmentKey = createSegmentKey()
  const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(7), segmentKey, { identityId, selfGroupId: 'self-group-1', segmentId: 'segment-1', sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: 'device-a', grantedAt: '2026-08-25T00:00:00.000Z' }, signer)
  let actorSeq = 0
  const committer = {
    async commitLocalMutation(input: any) {
      for (const object of input.objects) objects.set(object.objectId, object)
      events.push(...input.events)
      return 'committed' as const
    },
  }
  const reader = new OpenPgpCredentialReader({
    identityId,
    objects: { async readObject(_id: string, objectId: string) { return objects.get(objectId) } },
    events: { async readCredentialEvents() { return events.map(event => ({ ...event })) } },
    segmentKeys: { async resolveSegmentKey() { return segmentKey.slice() } },
    verifier: signer,
  })
  const sink = new OpenPgpCredentialVaultSink({
    identityId, actorDeviceId: 'device-a',
    async nextActorSeq() { return ++actorSeq },
    async initialParents() { return events.length ? [events.at(-1)!.id] : [] },
    async activeSegment() { return { segmentId: 'segment-1', segmentKey, keyWraps: [wrap] } },
    async currentSnapshot() { return { state: 'state-1', mailboxes: [], emails: [] } },
    signer, committer,
  })
  return { reader, sink, eventCount: () => events.length }
}

function signing() {
  const privateKey = ed25519.utils.randomSecretKey()
  return { updateKey: encodeMultikey(ed25519.getPublicKey(privateKey)), privateKey }
}

describe('enableOpenPgpMail', () => {
  test('generates and vault-stores a credential the first time, then publishes its public key to routing.json', async () => {
    const { reader, sink, eventCount } = await harness()
    const { fetch } = fakeAnchor()
    await enableOpenPgpMail(reader, sink, signing(), { identityId, mailAddress, fetch })

    expect(eventCount()).toBe(1)
    const credential = await reader.readCurrent()
    expect(credential.identityId).toBe(identityId)

    const routing = await fetchRouting(identityId, fetch)
    expect(routing?.openpgpPublicKey?.fingerprint).toBe(credential.fingerprint)
    expect(routing?.openpgpPublicKey?.armoredPublicKey).toContain('BEGIN PGP PUBLIC KEY')
  })

  test('is idempotent: a second call neither mints a new credential nor rewrites routing.json', async () => {
    const { reader, sink, eventCount } = await harness()
    const { fetch } = fakeAnchor()
    const keys = signing()
    await enableOpenPgpMail(reader, sink, keys, { identityId, mailAddress, fetch })
    const firstRouting = await fetchRouting(identityId, fetch)

    await enableOpenPgpMail(reader, sink, keys, { identityId, mailAddress, fetch })
    expect(eventCount()).toBe(1)
    const secondRouting = await fetchRouting(identityId, fetch)
    expect(secondRouting).toEqual(firstRouting)
  })

  test('propagates an ambiguous rotation instead of minting a competing third key', async () => {
    const { reader, sink } = await harness()
    const { fetch } = fakeAnchor()
    const now = '2026-08-25T00:00:00.000Z'
    const first: OpenPgpPrivateCredentialV1 = { version: 1, kind: 'credential.openpgp.private', identityId, fingerprint: '0123456789ABCDEF0123456789ABCDEF01234567', privateKey: new Uint8Array([1]), createdAt: now }
    const second: OpenPgpPrivateCredentialV1 = { version: 1, kind: 'credential.openpgp.private', identityId, fingerprint: '89ABCDEF0123456789ABCDEF0123456789ABCDEF', privateKey: new Uint8Array([2]), createdAt: now }
    await sink.store(first)
    await sink.store(second)

    await expect(enableOpenPgpMail(reader, sink, signing(), { identityId, mailAddress, fetch })).rejects.toThrow('ambiguous')
  })
})
