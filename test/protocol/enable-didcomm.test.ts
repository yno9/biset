// Same shape as test/protocol/enable-openpgp.test.ts, for the DIDComm
// keyAgreement credential (vault/didcomm-credential.ts, identity-shared
// since the 2026-08-27 mediator redesign -- ARC.md's DIDComm section).
// identity-bootstrap.test.ts's own 'enableDidComm' describe block covers
// the real-anchor/real-core, two-device-record end-to-end path; this file
// isolates just enableDidComm's credential-reader/sink interaction from
// that heavier fixture. Unlike enableOpenPgpMail, enableDidComm also calls
// publishRoutingPointer (a real did:webvh log write), so each test needs a
// real genesis log behind the identity, not just a routing.json stub.
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { createSegmentKey } from '../../src/vault/objects.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import type { DidCommPrivateCredentialV1 } from '../../src/vault/didcomm-credential.ts'
import { DidCommCredentialReader } from '../../src/vault/didcomm-credential-reader.ts'
import { DidCommCredentialVaultSink } from '../../src/vault/didcomm-credential-sink.ts'
import { enableDidComm } from '../../src/identity/bootstrap.ts'
import { fetchRouting } from '../../src/didcomm/webvh-routing.ts'
import { deviceKidFragment } from '../../src/didcomm/devicekid.ts'
import { createGenesis } from '../../src/identity/webvh/create-genesis.ts'
import { fakeAnchor } from './support/webvh-log-fixture.ts'
import type { IdentityRecord, IdentityRecordStore } from '../../src/identity/record-store.ts'
import { generatePeerIdentity } from '../../src/didcomm/peer.ts'
import { createMediator } from '../../src/mediator/server.ts'
import { queryKeylist } from '../../src/didcomm/mediator-coordinate.ts'
import { resolveDidCommSenderKey } from '../../src/didcomm/webvh-resolve.ts'

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function fromHex(hex: string): Uint8Array {
  return new Uint8Array((hex.match(/../g) ?? []).map(b => parseInt(b, 16)))
}

/** identity/webvh/resolver.ts's `resolve()` (the did.jsonl read side, used
 * by resolveDidCommSenderKey when the mediator authenticates a did:webvh
 * sender) always uses the real global fetch, no injection point (its own
 * header) -- so exercising the mediator against a did:webvh client needs
 * globalThis.fetch swapped for the test's duration, same pattern
 * test/protocol/didcomm-send-message.test.ts uses for the same reason. */
function withGlobalFetch<T>(handler: typeof fetch, run: () => Promise<T>): Promise<T> {
  const real = globalThis.fetch
  globalThis.fetch = handler
  return run().finally(() => { globalThis.fetch = real })
}

/** Routes any request whose URL starts with `origin` to `handle` (a
 * mediator's own HTTP surface); everything else falls through to
 * `anchorFetch` (routing.json/did.jsonl). Mirrors
 * test/protocol/didcomm-send-message.test.ts's own combined-stub pattern,
 * one layer deeper since enableDidComm needs BOTH a did:webvh anchor AND a
 * mediator behind one injected `fetch`. */
function combinedFetch(anchorFetch: typeof fetch, origin: string, handle: (req: Request, url: URL) => Promise<Response | null>): typeof fetch {
  return (async (input, init) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url.startsWith(origin)) {
      const parsed = new URL(url)
      const res = await handle(new Request(parsed, init), parsed)
      return res ?? new Response('not found', { status: 404 })
    }
    return anchorFetch(input, init)
  }) as typeof fetch
}

/** A real genesis-backed identity: enableDidComm's own publishRoutingPointer
 * call writes to the did:webvh log itself, so a routing.json-only stub
 * (like enable-openpgp.test.ts's fixture) isn't enough here. */
async function genesisRecord(domain: string, fetchImpl: typeof fetch): Promise<IdentityRecord> {
  const rootPrivateKey = ed25519.utils.randomSecretKey()
  const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
  const { did, versionId } = await createGenesis({ domain, rootPrivateKey, rootPublicKey, fetch: fetchImpl })
  return { did, rootPublicKey: toHex(rootPublicKey), rootPrivateKey: toHex(rootPrivateKey), signPublicKey: toHex(rootPublicKey), signPrivateKey: toHex(rootPrivateKey), generation: versionId }
}

async function harness(identityId: string) {
  const signer: VaultEventSigner = {
    deviceId: 'device-a',
    async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
    async verify(deviceId, bytes, signature) {
      if (deviceId !== 'device-a') return false
      const expected = await this.sign(bytes)
      return expected.length === signature.length && expected.every((b, i) => b === signature[i])
    },
  }
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
  const reader = new DidCommCredentialReader({
    identityId,
    objects: { async readObject(_id: string, objectId: string) { return objects.get(objectId) } },
    events: { async readCredentialEvents() { return events.map(event => ({ ...event })) } },
    segmentKeys: { async resolveSegmentKey() { return segmentKey.slice() } },
    verifier: signer,
  })
  const sink = new DidCommCredentialVaultSink({
    identityId, actorDeviceId: 'device-a',
    async nextActorSeq() { return ++actorSeq },
    async initialParents() { return events.length ? [events.at(-1)!.id] : [] },
    async activeSegment() { return { segmentId: 'segment-1', segmentKey, keyWraps: [wrap] } },
    async currentSnapshot() { return { state: 'state-1', mailboxes: [], emails: [] } },
    signer, committer,
  })
  return { reader, sink, eventCount: () => events.length }
}

function memoryRecordStore(): IdentityRecordStore {
  const records = new Map<string, IdentityRecord>()
  return {
    async get(did) { return records.get(did) },
    async put(record) { records.set(record.did, record) },
    async list() { return [...records.values()] },
    async delete(did) { records.delete(did) },
  }
}

describe('enableDidComm (credential reader/sink isolation)', () => {
  test('mints and vault-stores a credential the first time, then publishes its public key to routing.json', async () => {
    const { fetch } = fakeAnchor()
    const record = await genesisRecord('alice.example', fetch)
    const { reader, sink, eventCount } = await harness(record.did)
    const recordStore = memoryRecordStore()

    const updated = await enableDidComm(recordStore, record, reader, sink, { fetch })

    expect(eventCount()).toBe(1)
    const credential = await reader.readCurrent()
    expect(credential.identityId).toBe(record.did)
    expect(updated.didCommKid).toBe(credential.didCommKid)
    expect(updated.didCommX25519PrivateKey).toBe(toHex(credential.privateKey))

    const routing = await fetchRouting(record.did, fetch)
    const kaVm = routing?.keyAgreementVerificationMethod?.[0]
    expect(kaVm?.id).toBe(credential.didCommKid)
    expect(kaVm?.id).toBe(`${record.did}${deviceKidFragment(x25519.getPublicKey(credential.privateKey))}`)
  })

  test('is idempotent: a second call neither mints a new credential nor rewrites routing.json', async () => {
    const { fetch } = fakeAnchor()
    const record = await genesisRecord('bob.example', fetch)
    const { reader, sink } = await harness(record.did)
    const recordStore = memoryRecordStore()

    const first = await enableDidComm(recordStore, record, reader, sink, { fetch })
    const firstRouting = await fetchRouting(record.did, fetch)

    const second = await enableDidComm(recordStore, first, reader, sink, { fetch })
    expect(second.didCommKid).toBe(first.didCommKid)
    const secondRouting = await fetchRouting(record.did, fetch)
    expect(secondRouting).toEqual(firstRouting)
  })

  test('propagates an ambiguous rotation instead of minting a competing third key', async () => {
    const { fetch } = fakeAnchor()
    const record = await genesisRecord('carol.example', fetch)
    const { reader, sink } = await harness(record.did)
    const recordStore = memoryRecordStore()
    const now = '2026-08-27T00:00:00.000Z'
    const priv1 = x25519.utils.randomSecretKey()
    const priv2 = x25519.utils.randomSecretKey()
    const first: DidCommPrivateCredentialV1 = { version: 1, kind: 'credential.didcomm.private', identityId: record.did, didCommKid: `${record.did}${deviceKidFragment(x25519.getPublicKey(priv1))}`, privateKey: priv1, createdAt: now }
    const second: DidCommPrivateCredentialV1 = { version: 1, kind: 'credential.didcomm.private', identityId: record.did, didCommKid: `${record.did}${deviceKidFragment(x25519.getPublicKey(priv2))}`, privateKey: priv2, createdAt: now }
    await sink.store(first)
    await sink.store(second)

    await expect(enableDidComm(recordStore, record, reader, sink, { fetch })).rejects.toThrow('ambiguous')
  })

  test('mediatorUrls: registers with the mediator and publishes routingKeys instead of the legacy direct endpoint', async () => {
    const { fetch: anchorFetch } = fakeAnchor()
    const mediatorIdentity = generatePeerIdentity({ uri: 'https://mediator.test.example', accept: ['didcomm/v2'] })
    // The mediator must authenticate a did:webvh sender's mediate-request --
    // resolved against the SAME fake anchor the identity's own did.jsonl/
    // routing.json live on (resolveDidCommSenderKey is pure HTTP, no
    // biset-core dependency, per its own header).
    const { handle } = createMediator({
      mediator: mediatorIdentity,
      resolveDidWebvh: async (_did, kid) => { try { return await resolveDidCommSenderKey(kid, anchorFetch) } catch { return null } },
    })
    const fetch = combinedFetch(anchorFetch, 'https://mediator.test.example', handle)

    await withGlobalFetch(fetch, async () => {
      const record = await genesisRecord('dora.example', fetch)
      const { reader, sink } = await harness(record.did)
      const recordStore = memoryRecordStore()

      const updated = await enableDidComm(recordStore, record, reader, sink, {
        mediatorUrls: ['https://mediator.test.example'], fetch,
      })

      const routing = await fetchRouting(record.did, fetch)
      expect(routing?.service).toHaveLength(1)
      const service = routing!.service[0]!
      expect((service.serviceEndpoint as any).uri).toBe('https://mediator.test.example')
      expect((service.serviceEndpoint as any).routingKeys).toEqual([mediatorIdentity.xKid])

      // The registration actually took: the mediator's own keylist now
      // contains this identity's didCommKid.
      const conn = await queryKeylist({ url: 'https://mediator.test.example', did: mediatorIdentity.did, xKid: mediatorIdentity.xKid, xPub: mediatorIdentity.xPub }, { did: record.did, xKid: updated.didCommKid!, xPriv: fromHex(updated.didCommX25519PrivateKey!) }, fetch)
      expect(conn).toEqual([{ kid: updated.didCommKid! }])
    })
  })

  test('mediatorUrls: publishes no service entry at all when every registration fails', async () => {
    const { fetch: anchorFetch } = fakeAnchor()
    const deadFetch = combinedFetch(anchorFetch, 'https://unreachable.test.example', async () => new Response('offline', { status: 503 }))

    await withGlobalFetch(deadFetch, async () => {
      const record = await genesisRecord('erin.example', deadFetch)
      const { reader, sink } = await harness(record.did)
      const recordStore = memoryRecordStore()

      await enableDidComm(recordStore, record, reader, sink, {
        mediatorUrls: ['https://unreachable.test.example'], fetch: deadFetch,
      })

      // The legacy `coreBaseUrl` direct-delivery fallback is gone (core is
      // retired, and the value was always '' in production, so what it
      // actually published was the relative, undeliverable URI
      // `/v1/didcomm/ingress`). The keyAgreement key still goes out -- that
      // is what a mediate-request has to resolve -- but with no service
      // entry, so no sender is pointed anywhere.
      const routing = await fetchRouting(record.did, deadFetch)
      expect(routing?.service).toEqual([])
      expect(routing?.keyAgreementVerificationMethod?.length).toBe(1)
    })
  })
})
