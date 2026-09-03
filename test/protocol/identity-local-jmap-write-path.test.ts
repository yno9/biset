// PLAN.md §3.2's "MLS/device signer接続": confirms buildVaultCryptoBoundary's
// signer -- built from a REAL MLS self group, not a hand-built fixture --
// is directly usable as VaultBackedLocalJmapMutationSink's own
// VaultEventSigner (the two interfaces are structurally identical on
// purpose). No test file exercised this combination before; every existing
// VaultBackedLocalJmapMutationSink test used a SHA-256 fixture signer.
// Round-trips all the way through: local Email/set -> signed event -> packed
// delivery outbox -> decoded -> verified and projected by a SEPARATE real
// MLS-connected verifier (buildVaultDeliveryProjector), proving the whole
// local-write-to-shared-delivery path actually interoperates on real keys.
import { describe, expect, test } from 'bun:test'
import { buildVaultCryptoBoundary, buildVaultDeliveryProjector } from '../../src/identity/bootstrap.ts'
import { createMlsGroup } from '../../src/mls/group.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'
import { LocalJmapGateway, LocalJmapTransport, MemoryLocalJmapReadModel, type LocalJmapSnapshot } from '../../src/local-jmap/gateway.ts'
import { VaultBackedLocalJmapMutationSink, type LocalVaultMutationCommitter } from '../../src/local-jmap/vault-mutation-sink.ts'
import { decodeVaultDeliveryPack } from '../../src/vault/delivery-pack.ts'
import { vaultEventSigningBytes } from '../../src/vault/events.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultSegmentRecord } from '../../src/vault/store.ts'
import type { IdentityRecord } from '../../src/identity/record-store.ts'
import type { SegmentKeyWrapV1 } from '../../src/protocol/vault.ts'

const identityId = 'did:web:alice.example'
const selfGroupId = 'test-self-group'

function memorySelfGroupStore(): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>()
  return {
    async save(id, selfGroupId, state) { rows.set(id, { selfGroupId, state }) },
    async load(id) { return rows.get(id) },
  }
}

function memoryWrapStore(): SegmentKeyWrapReader & SegmentKeyWrapWriter {
  const rows = new Map<string, SegmentKeyWrapV1>()
  const key = (id: string, segmentId: string, epoch: string) => `${id} ${segmentId} ${epoch}`
  return {
    async readSegmentKeyWrap(id, segmentId, epoch) { return rows.get(key(id, segmentId, epoch)) },
    async writeSegmentKeyWrap(wrap) { rows.set(key(wrap.identityId, wrap.segmentId, wrap.recipientEpoch), wrap) },
  }
}

function memorySegmentStore(): ActiveVaultSegmentStore {
  const rows: VaultSegmentRecord[] = []
  return {
    async currentSegment(id) { return rows.find(r => r.identityId === id && !r.sealed) },
    async allSegments(id) { return rows.filter(r => r.identityId === id) },
    async sealAndActivateSegment(next) {
      for (const row of rows) if (row.identityId === next.identityId && !row.sealed) row.sealed = true
      rows.push({ ...next })
    },
    async recordSegmentRewrapped(id, segmentId, epoch) {
      const row = rows.find(r => r.identityId === id && r.segmentId === segmentId)
      if (!row) throw new Error('no such segment')
      row.epoch = epoch
    },
  }
}

describe('local JMAP write path with a real MLS device signer', () => {
  test('Email/set signs with the real MLS leaf key, and a separate real MLS verifier accepts and projects it', async () => {
    const device = await mlsDeviceFixture(identityId)
    const deviceKid = device.kid
    const kp = device.own
    const state = await createMlsGroup(new TextEncoder().encode(selfGroupId), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupId, state)

    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const wraps = memoryWrapStore()
    const boundary = buildVaultCryptoBoundary(wraps, memorySegmentStore(), selfGroupStore, record)
    expect(boundary.signer.deviceId).toBe(deviceKid)

    let committed: Record<string, unknown> | undefined
    const committer: LocalVaultMutationCommitter = {
      async commitLocalMutation(input) { committed = input as unknown as Record<string, unknown>; return 'committed' },
    }
    let sequence = 0
    const sink = new VaultBackedLocalJmapMutationSink({
      accountId: `biset:${identityId}`,
      identityId,
      actorDeviceId: deviceKid,
      async nextActorSeq() { sequence += 1; return sequence },
      async initialParents() { return [] },
      activeSegment: () => boundary.activeSegment(),
      signer: boundary.signer,
      committer,
      now: () => new Date('2026-08-24T00:00:00.000Z'),
    })
    const model = new MemoryLocalJmapReadModel({
      state: 'state-1',
      mailboxes: [{ id: 'inbox', name: 'Inbox', totalEmails: 1, unreadEmails: 1 }],
      emails: [{ id: 'email-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-24T00:00:00.000Z' }],
    })
    const transport = new LocalJmapTransport(new LocalJmapGateway({ accountId: `biset:${identityId}`, identityId, readModel: model, mutationSink: sink }))

    const response = await transport.call<{ methodResponses: Array<[string, Record<string, unknown>, string]> }>([
      { name: 'Email/set', arguments: { accountId: `biset:${identityId}`, update: { 'email-1': { keywords: { '$seen': true } } } }, callId: 'set-1' },
    ])
    expect(response.methodResponses[0]).toMatchObject(['Email/set', { updated: { 'email-1': null } }, 'set-1'])

    // The signature attached to the committed event is a REAL MLS leaf
    // signature -- verified against the boundary's own (real) verifier.
    const event = (committed?.events as { signature: Uint8Array }[])[0]!
    const ok = await boundary.signer.verify(deviceKid, vaultEventSigningBytes(event as never), event.signature)
    expect(ok).toBe(true)

    // Round-trip through a SEPARATE real MLS-connected verifier -- the same
    // one shared vault delivery would use to accept this from a sibling
    // device -- proving the write path and the delivery path actually agree
    // on what a valid signature looks like.
    const deliveryOutbox = committed?.deliveryOutbox as { payload: Uint8Array }
    const pack = decodeVaultDeliveryPack(deliveryOutbox.payload)
    const baseSnapshot: LocalJmapSnapshot = { state: '0', mailboxes: [], emails: [{ id: 'email-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-24T00:00:00.000Z' }] }
    const projector = buildVaultDeliveryProjector(selfGroupStore, identityId, async () => baseSnapshot)
    const projected = await projector.verifyAndProject(pack)
    expect(projected.projection.emails[0]).toMatchObject({ id: 'email-1', keywords: { '$seen': true } })
  })
})
