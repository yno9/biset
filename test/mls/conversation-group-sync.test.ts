// End-to-end: syncConversationGroupDeliveries against a real MLS group and
// a real Conversation Group DS -- confirms the pull-based catch-up loop
// (replacing the deleted push-based conversation-group-ingress.ts) actually
// decrypts, projects, and persists progress correctly: commit/proposal
// entries advance state with no Vault record, application entries decode
// to a message.add committed through the caller's callback, and the stored
// cursor only advances as far as what was actually committed.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import { Ed25519ConversationDsSignatureVerifier } from '../../src/mls-ds/authorizer.ts'
import { createConversationDeliveryHttpHandler } from '../../src/mls-ds/http.ts'
import { ConversationMlsDeliveryTransport } from '../../src/mls-ds/client-transport.ts'
import { addMembersToConversationGroup, createConversationGroup, randomGroupLocalKeypair, sendConversationApplicationMessage } from '../../src/mls/conversation-group.ts'
import { syncConversationGroupDeliveries, type ConversationGroupVaultRecord } from '../../src/mls/conversation-group-sync.ts'
import type { ConversationGroupRosterEntry, MlsConversationGroupStateStore } from '../../src/mls/conversation-group-store.ts'
import { encodeMimiContent, mimiRoomUri, DISPOSITION_RENDER, type MimiContent } from '../../src/mls/mimi-content.ts'
import { joinMlsGroup, type ClientState } from '../../src/mls/group.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { mlsDeviceFixture } from '../protocol/support/mls-device-fixture.ts'

const identityId = 'did:web:bob.example'
const alice = await mlsDeviceFixture('did:web:alice.example')
const bob = await mlsDeviceFixture(identityId)

const signer: VaultEventSigner = {
  deviceId: bob.kid,
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === bob.kid && equalBytes(signature, await this.sign(bytes)) },
}

function memoryStateStore(initial?: { groupId: string; state: ClientState; ownGroupLocalPrivateKey: Uint8Array; roster: ConversationGroupRosterEntry[] }): MlsConversationGroupStateStore {
  const rows = new Map<string, { state: ClientState; lastSeenSeq: number; ownGroupLocalPrivateKey: Uint8Array; roster: ConversationGroupRosterEntry[] }>()
  if (initial) rows.set(initial.groupId, { state: initial.state, lastSeenSeq: 0, ownGroupLocalPrivateKey: initial.ownGroupLocalPrivateKey, roster: initial.roster })
  return {
    async save(groupId, state, lastSeenSeq, ownGroupLocalPrivateKey, roster) { rows.set(groupId, { state, lastSeenSeq, ownGroupLocalPrivateKey, roster }) },
    async load(groupId) { return rows.get(groupId) },
    async listGroupIds() { return [...rows.keys()] },
  }
}

const path = `/tmp/biset-conversation-group-sync-${process.pid}-${Date.now()}.sqlite`
afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) { try { rmSync(`${path}${suffix}`) } catch {} }
})

async function setupGroup(text: string) {
  const ds = SqliteConversationDeliveryService.open(path)
  const handle = createConversationDeliveryHttpHandler(ds, new Ed25519ConversationDsSignatureVerifier())
  const transport = new ConversationMlsDeliveryTransport({ baseUrl: 'https://mls-ds.example', fetch: (input, init) => handle(new Request(input, init)) })
  const groupId = `group-sync-${Math.random().toString(16).slice(2)}`

  const created = await createConversationGroup(transport, groupId, alice.own)
  let aliceState = created.state
  const aliceSign = (bytes: Uint8Array) => ed25519.sign(bytes, created.ownGroupLocal.privateKey)
  const bobLocal = randomGroupLocalKeypair()

  aliceState = await addMembersToConversationGroup(
    aliceState, transport, groupId, created.ownGroupLocal.id, [{ keyPackage: bob.own.publicPackage, groupLocalId: bobLocal.id }], aliceSign,
  )
  const welcomeEntry = ds.deliveriesSince(groupId, bobLocal.id, 0)!.find(e => e.kind === 'welcome')!
  const bobState = await joinMlsGroup(welcomeEntry.payload, bob.own, undefined)

  const senderUri = alice.kid
  const roomUri = mimiRoomUri(groupId)
  const content: MimiContent = {
    salt: new Uint8Array(16).fill(4), replaces: null, topicId: new Uint8Array(0), expires: null, inReplyTo: null,
    extensions: { senderUri, roomUri },
    nestedPart: { disposition: DISPOSITION_RENDER, language: 'en', part: { kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode(text) } },
  }
  aliceState = await sendConversationApplicationMessage(aliceState, transport, groupId, created.ownGroupLocal.id, encodeMimiContent(content), aliceSign)

  return { ds, transport, groupId, bobState, bobLocal, aliceSign: signerFor(bobLocal.privateKey) }

  function signerFor(privateKey: Uint8Array) {
    return (bytes: Uint8Array) => ed25519.sign(bytes, privateKey)
  }
}

async function segmentFor() {
  const segmentKey = createSegmentKey()
  const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(9), segmentKey, {
    identityId, selfGroupId: 'self-group-1', segmentId: 'segment-1', sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: bob.kid, grantedAt: '2026-08-31T00:00:00.000Z',
  }, signer)
  return { segmentId: 'segment-1', segmentKey, keyWraps: [wrap] }
}

function syncOptionsFor(transport: ConversationMlsDeliveryTransport, stateStore: MlsConversationGroupStateStore, sign: (bytes: Uint8Array) => Uint8Array, committed: ConversationGroupVaultRecord[]) {
  let actorSeq = 1
  return {
    stateStore, transport, sign,
    identityId, actorDeviceId: bob.kid,
    async nextActorSeq() { return actorSeq++ },
    async initialParents() { return [] },
    activeSegment: segmentFor,
    async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [] } },
    signer,
    async commitVaultRecord(record: ConversationGroupVaultRecord) { committed.push(record) },
    now: () => new Date('2026-08-31T00:01:00.000Z'),
  }
}

describe('syncConversationGroupDeliveries', () => {
  test('pulls the welcome-commit-application backlog, commits the one application entry, and advances the stored cursor', async () => {
    const { transport, groupId, bobState, bobLocal } = await setupGroup('hello group')
    const stateStore = memoryStateStore({ groupId, state: bobState, ownGroupLocalPrivateKey: bobLocal.privateKey, roster: [] })
    const committed: ConversationGroupVaultRecord[] = []
    const sign = (bytes: Uint8Array) => ed25519.sign(bytes, bobLocal.privateKey)

    const result = await syncConversationGroupDeliveries(groupId, syncOptionsFor(transport, stateStore, sign, committed))
    expect(result.applied).toBe(1)
    expect(committed).toHaveLength(1)
    expect(committed[0]!.events[0]!.kind).toBe('message.add')

    const stored = await stateStore.load(groupId)
    // welcome(seq 1, skipped) + commit(seq 2, epoch 0 -- already folded into
    // bob's state via joinMlsGroup, so the epoch guard skips re-applying it
    // too) + application(seq 3, epoch 1 -- matches bob's current epoch, applied).
    expect(stored?.lastSeenSeq).toBe(3)
  })

  test('a second sync with nothing new applies zero entries and leaves the cursor unchanged', async () => {
    const { transport, groupId, bobState, bobLocal } = await setupGroup('hello again')
    const stateStore = memoryStateStore({ groupId, state: bobState, ownGroupLocalPrivateKey: bobLocal.privateKey, roster: [] })
    const committed: ConversationGroupVaultRecord[] = []
    const sign = (bytes: Uint8Array) => ed25519.sign(bytes, bobLocal.privateKey)

    const first = await syncConversationGroupDeliveries(groupId, syncOptionsFor(transport, stateStore, sign, committed))
    expect(first.applied).toBe(1)
    const afterFirst = await stateStore.load(groupId)

    const second = await syncConversationGroupDeliveries(groupId, syncOptionsFor(transport, stateStore, sign, committed))
    expect(second.applied).toBe(0)
    const afterSecond = await stateStore.load(groupId)
    expect(afterSecond?.lastSeenSeq).toBe(afterFirst?.lastSeenSeq)
  })

  test('throws for a group this device has no local state for', async () => {
    const { transport, groupId } = await setupGroup('irrelevant')
    const stateStore = memoryStateStore()
    const committed: ConversationGroupVaultRecord[] = []
    const sign = (bytes: Uint8Array) => ed25519.sign(bytes, randomGroupLocalKeypair().privateKey)
    await expect(syncConversationGroupDeliveries(groupId, syncOptionsFor(transport, stateStore, sign, committed))).rejects.toThrow(/no local state/)
  })
})
