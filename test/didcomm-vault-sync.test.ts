// Vault Sync: one message to the identity's own DID reaches every device;
// a device ignores its own copy; only the identity's own devices are heard.
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { VaultSyncClient, walletVaultSyncTransport, type VaultSyncMessage } from '../src/client/didcomm/vault-sync.ts'
import { bytesToBase64url } from '../src/protocol/canonical.ts'
import { VAULT_SYNC_STATE_REQUEST, VAULT_SYNC_STATE_RESPONSE, VAULT_SYNC_UPDATE } from '../src/protocol/didcomm/vault-sync-protocol.ts'
import { encodeVaultDeliveryPack } from '../src/client/store/vault/delivery-pack.ts'
import { createVaultEvent, type VaultEventAuthor } from '../src/client/store/vault/events.ts'
import { registerWithMediator } from '../src/client/didcomm/mediator-sync.ts'
import { pickupDeliver } from '../src/protocol/didcomm/mediator-pickup.ts'
import { mediatorInbox } from '../src/protocol/didcomm/mediator-device.ts'
import { serializeLog } from '../src/protocol/webvh/log.ts'
import { buildDidCommLog } from './protocol/support/webvh-log-fixture.ts'
import { freshMediator, MEDIATOR_URL } from './support/mediator.ts'
import type { IncomingVaultRecords } from '../src/client/store/vault/store.ts'

const DID = 'did:webvh:scid:alice.example'
const signer: VaultEventAuthor = { deviceId: 'device-a' }

function memoryStore() {
  const committed: IncomingVaultRecords[] = []
  return {
    committed,
    async readVaultEvents() { return [] }, async readVaultObjects() { return [] }, async readSegmentKeys() { return [] },
    async findDuplicateActorSequences() { return [] },
    async commitIncomingRecords(records: IncomingVaultRecords) { committed.push(records); return { addedEventIds: records.events.map(e => e.id), targetIds: [] } },
  }
}

const packBody = (events: Parameters<typeof encodeVaultDeliveryPack>[0]['events'], segmentKeys: Parameters<typeof encodeVaultDeliveryPack>[0]['segmentKeys'] = []) =>
  ({ pack: bytesToBase64url(encodeVaultDeliveryPack({ version: 1, identityId: DID, events, objects: [], segmentKeys })) })

describe('VaultSyncClient', () => {
  test('applies a sibling\'s records (with segment keys), ignores its own copy, and refuses other identities', async () => {
    const store = memoryStore(); const sent: VaultSyncMessage[] = []
    const client = new VaultSyncClient(DID, `${DID}#k_self`, store, { async send(message) { sent.push(message) } })
    const segmentKeys = [{ segmentId: 'segment-1', segmentKey: new Uint8Array(32).fill(4) }]
    const message: VaultSyncMessage = { type: VAULT_SYNC_STATE_RESPONSE, body: { ...packBody([], segmentKeys), hasMore: false } }
    expect(await client.receive(message, `${DID}#k_self`)).toBeUndefined()
    expect(store.committed).toHaveLength(0)
    await client.receive(message, `${DID}#k_sibling`)
    expect(store.committed[0]!.segmentKeys).toEqual(segmentKeys)
    await expect(client.receive(message, 'did:webvh:scid:mallory.example#k_x')).rejects.toThrow('this identity')
  })

  test('isolates one invalid event without rejecting valid records in the same batch', async () => {
    const valid = await createVaultEvent({ identityId: DID, actorDeviceId: 'device-a', actorSeq: 1, kind: 'settings.set', targetIds: ['settings'], objectRefs: [], parents: [], createdAt: '2026-01-01T00:00:00.000Z' }, signer)
    const invalid = { ...valid, actorSeq: 2 }
    const store = memoryStore()
    const client = new VaultSyncClient(DID, `${DID}#k_self`, store, { async send() {} })
    const result = await client.receive({ type: VAULT_SYNC_STATE_RESPONSE, body: { ...packBody([valid, invalid]), hasMore: false } }, `${DID}#k_sibling`)
    expect(store.committed[0]!.events).toHaveLength(1); expect(result?.skippedEvents).toBe(1)
  })

  test('an update is followed by one state request to every sibling', async () => {
    const sent: VaultSyncMessage[] = []
    const client = new VaultSyncClient(DID, `${DID}#k_self`, memoryStore(), { async send(message) { sent.push(message) } })
    await client.receive({ type: VAULT_SYNC_UPDATE, body: packBody([]) }, `${DID}#k_sibling`)
    expect(sent.map(message => message.type)).toEqual([VAULT_SYNC_STATE_REQUEST])
  })
})

describe('walletVaultSyncTransport', () => {
  test('one send reaches every device of the identity through the mediator, each able to open it', async () => {
    const { mediator, handle, store } = freshMediator()
    const root = ed25519.utils.randomSecretKey()
    const phoneX = x25519.utils.randomSecretKey(); const laptopX = x25519.utils.randomSecretKey()
    const { did, log } = buildDidCommLog({
      rootPrivateKey: root, rootPublicKey: ed25519.getPublicKey(root),
      keyAgreementKeys: [{ fragment: 'k_phone', x25519PublicKey: x25519.getPublicKey(phoneX) }, { fragment: 'k_laptop', x25519PublicKey: x25519.getPublicKey(laptopX) }],
      endpointUri: MEDIATOR_URL, routingKeys: [mediator.xKid], domain: 'alice.example',
    })
    const fetchImpl = (async (input, init) => {
      const url = new URL(String(input))
      if (url.origin === MEDIATOR_URL) return (await handle(new Request(url, init), url)) ?? new Response('not found', { status: 404 })
      if (url.hostname === 'alice.example') return new Response(serializeLog(log))
      return new Response('unexpected', { status: 500 })
    }) as typeof fetch
    const phone = mediatorInbox({ did, xKid: `${did}#k_phone`, xPriv: phoneX }, new Uint8Array(32).fill(1))
    const laptop = mediatorInbox({ did, xKid: `${did}#k_laptop`, xPriv: laptopX }, new Uint8Array(32).fill(2))
    const info = await registerWithMediator(MEDIATOR_URL, phone, fetchImpl)
    await registerWithMediator(MEDIATOR_URL, laptop, fetchImpl)

    await walletVaultSyncTransport(phone, fetchImpl).send({ type: VAULT_SYNC_STATE_REQUEST, body: { summary: {} } })
    expect(store.stats()).toMatchObject({ queuedMessages: 1, pendingDeliveries: 2 })
    const senderKey = async () => x25519.getPublicKey(phoneX)
    for (const device of [phone, laptop]) {
      const [delivered] = await pickupDeliver(info, device, senderKey, 10, fetchImpl)
      expect((delivered!.plaintext as { type: string }).type).toBe(VAULT_SYNC_STATE_REQUEST)
      expect(delivered!.senderKid).toBe(phone.xKid)
    }
  })
})
