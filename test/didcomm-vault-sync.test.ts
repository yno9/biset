import { describe, expect, test } from 'bun:test'
import { decryptUpdate, encryptUpdate, mediatedVaultSyncTransport, VaultSyncClient, vaultSyncSiblingDevices } from '../src/client/didcomm/vault-sync.ts'
import { encodeVaultSyncChunk, splitVaultSyncPayload, VAULT_SYNC_CHUNK_BYTES } from '../src/client/store/vault/vault-sync-chunks.ts'
import { encodeX25519Multikey } from '../src/protocol/didcomm/multikey.ts'
import { deviceKidFragment } from '../src/protocol/didcomm/devicekid.ts'
import { generatePeerIdentity } from '../src/protocol/didcomm/peer.ts'
import { bytesToBase64url, equalBytes } from '../src/protocol/canonical.ts'
import { VAULT_SYNC_STATE_RESPONSE } from '../src/protocol/didcomm/vault-sync-protocol.ts'
import { encodeVaultDeliveryPack } from '../src/client/store/vault/delivery-pack.ts'
import { createVaultEvent, type VaultEventSigner } from '../src/client/store/vault/events.ts'

describe('Vault Sync DIDComm payloads', () => {
  test('encrypts records with their VCK generation bound as AEAD data', async () => {
    const key = new Uint8Array(32).fill(9)
    const encrypted = await encryptUpdate(new Uint8Array([1, 2, 3]), { generation: '4', key })
    expect(await decryptUpdate(encrypted, { generation: '4', key })).toEqual(new Uint8Array([1, 2, 3]))
    await expect(decryptUpdate(encrypted, { generation: '5', key })).rejects.toThrow('generation')
  })

  test('selects only self-verifying Biset X25519 sibling keys', () => {
    const did = 'did:webvh:example:alice'; const own = new Uint8Array(32).fill(1); const sibling = new Uint8Array(32).fill(2)
    expect(vaultSyncSiblingDevices({ id: did, verificationMethod: [
      { id: deviceKidFragment(own), publicKeyMultibase: encodeX25519Multikey(own) },
      { id: `${did}${deviceKidFragment(sibling)}`, publicKeyMultibase: encodeX25519Multikey(sibling) },
    ] }, `${did}${deviceKidFragment(own)}`)).toEqual([{ kid: `${did}${deviceKidFragment(sibling)}`, publicKey: sibling }])
  })

  test('a maximum-size sync chunk stays below the mediator wire limit after DIDComm packing', async () => {
    const own = generatePeerIdentity({ uri: 'https://sender.example', routingKeys: ['did:peer:2.Vz6MkqRYqQmD9C1vUoGJdYVZ41UKbd8PiW2pD6TqEJqK6fpWsM4xS#key-1'] })
    const recipient = generatePeerIdentity({ uri: 'https://recipient.example', routingKeys: ['did:peer:2.Vz6MkqRYqQmD9C1vUoGJdYVZ41UKbd8PiW2pD6TqEJqK6fpWsM4xS#key-1'] })
    let wireBytes = 0
    const transport = mediatedVaultSyncTransport({ did: own.did, xKid: own.xKid, xPriv: own.xPriv }, async kid => ({ kid, publicKey: recipient.xPub, mediatorUrl: 'https://recipient.example', routingKid: recipient.xKid }), (async (_url, init) => { wireBytes = new TextEncoder().encode(String(init?.body)).length; return new Response(null, { status: 202 }) }) as typeof fetch)
    const [chunk] = splitVaultSyncPayload(crypto.getRandomValues(new Uint8Array(VAULT_SYNC_CHUNK_BYTES)))
    const encrypted = await encryptUpdate(new Uint8Array([1]), { generation: '0', key: new Uint8Array(32) })
    await transport.send(recipient.xKid, { type: VAULT_SYNC_STATE_RESPONSE, body: { ...encrypted, hasMore: false, chunk: bytesToBase64url(encodeVaultSyncChunk(chunk!)) } } as never)
    expect(wireBytes).toBeLessThan(1024 * 1024)
  })
  test('accepts a retained older VCK generation after rotation', async () => {
    const oldKey = new Uint8Array(32).fill(3)
    const body = await encryptUpdate(encodeVaultDeliveryPack({ version: 1, identityId: 'did:example:alice', events: [], objects: [], keyWraps: [] }), { generation: '4', key: oldKey })
    let committed = false
    const store = { async readVaultEvents() { return [] }, async readVaultObjects() { return [] }, async readSegmentKeyWraps() { return [] }, async findDuplicateActorSequences() { return [] }, async commitIncomingRecords() { committed = true; return { addedEventIds: [], targetIds: [] } } }
    const client = new VaultSyncClient('did:example:alice', store, { async verify() { return true } }, { async current() { return { generation: '5', key: new Uint8Array(32).fill(5) } }, async forGeneration(generation) { return generation === '4' ? oldKey.slice() : undefined } }, { async send() {} })
    await client.receive({ type: VAULT_SYNC_STATE_RESPONSE, body: { ...body, hasMore: false } })
    expect(committed).toBe(true)
  })
  test('isolates one invalid event without rejecting valid records in the same batch', async () => {
    const signer: VaultEventSigner = { deviceId: 'device-a', async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) }, async verify(deviceId, bytes, signature) { return deviceId === this.deviceId && equalBytes(signature, await this.sign(bytes)) } }
    const valid = await createVaultEvent({ identityId: 'did:example:alice', actorDeviceId: 'device-a', actorSeq: 1, kind: 'settings.set', targetIds: ['settings'], objectRefs: [], parents: [], createdAt: '2026-01-01T00:00:00.000Z' }, signer)
    const invalid = { ...valid, id: `${valid.id}-tampered`, actorSeq: 2 }
    const key = new Uint8Array(32).fill(8); const body = await encryptUpdate(encodeVaultDeliveryPack({ version: 1, identityId: 'did:example:alice', events: [valid, invalid], objects: [], keyWraps: [] }), { generation: '1', key })
    let accepted = 0
    const store = { async readVaultEvents() { return [] }, async readVaultObjects() { return [] }, async readSegmentKeyWraps() { return [] }, async findDuplicateActorSequences() { return [] }, async commitIncomingRecords(records: { events: unknown[] }) { accepted = records.events.length; return { addedEventIds: [valid.id], targetIds: ['settings'] } } }
    const client = new VaultSyncClient('did:example:alice', store, signer, { async current() { return { generation: '1', key: key.slice() } }, async forGeneration() { return key.slice() } }, { async send() {} })
    const result = await client.receive({ type: VAULT_SYNC_STATE_RESPONSE, body: { ...body, hasMore: false } })
    expect(accepted).toBe(1); expect(result?.skippedEvents).toBe(1)
  })
})
