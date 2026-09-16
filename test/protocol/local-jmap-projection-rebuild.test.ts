// Confirms projection-rebuild.ts's `rebuildLocalJmapProjection` actually
// recomputes a local JMAP projection from every event/object an identity
// has stored, using the plain SegmentKeyResolver/VaultEventVerifier pair
// the Wallet-authorized boundary provides -- no MLS self-group involved.
// This is the piece Vault Sync's device-to-device merge needs after landing
// another device's events/objects: merging the CRDT log and object store
// alone never updates the separately-stored projection the inbox actually
// renders from (main.ts's own VAULT_SYNC_UPDATE/STATE_RESPONSE handler).
import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { buildMailMessageAdd } from '../../src/client/store/vault/mail-message.ts'
import { createSegmentKey } from '../../src/client/store/vault/objects.ts'
import type { VaultEventSigner } from '../../src/client/store/vault/events.ts'
import type { SegmentKeyResolver } from '../../src/client/store/vault/segment-key-resolver.ts'
import type { VaultRecordReader } from '../../src/client/store/vault/store.ts'
import { rebuildLocalJmapProjection } from '../../src/client/store/vault/projection-rebuild.ts'

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

describe('rebuildLocalJmapProjection', () => {
  test('rebuilds the projection from every stored event/object, not just one incremental pack', async () => {
    const segmentKey = createSegmentKey()
    const raw = new TextEncoder().encode('From: alice@example.test\r\nSubject: Hello\r\n\r\nmail bytes\r\n')
    const record = await buildMailMessageAdd({
      email: {
        id: 'email-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {},
        receivedAt: '2026-09-15T00:00:00.000Z', subject: 'Hello', size: raw.length,
      },
      rawRfc5322: raw,
    }, {
      identityId, actorDeviceId: 'device-a', actorSeq: 1, parents: [],
      segmentId: 'segment-1', segmentKey, createdAt: '2026-09-15T00:00:00.000Z',
    }, signer)

    const records: VaultRecordReader = {
      async readVaultEvents() { return [{ ...record.event, identityId }] },
      async readVaultObjects() { return [{ ...record.metadataObject, identityId }, { ...record.rawRfc5322Object, identityId }] },
    }
    const resolver: SegmentKeyResolver = { async resolveSegmentKey() { return segmentKey.slice() } }

    const projection = await rebuildLocalJmapProjection({ identityId, records, resolver, verifier: signer })

    expect(projection.version).toBe(1)
    expect(projection.identityId).toBe(identityId)
    expect(projection.emails).toHaveLength(1)
    expect(projection.emails[0]).toMatchObject({ id: 'email-1', subject: 'Hello', threadId: 'thread-1' })
  })

  test('an identity with no stored events yet rebuilds to an empty (not missing) projection', async () => {
    const records: VaultRecordReader = { async readVaultEvents() { return [] }, async readVaultObjects() { return [] } }
    const resolver: SegmentKeyResolver = { async resolveSegmentKey() { throw new Error('must not be called') } }
    const projection = await rebuildLocalJmapProjection({ identityId, records, resolver, verifier: signer })
    expect(projection).toMatchObject({ version: 1, identityId, emails: [] })
  })
})
