// Regression coverage for the durable "this device's earlier history is
// unavailable" flag (store.ts's VaultCheckpointRecoveryStatus), added
// 2026-09-06 after establishing that mimi-vault-sync.ts's own `gaps` entry
// for checkpoint-epoch-unavailable is gone by the very next sync round --
// the delivery cursor already moved past the unopenable manifest, so it is
// never re-pulled. Without a separate durable record, the account page has
// nothing to show across a reload for a state that can otherwise persist
// indefinitely (until a sibling device republishes at the current epoch).
import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { IndexedDbVaultStore } from '../src/client/store/vault/store.ts'

const identityId = 'did:webvh:test:alice.example'
const deviceId = `${identityId}#device-1`

afterEach(async () => {
  await new Promise<void>(resolve => {
    const request = indexedDB.deleteDatabase('biset-vault-core')
    request.onsuccess = request.onerror = request.onblocked = () => resolve()
  })
})

describe('checkpoint recovery status', () => {
  test('starts unavailable: false with no record', async () => {
    const store = await IndexedDbVaultStore.open()
    try {
      expect(await store.readCheckpointRecoveryStatus(identityId, deviceId)).toEqual({ unavailable: false })
    } finally { store.close() }
  })

  test('recordCheckpointEpochUnavailable persists across a fresh store handle', async () => {
    const first = await IndexedDbVaultStore.open()
    try {
      await first.recordCheckpointEpochUnavailable(identityId, deviceId, 'sealed for self-group epoch g/3, this device is at g/5', '2026-09-06T00:00:00.000Z')
    } finally { first.close() }

    // A new handle, not the one that wrote it -- this is the property that
    // matters: the flag must survive a reload, not just the same session.
    const second = await IndexedDbVaultStore.open()
    try {
      const status = await second.readCheckpointRecoveryStatus(identityId, deviceId)
      expect(status.unavailable).toBe(true)
      expect(status.detail).toBe('sealed for self-group epoch g/3, this device is at g/5')
      expect(status.since).toBe('2026-09-06T00:00:00.000Z')
    } finally { second.close() }
  })

  test('the "since" timestamp does not move on a repeated failure', async () => {
    const store = await IndexedDbVaultStore.open()
    try {
      await store.recordCheckpointEpochUnavailable(identityId, deviceId, 'first', '2026-09-06T00:00:00.000Z')
      await store.recordCheckpointEpochUnavailable(identityId, deviceId, 'second', '2026-09-06T01:00:00.000Z')
      const status = await store.readCheckpointRecoveryStatus(identityId, deviceId)
      // The detail can be refreshed to the latest failure, but "since" is
      // when this device FIRST found itself unable to recover -- that is
      // what "how long have I been waiting" on the account-page card means.
      expect(status.detail).toBe('second')
      expect(status.since).toBe('2026-09-06T00:00:00.000Z')
    } finally { store.close() }
  })

  test('advanceDeliveryCursor -- the only path a successful checkpoint restore takes -- clears it', async () => {
    const store = await IndexedDbVaultStore.open()
    try {
      await store.recordCheckpointEpochUnavailable(identityId, deviceId, 'sealed for a past epoch', '2026-09-06T00:00:00.000Z')
      expect((await store.readCheckpointRecoveryStatus(identityId, deviceId)).unavailable).toBe(true)

      await store.advanceDeliveryCursor(identityId, deviceId, '10', 'checkpoint-1', '2026-09-06T02:00:00.000Z')

      expect(await store.readCheckpointRecoveryStatus(identityId, deviceId)).toEqual({ unavailable: false })
      // The cursor itself is not a side effect of the flag bookkeeping --
      // confirm the actual restore still advanced normally.
      expect(await store.readDeliveryCursor(identityId, deviceId)).toBe('10')
    } finally { store.close() }
  })

  test('acknowledgeCheckpointEpochUnavailable clears the flag without touching the cursor', async () => {
    const store = await IndexedDbVaultStore.open()
    try {
      await store.advanceDeliveryCursor(identityId, deviceId, '7', 'checkpoint-0', '2026-09-06T00:00:00.000Z')
      await store.recordCheckpointEpochUnavailable(identityId, deviceId, 'sealed for a past epoch', '2026-09-06T01:00:00.000Z')

      await store.acknowledgeCheckpointEpochUnavailable(identityId, deviceId)

      expect(await store.readCheckpointRecoveryStatus(identityId, deviceId)).toEqual({ unavailable: false })
      // "Continue without it" performs no data operation -- the cursor from
      // before the acknowledgement is untouched, matching the store
      // method's own doc comment.
      expect(await store.readDeliveryCursor(identityId, deviceId)).toBe('7')
    } finally { store.close() }
  })

  test('acknowledging with no prior record at all does not throw', async () => {
    const store = await IndexedDbVaultStore.open()
    try {
      await store.acknowledgeCheckpointEpochUnavailable(identityId, deviceId)
      expect(await store.readCheckpointRecoveryStatus(identityId, deviceId)).toEqual({ unavailable: false })
    } finally { store.close() }
  })
})
