import 'fake-indexeddb/auto'
import { expect, test } from 'bun:test'
import { acceptMimiRoomMigration, createMimiRoomMigrationOffer, cutOverMimiRoomMigration, IndexedDbMimiRoomMigrationStore, migrationOfferBody } from '../../src/client/mimi/mimi-room-migration.ts'

test('MIMI migration keeps the old-room mapping local and requires verified cutover', () => {
  const now = new Date('2026-09-01T00:00:00.000Z')
  const { offer, local } = createMimiRoomMigrationOffer('old-local-room', 'mimi://anon.example/r/fresh', now, new Date('2026-09-02T00:00:00.000Z'), 'migration-1')
  expect(migrationOfferBody(offer)).not.toHaveProperty('oldRoomId')
  const accepted = acceptMimiRoomMigration(local, { version: 1, migrationId: 'migration-1', acceptedAt: now.toISOString() }, now)
  expect(() => cutOverMimiRoomMigration(accepted, { version: 1, migrationId: 'migration-1', cutoverAt: now.toISOString() }, false)).toThrow('not locally verified')
  expect(cutOverMimiRoomMigration(accepted, { version: 1, migrationId: 'migration-1', cutoverAt: now.toISOString() }, true)).toMatchObject({ oldRoomId: 'old-local-room', newRoomId: 'mimi://anon.example/r/fresh', status: 'cutover' })
})

test('MIMI migration mapping is retained only in device-local IndexedDB', async () => {
  const now = new Date('2026-09-01T00:00:00.000Z')
  const { local } = createMimiRoomMigrationOffer('old-local-persisted', 'mimi://anon.example/r/persisted', now, new Date('2026-09-02T00:00:00.000Z'), 'migration-2')
  const store = new IndexedDbMimiRoomMigrationStore()
  await store.save(local)
  expect(await store.load('old-local-persisted')).toEqual(local)
  store.close()
})
