import 'fake-indexeddb/auto'
import { describe, expect, test } from 'bun:test'
import { IndexedDbDidCommGroupChatStore } from '../../src/shared/didcomm/group-chat-store.ts'

describe('IndexedDbDidCommGroupChatStore', () => {
  test('save then load round-trips a roster', async () => {
    const store = new IndexedDbDidCommGroupChatStore()
    try {
      await store.save({ groupId: 'g1', name: 'Project Chat', members: ['did:web:alice.example', 'did:web:bob.example'], createdAt: '2026-09-02T00:00:00.000Z', updatedAt: '2026-09-02T00:00:00.000Z' })
      const loaded = await store.load('g1')
      expect(loaded).toEqual({ groupId: 'g1', name: 'Project Chat', members: ['did:web:alice.example', 'did:web:bob.example'], createdAt: '2026-09-02T00:00:00.000Z', updatedAt: '2026-09-02T00:00:00.000Z' })
      expect(await store.listGroupIds()).toEqual(['g1'])
    } finally {
      store.close()
    }
  })

  test('load returns undefined for an unknown group', async () => {
    const store = new IndexedDbDidCommGroupChatStore()
    try {
      expect(await store.load('nope')).toBeUndefined()
    } finally {
      store.close()
    }
  })

  test('merge unions members into an existing roster without dropping the name', async () => {
    const store = new IndexedDbDidCommGroupChatStore()
    try {
      await store.save({ groupId: 'g2', name: 'Team', members: ['did:web:alice.example'], createdAt: '2026-09-02T00:00:00.000Z', updatedAt: '2026-09-02T00:00:00.000Z' })
      await store.merge('g2', { members: ['did:web:bob.example'], updatedAt: '2026-09-02T00:05:00.000Z' })
      const loaded = await store.load('g2')
      expect(loaded?.name).toBe('Team')
      expect(loaded?.members.sort()).toEqual(['did:web:alice.example', 'did:web:bob.example'])
      expect(loaded?.createdAt).toBe('2026-09-02T00:00:00.000Z')
      expect(loaded?.updatedAt).toBe('2026-09-02T00:05:00.000Z')
    } finally {
      store.close()
    }
  })

  test('merge on an unknown group creates it', async () => {
    const store = new IndexedDbDidCommGroupChatStore()
    try {
      await store.merge('g3', { members: ['did:web:alice.example', 'did:web:bob.example'], name: 'New Group', updatedAt: '2026-09-02T00:00:00.000Z' })
      const loaded = await store.load('g3')
      expect(loaded).toEqual({ groupId: 'g3', name: 'New Group', members: ['did:web:alice.example', 'did:web:bob.example'], createdAt: '2026-09-02T00:00:00.000Z', updatedAt: '2026-09-02T00:00:00.000Z' })
    } finally {
      store.close()
    }
  })

  test('merge called twice with the identical patch is idempotent (redelivered-invite case)', async () => {
    const store = new IndexedDbDidCommGroupChatStore()
    try {
      const patch = { members: ['did:web:alice.example', 'did:web:bob.example', 'did:web:carol.example'], name: 'Trio', updatedAt: '2026-09-02T00:00:00.000Z' }
      await store.merge('g4', patch)
      const first = await store.load('g4')
      await store.merge('g4', patch)
      const second = await store.load('g4')
      expect(second).toEqual(first)
      expect(second?.members.length).toBe(3)
    } finally {
      store.close()
    }
  })
})
