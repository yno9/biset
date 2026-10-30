// @vitest-environment happy-dom
// Disconnect purges what the app kept in plain storage about an identity, and leaves the screen's own settings.
import { beforeEach, expect, test } from 'vitest'
import { clearPlainStorage } from '../../src/client/app/local-data.ts'

// Node has a localStorage of its own (unusable without a file), which shadows the page's: the test uses plain stand-ins.
class MemoryStorage implements Storage {
  private entries = new Map<string, string>();
  [name: string]: unknown
  get length(): number { return this.entries.size }
  key(index: number): string | null { return [...this.entries.keys()][index] ?? null }
  getItem(key: string): string | null { return this.entries.get(key) ?? null }
  setItem(key: string, value: string): void { this.entries.set(key, String(value)) }
  removeItem(key: string): void { this.entries.delete(key) }
  clear(): void { this.entries.clear() }
}
const local = new MemoryStorage()
const session = new MemoryStorage()
Object.defineProperty(globalThis, 'localStorage', { value: local, configurable: true })
Object.defineProperty(globalThis, 'sessionStorage', { value: session, configurable: true })

const keysOf = (store: Storage): string[] => Array.from({ length: store.length }, (_, index) => store.key(index)!).sort()

beforeEach(() => { local.clear(); session.clear() })

test('the records about the identity are gone, the screen settings stay', () => {
  for (const key of ['biset.did-links', 'biset.vh-places', 'biset.log-versions', 'biset.profileSent.did:vh:abc', 'lp-width', 'lp-open', 'biset.dito-frame-height', 'other-site-key']) local.setItem(key, '1')
  for (const key of ['biset:pending-send', 'biset:page', 'biset-did-md-just-connected-v1', 'unrelated']) session.setItem(key, '1')
  clearPlainStorage()
  expect(keysOf(local)).toEqual(['biset.dito-frame-height', 'lp-open', 'lp-width', 'other-site-key'])
  expect(keysOf(session)).toEqual(['unrelated'])
})
