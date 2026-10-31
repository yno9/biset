// @vitest-environment happy-dom
import { beforeEach, expect, test, vi } from 'vitest'

// Node has a localStorage of its own (unusable without a file), which shadows the page's: the test uses a plain stand-in.
const entries = new Map<string, string>()
const memory = { getItem: (key: string) => entries.get(key) ?? null, setItem: (key: string, value: string) => { entries.set(key, String(value)) }, removeItem: (key: string) => { entries.delete(key) }, clear: () => { entries.clear() } }
Object.defineProperty(globalThis, 'localStorage', { value: memory, configurable: true })

const load = async () => { vi.resetModules(); return import('../../src/client/app/ui/color-settings.ts') }

beforeEach(() => { localStorage.clear() })

test('a part has its defaults until colours are chosen, and a choice is kept and can be taken back', async () => {
  const colors = await load()
  const defaults = colors.partColors('avatar')
  expect(defaults).toHaveLength(5)
  const chosen = ['#111111', '#222222', '#333333', '#444444', '#555555']
  colors.setPartColors('avatar', chosen)
  expect(colors.partColors('avatar')).toEqual(chosen)
  // Kept: a page loaded after it reads it back.
  expect((await load()).partColors('avatar')).toEqual(chosen)
  colors.resetPartColors('avatar')
  expect(colors.partColors('avatar')).toEqual(defaults)
  expect((await load()).partColors('avatar')).toEqual(defaults)
})

test('what is stored but is not five #rrggbb colours is not used', async () => {
  const defaults = (await load()).partColors('avatar')
  for (const bad of [['#111111'], ['red', '#222222', '#333333', '#444444', '#555555'], 'nonsense', { avatar: 1 }]) {
    localStorage.setItem('biset.colors', JSON.stringify({ avatar: bad }))
    expect((await load()).partColors('avatar')).toEqual(defaults)
  }
  localStorage.setItem('biset.colors', '{not json')
  expect((await load()).partColors('avatar')).toEqual(defaults)
})
