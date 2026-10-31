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

test('the mean mix is the channels\' mean, darkened only as far as white needs to read on it', async () => {
  const { mixInk } = await load()
  // Already dark enough: the mean as it is.
  expect(mixInk(['#000000', '#202020'], 4.5, 'mean')).toBe('#101010')
  expect(mixInk(['#000000', '#202020'])).toBe('#101010')
})

test('the hue mix keeps the colour as colourful as the colours, and white reads on it', async () => {
  const { mixInk, partColors } = await load()
  const channel = (hex: string, at: number): number => parseInt(hex.slice(at, at + 2), 16) / 255
  const lin = (unit: number): number => unit <= 0.03928 ? unit / 12.92 : ((unit + 0.055) / 1.055) ** 2.4
  const saturationOf = (hex: string): number => { const [r, g, b] = [1, 3, 5].map(at => channel(hex, at)); const max = Math.max(r!, g!, b!), min = Math.min(r!, g!, b!); return max === min ? 0 : (max - min) / (1 - Math.abs(max + min - 1)) }
  const colors = partColors('avatar')
  for (const contrast of [4.5, 8]) {
    const mixed = mixInk(colors, contrast)
    const [r, g, b] = [1, 3, 5].map(at => lin(channel(mixed, at)))
    expect(1.05 / (0.2126 * r! + 0.7152 * g! + 0.0722 * b! + 0.05)).toBeGreaterThanOrEqual(contrast - 0.1)
    // As colourful as the mean of the colours' saturations, give or take the rounding to #rrggbb.
    const mean = colors.reduce((sum, color) => sum + saturationOf(color), 0) / colors.length
    expect(Math.abs(saturationOf(mixed) - mean)).toBeLessThan(0.05)
  }
  // The channel mean of the same colours is duller.
  expect(saturationOf(mixInk(colors, 8))).toBeGreaterThan(saturationOf(mixInk(colors, 8, 'mean')))
})
