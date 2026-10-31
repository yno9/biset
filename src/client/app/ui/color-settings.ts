// The colours a person may choose for parts of the screen. A part has a name, a label and the colours it has when nothing was chosen; what was
// chosen is kept in this browser (localStorage), for this device only, and a screen that draws the part reads it through `usePartColors`.
// The avatar is the first part; another is one more entry of COLOR_PARTS.
import { createStore, useStore } from '../react/store.ts'
import { AVATAR_COLORS } from './format.ts'

export interface ColorPart { id: string; label: string; defaults: readonly string[] }

export const COLOR_PARTS: readonly ColorPart[] = [
  { id: 'avatar', label: 'Avatar', defaults: AVATAR_COLORS },
]

const KEY = 'biset.colors'
const HEX = /^#[0-9a-f]{6}$/i

/** What was chosen, by part; a part with nothing here has its defaults. */
type Chosen = Readonly<Record<string, readonly string[]>>

function read(): Chosen {
  try {
    const stored = JSON.parse(localStorage.getItem(KEY) ?? '{}') as Record<string, unknown>
    const chosen: Record<string, readonly string[]> = {}
    for (const part of COLOR_PARTS) {
      const colors = stored[part.id]
      // A value that is not as many colours as the part has, each one a #rrggbb, was not written by this screen: it is not used.
      if (Array.isArray(colors) && colors.length === part.defaults.length && colors.every(color => typeof color === 'string' && HEX.test(color))) chosen[part.id] = colors as string[]
    }
    return chosen
  } catch { return {} }
}

const chosen = createStore<Chosen>(read())

function write(next: Chosen): void {
  chosen.set(next)
  try { localStorage.setItem(KEY, JSON.stringify(next)) } catch { /* private browsing: the choice lasts until the page is closed */ }
}

const defaultsOf = (id: string): readonly string[] => COLOR_PARTS.find(part => part.id === id)?.defaults ?? []

/** The colours of a part: those chosen, else its defaults. */
export const partColors = (id: string): readonly string[] => chosen.get()[id] ?? defaultsOf(id)

export function usePartColors(id: string): readonly string[] {
  return useStore(chosen)[id] ?? defaultsOf(id)
}

export const setPartColors = (id: string, colors: readonly string[]): void => write({ ...chosen.get(), [id]: colors })

export function resetPartColors(id: string): void {
  const { [id]: _dropped, ...rest } = chosen.get()
  write(rest)
}

/** Whether a part has colours of the person's own choosing. */
export const usePartChosen = (id: string): boolean => id in useStore(chosen)

const channels = (hex: string): number[] => [1, 3, 5].map(at => parseInt(hex.slice(at, at + 2), 16))
function luminance([red, green, blue]: number[]): number {
  const linear = (value: number): number => { const unit = value / 255; return unit <= 0.03928 ? unit / 12.92 : ((unit + 0.055) / 1.055) ** 2.4 }
  return 0.2126 * linear(red!) + 0.7152 * linear(green!) + 0.0722 * linear(blue!)
}

const hex = (rgb: number[]): string => `#${rgb.map(value => Math.round(Math.min(255, Math.max(0, value))).toString(16).padStart(2, '0')).join('')}`
const whiteContrast = (rgb: number[]): number => 1.05 / (luminance(rgb) + 0.05)

function toHsl([red, green, blue]: number[]): { hue: number; saturation: number; lightness: number } {
  const [r, g, b] = [red! / 255, green! / 255, blue! / 255]
  const max = Math.max(r, g, b), min = Math.min(r, g, b), delta = max - min
  const lightness = (max + min) / 2
  const saturation = delta === 0 ? 0 : delta / (1 - Math.abs(2 * lightness - 1))
  const hue = delta === 0 ? 0 : (max === r ? ((g - b) / delta) % 6 : max === g ? (b - r) / delta + 2 : (r - g) / delta + 4) * 60
  return { hue: (hue + 360) % 360, saturation, lightness }
}
function fromHsl(hue: number, saturation: number, lightness: number): number[] {
  const chroma = (1 - Math.abs(2 * lightness - 1)) * saturation
  const f = (n: number): number => { const k = (n + hue / 30) % 12; return lightness - (chroma / 2) * Math.max(-1, Math.min(k - 3, 9 - k, 1)) }
  return [f(0), f(8), f(4)].map(value => value * 255)
}

/** Colours (#rrggbb each) mixed into one that white text reads on (a contrast of `contrast` to 1).
 *  - 'hue' (the default): the hue is the mean of the hues (each counted by its saturation), the saturation and the lightness are the means, and the
 *    lightness is then lowered as far as white needs. Colours that are far apart in hue do not grey one another out, as they do in a mean of channels.
 *  - 'mean': the mean of the channels, darkened toward black as far as white needs. A mix of bright, different colours is a light, dull one. */
export function mixInk(colors: readonly string[], contrast = 4.5, method: 'hue' | 'mean' = 'hue'): string {
  const all = colors.map(color => channels(color))
  if (method === 'mean') {
    const mean = [0, 1, 2].map(at => all.reduce((sum, rgb) => sum + rgb[at]!, 0) / all.length)
    let rgb = mean
    for (let scale = 1; whiteContrast(rgb) < contrast && scale > 0; scale -= 0.02) rgb = mean.map(value => value * scale)
    return hex(rgb)
  }
  const hsl = all.map(toHsl)
  const x = hsl.reduce((sum, { hue, saturation }) => sum + saturation * Math.cos(hue * Math.PI / 180), 0)
  const y = hsl.reduce((sum, { hue, saturation }) => sum + saturation * Math.sin(hue * Math.PI / 180), 0)
  const hue = (Math.atan2(y, x) * 180 / Math.PI + 360) % 360
  const saturation = hsl.reduce((sum, color) => sum + color.saturation, 0) / hsl.length
  let lightness = hsl.reduce((sum, color) => sum + color.lightness, 0) / hsl.length
  while (whiteContrast(fromHsl(hue, saturation, lightness)) < contrast && lightness > 0) lightness -= 0.01
  return hex(fromHsl(hue, saturation, Math.max(0, lightness)))
}
