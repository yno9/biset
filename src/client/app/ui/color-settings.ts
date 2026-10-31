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
