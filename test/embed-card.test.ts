import { existsSync, readFileSync } from 'node:fs'
import { expect, test } from 'vitest'

// The cards over a page share one stylesheet: dito keeps it, comail copies it at build time (pnpm sync:embed-card). A copy that
// differs from dito's is a card that looks different.
const DITO = new URL('../../dito/public/embed-card.css', import.meta.url)
const COPY = new URL('../src/client/app/embed-card.css', import.meta.url)

test.skipIf(!existsSync(DITO))('the embed-card.css comail has is dito\'s', () => {
  expect(readFileSync(COPY, 'utf8')).toBe(readFileSync(DITO, 'utf8'))
})

test('the stylesheet has the box, the card, the title, the input and the button', () => {
  const css = readFileSync(COPY, 'utf8')
  for (const name of ['.ec-dialog', '.ec-card', '.ec-title', '.ec-input', '.ec-button', '--ec-radius']) expect(css).toContain(name)
})
