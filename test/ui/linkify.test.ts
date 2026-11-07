import { expect, test } from 'vitest'
import { esc, linkify } from '../../src/client/app/ui/format.ts'

const links = (text: string) => [...linkify(esc(text)).matchAll(/href="([^"]*)"/g)].map(match => match[1])

test('a path is a link only where it starts a word', () => {
  expect(links('this and/or that')).toEqual([])
  expect(links('/alice@example.com')).toEqual(['/alice@example.com'])
  expect(links('see /alice@example.com\n/bob@example.com')).toEqual(['/alice@example.com', '/bob@example.com'])
})

test('an https URL is a link, and nothing escaped becomes markup', () => {
  expect(links('go https://example.com/a?b=1&c=2 now')).toEqual(['https://example.com/a?b=1&amp;c=2'])
  expect(linkify(esc('<img src=x onerror=alert(1)> "https://x.example/"onmouseover="a"'))).not.toMatch(/<img|" onmouseover/)
})
