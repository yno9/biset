import { expect, test } from 'vitest'
import { extractPlainTextBody } from '../src/client/app/ui/message/body-text.ts'

const body = (text: string) => extractPlainTextBody(new TextEncoder().encode(text))

test('a chat message keeps its first paragraph, whatever follows the blank line', () => {
  expect(body('たなな\n\n-- \nsig')).toBe('たなな\n\n-- \nsig')
  expect(body('Re: hello\n\nbody')).toBe('Re: hello\n\nbody')
})

test('an empty header block (the feed and the notice) leaves the text alone', () => {
  expect(body('\n\nたなな\n\nsig')).toBe('たなな\n\nsig')
  expect(body('X-Source-Url: https://example.org/a\n\nたなな')).toBe('たなな')
})

test('a real MIME entity is still decoded', () => {
  expect(body('Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n44Gf44Gq44Gq')).toBe('たなな')
})
