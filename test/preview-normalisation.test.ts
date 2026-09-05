// The conversation list and the thread view must read a message the same way.
//
// They did not: thread.ts ran bodyText through stripQuoted, the left pane's
// fmtPreview did not, and a reply that opened as "test" was listed as
// "test > On Aug 11, 2026, at 7:52, y <y@4r.ma> wrote:". Two renderers, one
// message, two answers.
//
// The assertions are on what a reader sees -- no quote marker, no attribution
// line, the actual reply present -- rather than on previewText being written
// the way it currently is. Restating the implementation would pass just as
// happily if the shared normalisation were dropped again.
//
// Imports ui/format.ts, which is what left-pane.ts and thread.ts actually
// call (2026-09-05). It used to import src/utils.ts -- a copy of the same
// helpers that no production module had referenced since ui/format.ts was
// split out, so this file was guarding the dead copy: ui/format.ts could
// regress on exactly the bug above and these assertions would still pass.
// The dead copy is gone; this now tests the code that ships.
//
// Rewritten onto bun:test's own API at the same time. The hand-rolled
// `ok()`/console.log harness it used before reported "Ran 0 tests" to
// `bun run test`, so a failure here was invisible in the suite summary.
import { describe, expect, test } from 'bun:test'
import { previewText, stripQuoted } from '../src/client/app/ui/format.ts'

// The message from the report, as the relay stores it.
const REPLY = `test

> On Aug 11, 2026, at 7:52, y <y@4r.ma> wrote:
>
> original message text
`

describe('引用は一覧のプレビューからも消える', () => {
  test('返信本文だけが残る', () => {
    const preview = previewText(REPLY)
    expect(preview).toContain('test')
    expect(preview).not.toContain('>')
    expect(preview.toLowerCase()).not.toContain('wrote')
    expect(preview).not.toContain('Aug 11')
    expect(preview).not.toContain('original message text')
  })
})

describe('一覧とスレッドが同じ正規化を通る', () => {
  // The property the bug violated: the preview is a shorter view of what the
  // thread renders, not a different reading of it. Anything the preview shows
  // must appear in the thread's own text.
  test('プレビューはスレッド本文の接頭辞', () => {
    const thread = stripQuoted(REPLY).replace(/[\r\n\t]+/g, ' ').trim()
    expect(thread.startsWith(previewText(REPLY))).toBe(true)
  })
})

describe('全文が引用の返信は空行にしない', () => {
  const quoteOnly = '> On Aug 11, 2026, at 7:52, y <y@4r.ma> wrote:\n> nothing of my own\n'
  test('引用しかなくても何か出る', () => {
    expect(previewText(quoteOnly).length).toBeGreaterThan(0)
  })
  test('stripQuoted 自体は空を返す（＝空対策が効いている）', () => {
    expect(stripQuoted(quoteOnly)).toBe('')
  })
})

describe('長さと空白', () => {
  test('60 字で切る', () => { expect(previewText('a'.repeat(200)).length).toBe(60) })
  test('改行はスペースになる', () => { expect(previewText('one\ntwo')).toBe('one two') })
  test('空本文は空', () => { expect(previewText('')).toBe('') })
})
