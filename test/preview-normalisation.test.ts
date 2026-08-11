// The conversation list and the thread view must read a message the same way.
//
// They did not: thread.ts ran bodyText through stripQuoted, the left pane's
// fmtPreview did not, and a reply that opened as "test" was listed as
// "test > On Aug 11, 2026, at 7:52, y <y@4r.ma> wrote:". Two renderers, one
// message, two answers.
//
// The assertions are on what a reader sees — no quote marker, no attribution
// line, the actual reply present — rather than on previewText being written
// the way it currently is. Restating the implementation would pass just as
// happily if the shared normalisation were dropped again.
import { previewText, stripQuoted } from '../src/utils.ts'

let failed = 0
function ok(name: string, cond: boolean, got?: unknown) {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond ? '' : `  → ${JSON.stringify(got)}`}`)
  if (!cond) failed++
}

// The message from the report, as the relay stores it.
const REPLY = `test

> On Aug 11, 2026, at 7:52, y <y@4r.ma> wrote:
>
> original message text
`

console.log('=== 引用は一覧のプレビューからも消える ===')
{
  const p = previewText(REPLY)
  ok('返信本文が残る', p.includes('test'), p)
  ok('引用マーカーが出ない', !p.includes('>'), p)
  ok('帰属行が出ない', !p.toLowerCase().includes('wrote'), p)
  ok('日付が漏れない', !p.includes('Aug 11'), p)
  ok('引用本文が漏れない', !p.includes('original message text'), p)
}

console.log('\n=== 一覧とスレッドが同じ正規化を通る ===')
{
  // The property the bug violated: the preview is a shorter view of what the
  // thread renders, not a different reading of it. Anything the preview shows
  // must appear in the thread's own text.
  const thread = stripQuoted(REPLY).replace(/[\r\n\t]+/g, ' ').trim()
  ok('プレビューはスレッド本文の接頭辞', thread.startsWith(previewText(REPLY)), {
    thread,
    preview: previewText(REPLY),
  })
}

console.log('\n=== 全文が引用の返信は空行にしない ===')
{
  const quoteOnly = '> On Aug 11, 2026, at 7:52, y <y@4r.ma> wrote:\n> nothing of my own\n'
  ok('引用しかなくても何か出る', previewText(quoteOnly).length > 0, previewText(quoteOnly))
  ok('stripQuoted 自体は空を返す（＝空対策が効いている）', stripQuoted(quoteOnly) === '')
}

console.log('\n=== 長さと空白 ===')
{
  ok('60 字で切る', previewText('a'.repeat(200)).length === 60)
  ok('改行はスペースになる', previewText('one\ntwo') === 'one two', previewText('one\ntwo'))
  ok('空本文は空', previewText('') === '')
}

console.log(failed === 0 ? '\n  全て通過' : `\n  ${failed} 件失敗`)
if (failed > 0) process.exit(1)
