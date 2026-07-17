// Exercises cloudflare.ts's zone guard + quote handling against a fake
// Cloudflare. Records every outbound request so we can assert what was NOT
// sent — the whole point of the guard is a write that must not happen.
import { CloudflareAnchor } from '../src/anchor/cloudflare.ts'

type Call = { method: string; path: string; body?: any }
let calls: Call[] = []
let zoneRecords: { id: string; name: string; content: string }[] = []

const real = globalThis.fetch
globalThis.fetch = (async (url: any, init: any = {}) => {
  const u = new URL(String(url))
  const path = u.pathname + u.search
  const method = init.method ?? 'GET'
  calls.push({ method, path, body: init.body ? JSON.parse(init.body) : undefined })
  const J = (o: any, status = 200) => new Response(JSON.stringify(o), { status })

  if (/\/zones\/[^/]+$/.test(u.pathname)) return J({ success: true, result: { name: 'biset.md' } })
  if (u.pathname.endsWith('/dns_records') && method === 'GET') {
    const want = u.searchParams.get('name')
    return J({ success: true, result: zoneRecords.filter(r => r.name === want) })
  }
  if (u.pathname.endsWith('/dns_records') && method === 'POST') return J({ success: true, result: { id: 'new' } })
  if (method === 'PATCH') return J({ success: true, result: { id: 'patched' } })
  if (method === 'DELETE') {
    const id = u.pathname.split('/').pop()
    if (!zoneRecords.some(r => r.id === id)) return J({ success: false, errors: [{ message: 'record not found' }] }, 404)
    zoneRecords = zoneRecords.filter(r => r.id !== id)
    return J({ success: true, result: { id } })
  }
  return J({ success: false, errors: [{ message: 'unexpected ' + method + ' ' + path }] }, 400)
}) as any

const cf = new CloudflareAnchor({ apiToken: 'fake', zoneId: 'ZID' })
const DID = 'did:dht:6oien8gcebk6zdy49sj9319wg13zaid1sdpkamb7jp6bw31pkdxo'

let fails = 0
async function check(name: string, fn: () => Promise<void>, expect: (c: Call[], err: string | null) => string | null) {
  calls = []
  let err: string | null = null
  try { await fn() } catch (e: any) { err = e?.message ?? String(e) }
  const problem = expect(calls, err)
  console.log(`  ${problem ? 'FAIL' : 'ok  '}  ${name}${problem ? '\n          → ' + problem : ''}`)
  if (problem) fails++
}

const writes = (c: Call[]) => c.filter(x => x.method === 'POST' || x.method === 'PATCH')

console.log('\n=== ゾーンガード ===')

zoneRecords = []
await check('ゾーン外(orillo.org)は書かない・理由を述べて throw', () => cf.writeAnchorTXT('y', 'orillo.org', DID), (c, err) => {
  if (writes(c).length) return `書き込みが発生: ${JSON.stringify(writes(c))}`
  if (!err) return 'throwしていない'
  if (!err.includes('outside zone biset.md')) return `メッセージが不十分: ${err}`
  return null
})

zoneRecords = []
await check('ゾーン内(biset.md)は新規POSTする', () => cf.writeAnchorTXT('y', 'biset.md', DID), (c, err) => {
  if (err) return `throwした: ${err}`
  const w = writes(c)
  if (w.length !== 1 || w[0].method !== 'POST') return `期待=POST1件、実際=${JSON.stringify(w)}`
  if (w[0].body?.name !== '_did.y.biset.md') return `name違い: ${w[0].body?.name}`
  if (w[0].body?.content !== `did=${DID}`) return `content違い: ${w[0].body?.content}`
  return null
})

zoneRecords = []
await check('サブドメイン(t.biset.md)はゾーン内として通す', () => cf.writeAnchorTXT('aab1', 't.biset.md', DID), (c, err) => {
  if (err) return `throwした: ${err}`
  return writes(c).length === 1 ? null : `期待=書き込み1件、実際=${writes(c).length}`
})

zoneRecords = []
await check('似て非なるドメイン(notbiset.md)は弾く', () => cf.writeAnchorTXT('y', 'notbiset.md', DID), (c, err) => {
  if (writes(c).length) return '書き込みが発生 — サフィックス一致が甘い'
  return err?.includes('outside zone') ? null : `throwしていない: ${err}`
})

console.log('\n=== 引用符の正規化(既存レコードとの比較) ===')

zoneRecords = [{ id: 'r1', name: '_did.y.biset.md', content: `did=${DID}` }]
await check('素の content が一致 → 書き込まない', () => cf.writeAnchorTXT('y', 'biset.md', DID), (c, err) => {
  if (err) return `throwした: ${err}`
  return writes(c).length === 0 ? null : `無駄な書き込み: ${JSON.stringify(writes(c))}`
})

zoneRecords = [{ id: 'r1', name: '_did.y.biset.md', content: `"did=${DID}"` }]
await check('引用符つき content が一致 → 書き込まない(本番 _did.y.biset.md の形)', () => cf.writeAnchorTXT('y', 'biset.md', DID), (c, err) => {
  if (err) return `throwした: ${err}`
  return writes(c).length === 0 ? null : `無駄なPATCHが発生(修正前の挙動): ${JSON.stringify(writes(c))}`
})

zoneRecords = [{ id: 'r1', name: '_did.y.biset.md', content: 'did=did:dht:OLDOLDOLD' }]
await check('content が本当に違う → PATCH する', () => cf.writeAnchorTXT('y', 'biset.md', DID), (c, err) => {
  if (err) return `throwした: ${err}`
  const w = writes(c)
  if (w.length !== 1 || w[0].method !== 'PATCH') return `期待=PATCH1件、実際=${JSON.stringify(w)}`
  return w[0].path.includes('/r1') ? null : `recordID違い: ${w[0].path}`
})

console.log('\n=== release時のTXT削除 ===')

zoneRecords = [{ id: 'r1', name: '_did.gone.t.biset.md', content: `did=${DID}` }]
await check('ゾーン内のレコードをDELETEする', () => cf.deleteAnchorTXT('gone', 't.biset.md'), (c, err) => {
  if (err) return `throwした: ${err}`
  const d = c.filter(x => x.method === 'DELETE')
  if (d.length !== 1) return `期待=DELETE1件、実際=${d.length}`
  return d[0].path.includes('/r1') ? null : `recordID違い: ${d[0].path}`
})

zoneRecords = [
  { id: 'a', name: '_did.dup.t.biset.md', content: 'did=did:dht:AAA' },
  { id: 'b', name: '_did.dup.t.biset.md', content: 'did=did:dht:BBB' },
]
await check('同名重複は全部消す(本番の _did.test.orillo.org.biset.md ×2 の形)', () => cf.deleteAnchorTXT('dup', 't.biset.md'), (c, err) => {
  if (err) return `throwした: ${err}`
  const ids = c.filter(x => x.method === 'DELETE').map(x => x.path.split('/').pop())
  return ids.length === 2 && ids.includes('a') && ids.includes('b') ? null : `消し漏れ: ${JSON.stringify(ids)}`
})

zoneRecords = []
await check('存在しなければ何もしない(冪等)', () => cf.deleteAnchorTXT('never', 't.biset.md'), (c, err) => {
  if (err) return `throwした: ${err}`
  return c.some(x => x.method === 'DELETE') ? 'DELETEが発生' : null
})

zoneRecords = [{ id: 'x', name: '_did.y.orillo.org', content: `did=${DID}` }]
await check('ゾーン外は触らない(我々が公表したものではない)', () => cf.deleteAnchorTXT('y', 'orillo.org'), (c, err) => {
  if (err) return `throwした: ${err}`
  return c.some(x => x.method === 'DELETE') ? 'ゾーン外のレコードを消そうとした' : null
})

console.log('\n=== ゾーン名の取得 ===')
{
  // 新しいインスタンスで測る。使い回すと上のテストで既にキャッシュ済みになり、
  // 「取得が0回」を「キャッシュが効いている」と読み違える。
  const fresh = new CloudflareAnchor({ apiToken: 'fake', zoneId: 'ZID' })
  const zoneCalls = () => calls.filter(c => /\/zones\/[^/?]+$/.test(c.path)).length
  calls = []
  const a = await fresh.zoneName()
  const after1 = zoneCalls()
  await fresh.zoneName()
  const after2 = zoneCalls()
  const ok = a === 'biset.md' && after1 === 1 && after2 === 1
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  初回に1回だけ取得しキャッシュする ` +
    `(name=${a}, 1回目後=${after1}回, 2回目後=${after2}回)`)
  if (!ok) fails++
}
{
  // 失敗はキャッシュしない — 一時的な不達が恒久的な機能停止になってはいけない。
  const flaky = new CloudflareAnchor({ apiToken: 'fake', zoneId: 'BOOM' })
  const saved = globalThis.fetch
  let n = 0
  globalThis.fetch = (async () => {
    n++
    return n === 1
      ? new Response('{}', { status: 500 })
      : new Response(JSON.stringify({ success: true, result: { name: 'biset.md' } }), { status: 200 })
  }) as any
  let firstErr: string | null = null
  try { await flaky.zoneName() } catch (e: any) { firstErr = e.message }
  const recovered = await flaky.zoneName().catch(() => null)
  globalThis.fetch = saved
  const ok = !!firstErr && recovered === 'biset.md'
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  失敗はキャッシュせず次回リトライする (1回目=throw, 2回目=${recovered})`)
  if (!ok) fails++
}

globalThis.fetch = real
console.log(`\n  ${fails === 0 ? '全て通過' : fails + ' 件失敗'}\n`)
process.exit(fails === 0 ? 0 : 1)
