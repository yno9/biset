// The gateway's disk behaviour and its wire format. Not the DHT: that cannot be
// faked, and the port was verified against the real one from a host that can
// reach it (ANCHOR.md, pkarr吸収). What's pinned here is what a unit test can
// actually hold — the two things that fail silently.
import { mkdtempSync, rmSync, existsSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ed25519 } from '@noble/curves/ed25519.js'
import { PayloadStore, splitPayload, joinPayload } from '../src/anchor/pkarr.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

const dir = mkdtempSync(join(tmpdir(), 'pkarr-store-'))

console.log('\n=== ワイヤ形式（Go ゲートウェイと同じ 1 つのバイト列）===')
{
  const sig = Buffer.alloc(64, 7)
  const v = Buffer.from('a compressed DNS packet')
  const payload = joinPayload(sig, 1784261266, v)
  ok('sig(64) ‖ seq(8) ‖ v の順で並ぶ', payload.length === 64 + 8 + v.length)
  ok('seq はビッグエンディアン', payload.readBigUInt64BE(64) === 1784261266n,
    'Go は binary.BigEndian.PutUint64 で書く — リトルにすると本番の全レコードが壊れる')
  const p = splitPayload(payload)
  ok('split は join を巻き戻す', !!p && p.seq === 1784261266 && p.v.equals(v) && p.sig.equals(sig))
  ok('ヘッダより短い本文は null（例外ではなく）', splitPayload(Buffer.alloc(10)) === null,
    'HTTP 400 にする材料であって、ゲートウェイを落とす理由ではない')
}

console.log('\n=== republish 集合はプロセスをまたぐ（これが無いと再起動で公開が黙って止まる）===')
{
  const store = new PayloadStore(dir)
  ok('初回起動は空（ディレクトリすら無い）', store.load().size === 0)

  const key = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
  const hex = Buffer.from(key).toString('hex')
  const payload = joinPayload(Buffer.alloc(64, 9), 42, Buffer.from('record'))
  store.put(hex, payload)

  // A different instance = what the next process sees.
  const reloaded = new PayloadStore(dir).load()
  ok('再起動後も残っている', reloaded.size === 1 && !!reloaded.get(hex))
  ok('バイトがそのまま戻る', !!reloaded.get(hex)?.equals(payload),
    '再公開は署名済みの元バイトを一字一句そのまま出す — 作り直せない')

  store.put(hex, joinPayload(Buffer.alloc(64, 9), 43, Buffer.from('newer')))
  const after = new PayloadStore(dir).load()
  ok('同じ鍵の新しい seq は上書きする（増殖しない）', after.size === 1)
  ok('新しい方が残る', splitPayload(after.get(hex)!)?.seq === 43)

  store.drop(hex)
  ok('drop でディスクからも消える', new PayloadStore(dir).load().size === 0)
  ok('ファイルが実際に無い', !existsSync(join(dir, hex)),
    'メモリからだけ消すと、再起動が「忘れろ」と言われた identity を蘇らせる')
}

console.log('\n=== 壊れた入力で起動を諦めない ===')
{
  const d2 = mkdtempSync(join(tmpdir(), 'pkarr-broken-'))
  const good = 'aa'.repeat(32)
  mkdirSync(d2, { recursive: true })
  writeFileSync(join(d2, good), joinPayload(Buffer.alloc(64, 1), 1, Buffer.from('x')))
  mkdirSync(join(d2, 'a-directory-somehow')) // readFileSync will throw on this
  const loaded = new PayloadStore(d2).load()
  ok('読めない項目は飛ばし、残りは載せる', loaded.size === 1 && loaded.has(good),
    '1 件の壊れた項目で anchor が起動しないのは、その 1 件より高くつく')
  rmSync(d2, { recursive: true, force: true })
}

rmSync(dir, { recursive: true, force: true })
console.log(fails ? `\n${fails} 件 FAILED` : '\n全て通過 — republish 集合は再起動を越える')
process.exit(fails ? 1 : 0)
