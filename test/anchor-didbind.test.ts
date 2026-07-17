// The anchor's DID-binding check, against signatures produced by the client's
// own signer (src/did/binding.ts). Three implementations have to agree on one
// byte string — client signs it, go-jmapserver/didbind.go verified it, this now
// does — and a drift between any two means every DID account creation fails.
// So the statement is pinned here explicitly as well as exercised end-to-end.
import { ed25519 } from '@noble/curves/ed25519.js'
import { zbase32Encode } from '../src/did/zbase32.ts'
import { bindingStatement } from '../src/did/binding.ts'
import { verifyDIDBinding, didPublicKey } from '../src/anchor/didbind.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

const priv = ed25519.utils.randomSecretKey()
const pub = ed25519.getPublicKey(priv)
const did = 'did:dht:' + zbase32Encode(pub)
const NOW = 1_752_700_000
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b))
const sign = (stmt: string) => b64(ed25519.sign(new TextEncoder().encode(stmt), priv))

const good = {
  did, username: 'y', relayHost: 'mail.biset.md', bindTs: NOW,
  sigB64: sign(bindingStatement(did, 'y', 'mail.biset.md', NOW)),
}

console.log('\n=== 文言の一致（3実装が同じ1つのバイト列に合意している）===')
ok('client の bindingStatement が Go と同じ形を作る',
  bindingStatement(did, 'y', 'mail.biset.md', NOW) === `bind:${did}:y@mail.biset.md:${NOW}`,
  bindingStatement(did, 'y', 'mail.biset.md', NOW))
ok('DID から公開鍵を復元できる（DID がそのまま鍵）',
  !!didPublicKey(did) && Buffer.from(didPublicKey(did)!).equals(Buffer.from(pub)))
ok('did:dht 以外は鍵を返さない', didPublicKey('did:peer:2.Ez6L') === null)

console.log('\n=== 正常系 ===')
ok('クライアントが署名したものを anchor が検証できる', verifyDIDBinding(good, NOW).ok)

console.log('\n=== 改竄はすべて弾く ===')
for (const [name, mut] of [
  ['username が違う（別アドレスへの流用）', { username: 'z' }],
  ['relayHost が違う（別 relay への再生）', { relayHost: 'mail.evil.md' }],
  ['did が違う（別人の DID を主張）', { did: 'did:dht:' + zbase32Encode(ed25519.getPublicKey(ed25519.utils.randomSecretKey())) }],
  ['bindTs が違う（署名対象がずれる）', { bindTs: NOW - 1 }],
  ['署名が壊れている', { sigB64: b64(new Uint8Array(64)) }],
  ['署名が base64 ですらない', { sigB64: '!!!not base64!!!' }],
] as const) {
  const r = verifyDIDBinding({ ...good, ...mut } as any, NOW)
  ok(name, !r.ok, r.ok ? '通ってしまった' : '')
}

console.log('\n=== 鮮度の窓（捕捉した署名の再生を止める）===')
ok('300秒前は通る', verifyDIDBinding(good, NOW + 300).ok)
ok('301秒前は弾く', !verifyDIDBinding(good, NOW + 301).ok)
ok('未来にずれた時計も同じ窓で扱う（-300 は通る）', verifyDIDBinding(good, NOW - 300).ok)
ok('-301 は弾く', !verifyDIDBinding(good, NOW - 301).ok)
ok('bind_ts 欠落は弾く（NaN を 0 と読んで窓に入れない）',
  !verifyDIDBinding({ ...good, bindTs: NaN }, NOW).ok)

console.log(`\n  ${fails === 0 ? '全て通過' : fails + ' 件失敗'}\n`)
process.exit(fails === 0 ? 0 : 1)
