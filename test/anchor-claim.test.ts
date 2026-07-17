// The claim endpoint's gate: naming a DID requires proving it.
//
// This exists because the rule was once only half there. The proof was checked
// when sent and skipped when absent, and PUT /account/did never sent one — so
// an ordinary self-service account could bind a stranger's DID to its own
// address and have the anchor publish a `_did` TXT record saying so. Basic Auth
// proved the caller owned an *account*; nothing proved they owned an
// *identity*. The hijack is replayed below and must stay a 401.
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ed25519 } from '@noble/curves/ed25519.js'
import { zbase32Encode } from '../src/did/zbase32.ts'
import { signBinding } from '../src/did/binding.ts'
import { ClaimStore } from '../src/anchor/store.ts'
import { CloudflareAnchor } from '../src/anchor/cloudflare.ts'
import { startAnchor } from '../src/anchor/server.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

const dataDir = mkdtempSync(join(tmpdir(), 'anchor-claim-'))
const store = new ClaimStore(dataDir)
const PORT = 18201
const A = `http://127.0.0.1:${PORT}`
const DOMAIN = 't.example'
const HOST = 'mail.example'

// No Cloudflare credential: claims are recorded, no DNS is touched.
const TOKEN = 'test-relay-token'
const server = startAnchor({
  claims: store,
  cloudflare: new CloudflareAnchor({}),
  port: PORT,
  hostname: '127.0.0.1',
  relayToken: TOKEN,
})
await Bun.sleep(200)

const claim = (localpart: string, body: object) =>
  fetch(`${A}/identity/${localpart}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TOKEN}` },
    body: JSON.stringify({ domain: DOMAIN, ...body }),
  })
// Read through the store, not HTTP: the anchor has no read routes. They had no
// caller — the client asks DNS for address→DID, on purpose — so they were a
// public surface answering nobody.
const addressesOf = (did: string): string[] =>
  store.lookupByDid(did).map(l => `${l.localpart}@${l.domain}`)

const identity = () => {
  const priv = ed25519.utils.randomSecretKey()
  return { priv, did: 'did:dht:' + zbase32Encode(ed25519.getPublicKey(priv)) }
}
const proofFor = (id: ReturnType<typeof identity>, username: string) => {
  const p = signBinding(id.priv, id.did, username, HOST)
  return { did_sig: p.sig, bind_ts: p.ts, host: HOST }
}

const victim = identity()
const attacker = identity()

console.log('\n=== 正当な主張は通る ===')
ok('署名付きで DID を主張できる', (await claim('victim', { did: victim.did, ...proofFor(victim, 'victim') })).status === 201)
ok('同じ主張の再送は冪等', (await claim('victim', { did: victim.did, ...proofFor(victim, 'victim') })).status === 200)
ok('索引が victim を指す', addressesOf(victim.did).join() === `victim@${DOMAIN}`)
ok('DID を伴わない主張は 400（もう claim するものが無い）',
  (await claim('plain', { fingerprint: 'envelope-fp' })).status === 400,
  'fingerprint は消えた — claim は DID を名指すもので、DID の無い主張は無内容')

console.log('\n=== 乗っ取り（この穴のために書かれたテスト）===')
// The client posts victim's DID against a name it does not own, with no proof —
// exactly what PUT /account/did used to forward before it carried a signature.
const hijack = await claim('attacker', { did: victim.did })
ok('署名なしで他人の DID は主張できない', hijack.status === 401, `status=${hijack.status}`)
ok('索引は victim を指したまま', addressesOf(victim.did).join() === `victim@${DOMAIN}`,
  '乗っ取りが通ると、ここに attacker が入る')
ok('attacker 自身の DID なら、署名付きで主張できる',
  (await claim('attacker', { did: attacker.did, ...proofFor(attacker, 'attacker') })).status === 201,
  '塞いだのは他人の DID を騙ることだけ')

console.log('\n=== 1つの DID が複数アドレスを持つ（索引が全部持つ）===')
// mail と AP、あるいは移行前後の旧新 — 1つの identity が複数アドレスを持つのは前提。
const multi = identity()
await claim('multi-a', { did: multi.did, ...proofFor(multi, 'multi-a') })
await claim('multi-b', { did: multi.did, ...proofFor(multi, 'multi-b') })
const both = addressesOf(multi.did)
ok('両方のアドレスが返る', both.length === 2 && both.includes(`multi-a@${DOMAIN}`) && both.includes(`multi-b@${DOMAIN}`),
  `got ${JSON.stringify(both)} — 1:1 索引だと後勝ちで片方が消える`)
ok('同じ主張の再送で重複しない', await (async () => {
  await claim('multi-a', { did: multi.did, ...proofFor(multi, 'multi-a') })
  return addressesOf(multi.did).length === 2
})())
await fetch(`${A}/identity/multi-a?domain=${DOMAIN}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${TOKEN}` } })
ok('片方を release しても、もう片方は残る', addressesOf(multi.did).join() === `multi-b@${DOMAIN}`,
  'DID ごと消すと、生きているアドレスの公表まで巻き添えになる')
await fetch(`${A}/identity/multi-b?domain=${DOMAIN}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${TOKEN}` } })
ok('最後の1つが消えたら索引から消える', addressesOf(multi.did).length === 0)

console.log('\n=== relay 以外は書けない（この穴のために書かれたテスト）===')
// The anchor is on the public internet — its DIDComm mediator has to be. A
// signature proves control of a DID, but not that the caller is a relay allowed
// to write here; before the relay token, "can reach it" was the whole story, so
// a valid signature from anyone was enough to squat, and an unauthenticated
// DELETE was enough to steal.
{
  const noAuth = (init: RequestInit) => fetch(`${A}/identity/victim?domain=${DOMAIN}`, init)
  const sq = identity()
  const sqProof = proofFor(sq, 'zzsquat')
  const squat = await fetch(`${A}/identity/zzsquat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: DOMAIN, did: sq.did, ...sqProof }),
  })
  ok('トークン無しなら、正しい署名を持っていても claim できない', squat.status === 403, `status=${squat.status}`)
  ok('実際に claim されていない', addressesOf(sq.did).length === 0)

  const wrong = await fetch(`${A}/identity/zzsquat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer wrong-token' },
    body: JSON.stringify({ domain: DOMAIN, did: sq.did, ...sqProof }),
  })
  ok('違うトークンでも claim できない', wrong.status === 403)

  ok('トークン無しで他人の claim を DELETE できない', (await noAuth({ method: 'DELETE' })).status === 403,
    '無認証の DELETE は、claim を持ち主から奪い DNS ごと消す手口そのもの')
  ok('victim の claim は無事', addressesOf(victim.did).join() === `victim@${DOMAIN}`)

  // Reads used to be open "by design". They answered nobody: the client never
  // learns the anchor's URL and asks DNS for address→DID, precisely so a
  // stranger's operator does not learn who is looking them up. A public surface
  // with no caller is only something to defend.
  ok('正引きの読み取りルートは無い', (await fetch(`${A}/identity/victim?domain=${DOMAIN}`)).status === 404,
    'address→DID は DNS が答える — anchor に聞くと相手の operator に足がつく')
  ok('by-did の読み取りルートも無い', (await fetch(`${A}/identity/by-did/${victim.did}`)).status === 404)
  ok('トークンを持っていても読めない（ルート自体が無い）', await (async () => {
    const r = await fetch(`${A}/identity/victim?domain=${DOMAIN}`, { headers: { 'Authorization': `Bearer ${TOKEN}` } })
    return r.status === 404
  })(), '認可の問題ではなく、存在しない')
}

console.log('\n=== 証明が壊れている場合 ===')
ok('改竄した署名は 401',
  (await claim('zz1', { did: victim.did, ...proofFor(victim, 'zz1'), did_sig: 'AAAA' })).status === 401)
ok('別の名前に対する署名は 401',
  (await claim('zz2', { did: victim.did, ...proofFor(victim, 'someone-else') })).status === 401,
  '文言に username が入っているため')
ok('別のホストに対する署名は 401',
  (await claim('zz3', { did: victim.did, ...proofFor(victim, 'zz3'), host: 'evil.example' })).status === 401,
  'これが replay 防御そのもの')
ok('期限切れの署名は 401', await (async () => {
  const p = signBinding(victim.priv, victim.did, 'zz4', HOST, Math.floor(Date.now() / 1000) - 5000)
  return (await claim('zz4', { did: victim.did, did_sig: p.sig, bind_ts: p.ts, host: HOST })).status === 401
})())

console.log(fails ? `\n${fails} 件 FAILED` : '\n全て通過 — 署名なしで他人の DID は主張できない')
server.stop(true)
rmSync(dataDir, { recursive: true, force: true })
process.exit(fails ? 1 : 0)
