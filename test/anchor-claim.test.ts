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
const PORT = 18201
const A = `http://127.0.0.1:${PORT}`
const DOMAIN = 't.example'
const HOST = 'mail.example'

// No Cloudflare credential: claims are recorded, no DNS is touched.
const server = startAnchor({
  claims: new ClaimStore(dataDir),
  cloudflare: new CloudflareAnchor({}),
  port: PORT,
  hostname: '127.0.0.1',
})
await Bun.sleep(200)

const claim = (localpart: string, body: object) =>
  fetch(`${A}/identity/${localpart}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: DOMAIN, ...body }),
  })
const byDid = (did: string) => fetch(`${A}/identity/by-did/${did}`)
const addressesOf = async (did: string): Promise<string[]> => {
  const r = await byDid(did)
  return r.status === 200 ? ((await r.json()) as { addresses: string[] }).addresses : []
}

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
ok('by-did が victim を指す', (await addressesOf(victim.did)).join() === `victim@${DOMAIN}`)
ok('DID を伴わない fingerprint のみの主張は証明不要',
  (await claim('plain', { fingerprint: 'envelope-fp' })).status === 201,
  'backfill と envelope rotation には証明すべき identity が無い')

console.log('\n=== 乗っ取り（この穴のために書かれたテスト）===')
// The attacker holds a real account: own fingerprint, no DID of their own.
await claim('attacker', { fingerprint: 'attacker-fp' })
// Exactly what PUT /account/did used to forward: someone else's DID, no proof.
const hijack = await claim('attacker', { fingerprint: 'attacker-fp', did: victim.did })
ok('署名なしで他人の DID は主張できない', hijack.status === 401, `status=${hijack.status}`)
ok('by-did は victim を指したまま', (await addressesOf(victim.did)).join() === `victim@${DOMAIN}`,
  '乗っ取りが通ると、ここに attacker が入る')
ok('attacker 自身の DID なら、署名付きで主張できる',
  (await claim('attacker', { fingerprint: 'attacker-fp', did: attacker.did, ...proofFor(attacker, 'attacker') })).status === 200,
  '塞いだのは他人の DID を騙ることだけで、正当な遅延移行は通る')

console.log('\n=== 1つの DID が複数アドレスを持つ（by-did が全部答える）===')
// mail と AP、あるいは移行前後の旧新 — 1つの identity が複数アドレスを持つのは前提。
const multi = identity()
await claim('multi-a', { did: multi.did, ...proofFor(multi, 'multi-a') })
await claim('multi-b', { did: multi.did, ...proofFor(multi, 'multi-b') })
const both = await addressesOf(multi.did)
ok('両方のアドレスが返る', both.length === 2 && both.includes(`multi-a@${DOMAIN}`) && both.includes(`multi-b@${DOMAIN}`),
  `got ${JSON.stringify(both)} — 1:1 索引だと後勝ちで片方が消える`)
ok('同じ主張の再送で重複しない', await (async () => {
  await claim('multi-a', { did: multi.did, ...proofFor(multi, 'multi-a') })
  return (await addressesOf(multi.did)).length === 2
})())
await fetch(`${A}/identity/multi-a?domain=${DOMAIN}`, { method: 'DELETE' })
ok('片方を release しても、もう片方は残る', (await addressesOf(multi.did)).join() === `multi-b@${DOMAIN}`,
  'DID ごと消すと、生きているアドレスの公表まで巻き添えになる')
await fetch(`${A}/identity/multi-b?domain=${DOMAIN}`, { method: 'DELETE' })
ok('最後の1つが消えたら 404（空配列ではなく）', (await byDid(multi.did)).status === 404)

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
