// The anchor's DID-binding check, against signatures produced by the client's
// own signer (src/did/binding.ts). Three implementations have to agree on one
// byte string — client signs it, go-jmapserver/didbind.go verified it, this now
// does — and a drift between any two means every DID account creation fails.
// So the statement is pinned here explicitly as well as exercised end-to-end.
//
// did:dht is retired (see PLANWEBVH.md); did:webvh is the only method, so
// every check below runs against a real webvh log — a did:webvh root key
// only lives in a resolved document, unlike did:dht where the DID was the
// key, so verifyDIDBinding needs a live rootKeyResolver (regression test for
// the 401 "not a did:dht identifier" bug hit when #new's did:webvh account
// creation first went through provisionAccount).
import { ed25519 } from '@noble/curves/ed25519.js'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { bindingStatement } from '../src/did/binding.ts'
import { verifyDIDBinding, rootKeyResolver } from '../src/anchor/didbind.ts'
import { startAnchor } from '../src/anchor/server.ts'
import { ClaimStore } from '../src/anchor/store.ts'
import { WebvhLogStore } from '../src/anchor/webvh-store.ts'
import { createGenesis } from '../src/did/webvh/publish.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

const NOW = 1_752_700_000
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b))
const sign = (priv: Uint8Array, stmt: string) => b64(ed25519.sign(new TextEncoder().encode(stmt), priv))

const dataDir = mkdtempSync(join(tmpdir(), 'anchor-didbind-webvh-'))
const PORT = 18511
startAnchor({
  claims: new ClaimStore(dataDir),
  port: PORT,
  hostname: '127.0.0.1',
  relayToken: 'test-relay-token',
  webvh: new WebvhLogStore(dataDir),
})
await Bun.sleep(200)

// The client resolves a did:webvh log over HTTPS at its own domain; this
// redirects that fetch to the anchor under test, the same way server.ts's own
// POST handler resolves against the log the client just PUT.
const REAL_FETCH = globalThis.fetch
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
  const m = /^https:\/\/([^/]+)(\/[^/]+\/(?:did\.jsonl|routing\.json).*)$/.exec(url)
  if (!m) return REAL_FETCH(input as any, init)
  const [, domain, path] = m
  const headers = new Headers(init?.headers)
  headers.set('Host', domain!)
  return REAL_FETCH(`http://127.0.0.1:${PORT}${path}`, { ...init, headers })
}) as typeof fetch

const rootPriv = ed25519.utils.randomSecretKey()
const rootPub = ed25519.getPublicKey(rootPriv)
const { did } = await createGenesis({
  domain: 'biset.md', username: 'y',
  rootPrivateKey: rootPriv, rootPublicKey: rootPub,
  relays: [], addresses: 'y@biset.md',
})
const resolveWebvh = rootKeyResolver(new WebvhLogStore(dataDir))

const good = {
  did, username: 'y', relayHost: 'mail.biset.md', bindTs: NOW,
  sigB64: sign(rootPriv, bindingStatement(did, 'y', 'mail.biset.md', NOW)),
}

console.log('\n=== 文言の一致（3実装が同じ1つのバイト列に合意している）===')
ok('client の bindingStatement が Go と同じ形を作る',
  bindingStatement(did, 'y', 'mail.biset.md', NOW) === `bind:${did}:y@mail.biset.md:${NOW}`,
  bindingStatement(did, 'y', 'mail.biset.md', NOW))

console.log('\n=== 正常系 ===')
ok('クライアントが署名したものを anchor が検証できる（旧: "not a did:dht identifier" で401していた）',
  (await verifyDIDBinding(good, resolveWebvh, NOW)).ok)

console.log('\n=== 改竄はすべて弾く ===')
const forgedPriv = ed25519.utils.randomSecretKey()
for (const [name, mut] of [
  ['username が違う（別アドレスへの流用）', { username: 'z' }],
  ['relayHost が違う（別 relay への再生）', { relayHost: 'mail.evil.md' }],
  ['未登録の did は鍵が引けず弾かれる', { did: did.replace(':y', ':nobody') }],
  ['bindTs が違う（署名対象がずれる）', { bindTs: NOW - 1 }],
  ['署名が壊れている', { sigB64: b64(new Uint8Array(64)) }],
  ['署名が base64 ですらない', { sigB64: '!!!not base64!!!' }],
  ['別人の鍵で署名した binding は弾く', { sigB64: sign(forgedPriv, bindingStatement(did, 'y', 'mail.biset.md', NOW)) }],
] as const) {
  const r = await verifyDIDBinding({ ...good, ...mut } as any, resolveWebvh, NOW)
  ok(name, !r.ok, r.ok ? '通ってしまった' : '')
}

console.log('\n=== 鮮度の窓（捕捉した署名の再生を止める）===')
ok('300秒前は通る', (await verifyDIDBinding(good, resolveWebvh, NOW + 300)).ok)
ok('301秒前は弾く', !(await verifyDIDBinding(good, resolveWebvh, NOW + 301)).ok)
ok('未来にずれた時計も同じ窓で扱う（-300 は通る）', (await verifyDIDBinding(good, resolveWebvh, NOW - 300)).ok)
ok('-301 は弾く', !(await verifyDIDBinding(good, resolveWebvh, NOW - 301)).ok)
ok('bind_ts 欠落は弾く（NaN を 0 と読んで窓に入れない）',
  !(await verifyDIDBinding({ ...good, bindTs: NaN }, resolveWebvh, NOW)).ok)

globalThis.fetch = REAL_FETCH
rmSync(dataDir, { recursive: true, force: true })

console.log(`\n  ${fails === 0 ? '全て通過' : fails + ' 件失敗'}\n`)
process.exit(fails === 0 ? 0 : 1)
