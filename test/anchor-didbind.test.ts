// The anchor's DID-binding check, against signatures produced by the client's
// own signer (src/did/binding.ts). Three implementations have to agree on one
// byte string — client signs it, go-jmapserver/didbind.go verified it, this now
// does — and a drift between any two means every DID account creation fails.
// So the statement is pinned here explicitly as well as exercised end-to-end.
//
// Also covers did:webvh: unlike did:dht (the DID *is* the key), a did:webvh
// root key only lives in a resolved document, so verifyDIDBinding needs a
// live rootKeyResolver against a real webvh log (regression test for the
// 401 "not a did:dht identifier" bug hit when #new's did:webvh account
// creation went through provisionAccount for the first time).
import { ed25519 } from '@noble/curves/ed25519.js'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { zbase32Encode } from '../src/did/dht/zbase32.ts'
import { bindingStatement } from '../src/did/binding.ts'
import { verifyDIDBinding, didPublicKey, rootKeyResolver } from '../src/anchor/didbind.ts'
import { startAnchor } from '../src/anchor/server.ts'
import { ClaimStore } from '../src/anchor/store.ts'
import { CloudflareAnchor } from '../src/anchor/cloudflare.ts'
import { WebvhLogStore } from '../src/anchor/webvh-store.ts'
import { createGenesis } from '../src/did/webvh/publish.ts'

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

const resolveDht = rootKeyResolver(undefined) // did:dht never touches the webvh store

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

console.log('\n=== 正常系（did:dht）===')
ok('クライアントが署名したものを anchor が検証できる', (await verifyDIDBinding(good, resolveDht, NOW)).ok)

console.log('\n=== 改竄はすべて弾く ===')
for (const [name, mut] of [
  ['username が違う（別アドレスへの流用）', { username: 'z' }],
  ['relayHost が違う（別 relay への再生）', { relayHost: 'mail.evil.md' }],
  ['did が違う（別人の DID を主張）', { did: 'did:dht:' + zbase32Encode(ed25519.getPublicKey(ed25519.utils.randomSecretKey())) }],
  ['bindTs が違う（署名対象がずれる）', { bindTs: NOW - 1 }],
  ['署名が壊れている', { sigB64: b64(new Uint8Array(64)) }],
  ['署名が base64 ですらない', { sigB64: '!!!not base64!!!' }],
] as const) {
  const r = await verifyDIDBinding({ ...good, ...mut } as any, resolveDht, NOW)
  ok(name, !r.ok, r.ok ? '通ってしまった' : '')
}

console.log('\n=== 鮮度の窓（捕捉した署名の再生を止める）===')
ok('300秒前は通る', (await verifyDIDBinding(good, resolveDht, NOW + 300)).ok)
ok('301秒前は弾く', !(await verifyDIDBinding(good, resolveDht, NOW + 301)).ok)
ok('未来にずれた時計も同じ窓で扱う（-300 は通る）', (await verifyDIDBinding(good, resolveDht, NOW - 300)).ok)
ok('-301 は弾く', !(await verifyDIDBinding(good, resolveDht, NOW - 301)).ok)
ok('bind_ts 欠落は弾く（NaN を 0 と読んで窓に入れない）',
  !(await verifyDIDBinding({ ...good, bindTs: NaN }, resolveDht, NOW)).ok)

console.log('\n=== did:webvh（root key はDID自体でなく解決したdocumentにある）===')
{
  const dataDir = mkdtempSync(join(tmpdir(), 'anchor-didbind-webvh-'))
  const PORT = 18511
  startAnchor({
    claims: new ClaimStore(dataDir),
    cloudflare: new CloudflareAnchor({}),
    port: PORT,
    hostname: '127.0.0.1',
    relayToken: 'test-relay-token',
    webvh: new WebvhLogStore(dataDir),
  })
  await Bun.sleep(200)

  const REAL_FETCH = globalThis.fetch
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const m = /^https:\/\/([^/]+)(\/[^/]+\/did\.jsonl.*)$/.exec(url)
    if (!m) return REAL_FETCH(input as any, init)
    const [, domain, path] = m
    const headers = new Headers(init?.headers)
    headers.set('Host', domain!)
    return REAL_FETCH(`http://127.0.0.1:${PORT}${path}`, { ...init, headers })
  }) as typeof fetch

  const rootPriv = ed25519.utils.randomSecretKey()
  const rootPub = ed25519.getPublicKey(rootPriv)
  const { did: webvhDid } = await createGenesis({
    domain: 'biset.md', username: 'wendy',
    rootPrivateKey: rootPriv, rootPublicKey: rootPub,
    relays: [], addresses: 'wendy@biset.md',
  })

  // Same webvh store instance the running anchor uses — verifyDIDBinding's
  // resolver reads directly off disk, exactly like server.ts's POST handler
  // will against the log the client just PUT.
  const resolveWebvh = rootKeyResolver(new WebvhLogStore(dataDir))

  const goodWebvh = {
    did: webvhDid, username: 'wendy', relayHost: 'mail.biset.md', bindTs: NOW,
    sigB64: b64(ed25519.sign(new TextEncoder().encode(bindingStatement(webvhDid, 'wendy', 'mail.biset.md', NOW)), rootPriv)),
  }
  const r = await verifyDIDBinding(goodWebvh, resolveWebvh, NOW)
  ok('did:webvh のroot鍵をdocument解決で検証できる（旧: "not a did:dht identifier" で401していた）', r.ok, r.ok ? '' : (r as any).reason)

  const forgedPriv = ed25519.utils.randomSecretKey()
  const forged = {
    ...goodWebvh,
    sigB64: b64(ed25519.sign(new TextEncoder().encode(bindingStatement(webvhDid, 'wendy', 'mail.biset.md', NOW)), forgedPriv)),
  }
  ok('別人の鍵で署名した did:webvh binding は弾く', !(await verifyDIDBinding(forged, resolveWebvh, NOW)).ok)

  ok('未登録の did:webvh は鍵が引けず弾かれる',
    !(await verifyDIDBinding({ ...goodWebvh, did: webvhDid.replace('wendy', 'nobody') }, resolveWebvh, NOW)).ok)

  globalThis.fetch = REAL_FETCH
  rmSync(dataDir, { recursive: true, force: true })
}

console.log(`\n  ${fails === 0 ? '全て通過' : fails + ' 件失敗'}\n`)
process.exit(fails === 0 ? 0 : 1)
