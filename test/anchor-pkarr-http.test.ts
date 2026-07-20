// /pkarr is open — no Authorization header required, for either GET or PUT.
// Was gated behind fromOwnRelay() (relay_token Bearer) or, for relay-less
// clients, a separate pkarr_token minted at mediator registration — removed
// because PUT is already self-authenticating (the payload's own signature is
// checked against the key named in the URL, so nobody can forge or overwrite
// a record they don't hold the key for, no matter who's asking) and the two
// public fallback gateways this same client already trusts (relay.pkarr.org,
// pkarr.pubky.org) have always operated exactly this way. The old gate
// bought no safety; it only coupled two unrelated services (DIDComm
// mediation and DHT gateway access) through one shared credential.
//
// /identity/* (the claim registry, address ownership) is a different
// resource — a real scarce, contestable one — and stays gated; verified here
// too so this file also catches an accidental widening of THAT gate.
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { startAnchor, type PkarrRef } from '../src/anchor/server.ts'
import { ClaimStore } from '../src/anchor/store.ts'
import { CloudflareAnchor } from '../src/anchor/cloudflare.ts'
import type { PkarrGateway } from '../src/anchor/pkarr.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

const dataDir = mkdtempSync(join(tmpdir(), 'anchor-pkarr-http-'))
const store = new ClaimStore(dataDir)
const PORT = 18202
const A = `http://127.0.0.1:${PORT}`

// A stub gateway: what handlePkarr needs (get/put), no real DHT join. The
// signature verification PUT relies on for safety is PkarrGateway's own job,
// already covered by anchor-pkarr.test.ts's wire-format tests — this file is
// purely about the HTTP layer's auth gate, so a plain in-memory store is
// enough to prove requests reach it without a Bearer header at all.
const backing = new Map<string, Buffer>()
const stubGateway = {
  async get(pubkey: Buffer) { return backing.get(pubkey.toString('hex')) ?? null },
  async put(pubkey: Buffer, payload: Buffer) { backing.set(pubkey.toString('hex'), payload) },
} as unknown as PkarrGateway
const pkarrRef: PkarrRef = { current: stubGateway, starting: false }

const TOKEN = 'test-relay-token'
const server = startAnchor({
  claims: store,
  cloudflare: new CloudflareAnchor({}),
  port: PORT,
  hostname: '127.0.0.1',
  relayToken: TOKEN,
  pkarr: pkarrRef,
})
await Bun.sleep(200)

// A 32-byte "pubkey" as its z-base-32 encoding — doesn't need to be a real
// ed25519 key, the stub gateway and the URL parsing don't care.
const { zbase32Encode } = await import('../src/did/zbase32.ts')
const key = zbase32Encode(new Uint8Array(32).fill(7))
const payload = new Uint8Array(80).fill(9)

console.log('\n=== /pkarr GET/PUT: no Authorization header required ===')
{
  const missResp = await fetch(`${A}/pkarr/${key}`)
  ok('存在しないキーは 404（認証ヘッダ無しでも到達する）', missResp.status === 404, `got ${missResp.status}`)

  const putResp = await fetch(`${A}/pkarr/${key}`, { method: 'PUT', body: payload })
  ok('Authorization ヘッダ無しの PUT が 204 で通る', putResp.status === 204, `got ${putResp.status}`)

  const getResp = await fetch(`${A}/pkarr/${key}`)
  ok('直後の GET も認証無しで通り、内容が一致', getResp.status === 200, `got ${getResp.status}`)
  const got = new Uint8Array(await getResp.arrayBuffer())
  ok('中身が put したバイト列と一致', got.length === payload.length && got.every((b, i) => b === payload[i]))
}

console.log('\n=== /identity/* は引き続き relay_token 必須（誤って一緒に開けていないことの確認）===')
{
  const resp = await fetch(`${A}/identity/someone`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: 't.example' }),
  })
  ok('トークン無しの claim は 403', resp.status === 403, `got ${resp.status}`)
}

console.log(fails === 0 ? '\n  全て通過 — /pkarr は認証不要、/identity/* は引き続き必須\n' : `\n  ${fails} 件失敗\n`)
server.stop()
rmSync(dataDir, { recursive: true, force: true })
process.exit(fails === 0 ? 0 : 1)
