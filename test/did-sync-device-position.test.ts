// The bug: a device that registered BEFORE a sibling device existed never
// learned about it, and syncDevicePosition — the ONLY thing that resolves
// the published document to learn about siblings — used to run just once, at
// registration time (create-standalone.ts). Every one of that device's LATER
// routine republishes (publish.ts's buildOwnDocument, every app boot) then
// rebuilt the document from its own key alone, silently erasing the sibling
// it never knew about — and since republish uses the current timestamp as
// seq, whichever device happened to reopen its browser more recently always
// won the "highest seq wins" resolve race. Found live: two of one identity's
// own browsers (y@biset.md), permanently unable to reach each other.
//
// The fix makes syncDevicePosition safe to call on every republish, not just
// once — it already only ever GROWS the sibling cache (a failed or partial
// resolve can't erase a real device), so nothing about the function itself
// needed to change, only where it gets called. This test proves the growing
// half of that contract directly: give a device's own record NO knowledge of
// a sibling that HAS since published, and confirm one resolve-and-merge pass
// (exactly what buildOwnDocument now does before every publish) picks it up.
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ed25519 } from '@noble/curves/ed25519.js'
import { buildBisetDocument, type DidDocument } from '../src/did/document.ts'
import { buildSignedPayload } from '../src/did/packet.ts'
import { didFromRootPublicKey } from '../src/did/keys.ts'
import { syncDevicePosition } from '../src/did/create-standalone.ts'
import type { DidRecord } from '../src/did/store.ts'
import { useSeqStore } from '../src/did/freshness.ts'

// resolve() (called inside syncDevicePosition) refuses to run at all without
// a rollback-defense store configured — a browser wires up localStorage at
// boot (main.ts); this headless test needs its own in-memory stand-in.
{
  const mem = new Map<string, string>()
  useSeqStore({ getItem: k => mem.get(k) ?? null, setItem: (k, v) => { mem.set(k, v) } })
}

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}
const bytesToHex = (b: Uint8Array): string => [...b].map(x => x.toString(16).padStart(2, '0')).join('')

// A minimal stub pkarr gateway — raw byte store keyed by path, no signature
// checking server-side (the client's own resolve() does that verification;
// this only needs to serve back whatever was PUT, like a real gateway does).
const backing = new Map<string, Uint8Array>()
const PORT = 18410
const URL_ = `http://127.0.0.1:${PORT}`
const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const key = new URL(req.url).pathname.slice(1)
    if (req.method === 'PUT') { backing.set(key, new Uint8Array(await req.arrayBuffer())); return new Response(null, { status: 204 }) }
    if (req.method === 'GET') { const v = backing.get(key); return v ? new Response(v) : new Response('not found', { status: 404 }) }
    return new Response('method not allowed', { status: 405 })
  },
})

// One identity, one root key — both "devices" are the same DID, as in
// reality (the DID is what makes them the same identity; the DIDComm keys
// differ per device).
const rootPriv = ed25519.utils.randomSecretKey()
const rootPub = ed25519.getPublicKey(rootPriv)
const did = didFromRootPublicKey(rootPub)

const device1Key = ed25519.utils.randomSecretKey() // stand-in X25519-shaped bytes — only their hex identity matters here
const device2Key = ed25519.utils.randomSecretKey()

console.log('\n=== デバイス2が先に登録し、両方のkidを含む文書を publish 済み ===')
const publishedDoc: DidDocument = {
  ...buildBisetDocument(did, rootPub, [], []),
  keyAgreementKeys: [
    { n: 1, publicKey: device1Key.slice(0, 32) },
    { n: 2, publicKey: device2Key.slice(0, 32) },
  ],
}
const payload = buildSignedPayload(rootPriv, publishedDoc)
const putResp = await fetch(`${URL_}/${did.replace('did:dht:', '')}`, { method: 'PUT', body: payload })
ok('gatewayへのputが通る', putResp.status === 204, `got ${putResp.status}`)

console.log('\n=== デバイス1のローカル記録は、デバイス2の存在を一切知らない ===')
const device1Rec: DidRecord = {
  did, email: did,
  rootPrivateKey: bytesToHex(rootPriv), rootPublicKey: bytesToHex(rootPub),
  nostrPrivateKey: '', nostrPublicKey: '', // unused by syncDevicePosition
  didCommOwnKid: '#k1', didCommPublicKey: bytesToHex(device1Key.slice(0, 32)),
  didCommSiblingKeys: [], // ← 空。これが「デバイス2を知らない」状態
}
ok('シード時点でsiblingは空', (device1Rec.didCommSiblingKeys ?? []).length === 0)

console.log('\n=== syncDevicePosition を1回走らせる（republish前に毎回呼ぶのが今回の修正）===')
await syncDevicePosition(device1Rec, [URL_]).catch(() => {}) // storeDidRecord は IndexedDB 無しの test 環境では失敗する — マージ自体はメモリ上の rec に対して先に起きているので無視してよい

const siblings = device1Rec.didCommSiblingKeys ?? []
ok('デバイス2のkidをsiblingとして学習した', siblings.some(s => s.kid === '#k2'), JSON.stringify(siblings))
ok('デバイス2の公開鍵が一致', siblings.find(s => s.kid === '#k2')?.publicKey === bytesToHex(device2Key.slice(0, 32)))
ok('自分自身(k1)はsiblingに含まれない', !siblings.some(s => s.kid === '#k1'))
ok('自分のkidは変わらず#k1のまま', device1Rec.didCommOwnKid === '#k1')

console.log(fails === 0 ? '\n  全て通過 — ルーチン republish 前の sync がsiblingを正しく学習する\n' : `\n  ${fails} 件失敗\n`)
server.stop()
process.exit(fails === 0 ? 0 : 1)
