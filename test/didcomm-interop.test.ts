// Interop: drives biset's NEW mediator using **didcomm-node** (the Rust
// reference implementation, via wasm) as the client.
//
// This is the test the round-trip suite cannot be: there, both ends are
// biset's own crypto, so a shared misreading of the spec would pass. Dropping
// didcomm-node from the mediator removed the only place a foreign
// implementation sat on the other side of the wire, and that signal has to be
// replaced rather than assumed. If a third-party DIDComm agent can no longer
// route through us, it fails HERE and nowhere else.
//
// didcomm-node stays a devDependency-shaped scratch tool for exactly this: it
// cannot ship (it reads its .wasm off disk at runtime, so `bun build --compile`
// can't fold it into the anchor binary — the finding that forced this port).
// @ts-ignore -- didcomm-node ships hand-written .d.ts without a "types" field
import * as didcomm from 'didcomm-node'
import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { identityFromKeys, decodePeerDid2 } from '../src/did/peer.ts'
import { createMediator } from '../src/anchor/mediator/server.ts'
import { loadMediatorIdentity } from '../src/anchor/mediator/identity.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

const dir = mkdtempSync(join(tmpdir(), 'interop-'))
const PORT = 8902
const URL_ = `http://127.0.0.1:${PORT}`

const mediatorIdentity = loadMediatorIdentity(join(dir, 'id.json'), URL_)
const mediator = createMediator({ mediator: mediatorIdentity })
const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    return (await mediator.handle(req, new URL(req.url))) ?? new Response('nf', { status: 404 })
  },
})

// didcomm-node needs our mediator's doc; every did:peer:2 it self-decodes.
const known: Record<string, any> = { [mediatorIdentity.did]: mediatorIdentity.doc }
const resolver = {
  async resolve(did: string) {
    if (known[did]) return known[did]
    try { return decodePeerDid2(did) } catch { return null }
  },
}
const allSecrets: Record<string, any> = {}
const secretsResolver = {
  async get_secret(id: string) { return allSecrets[id] ?? null },
  async find_secrets(ids: string[]) { return ids.filter(i => allSecrets[i]) },
}

function mkIdentity(routingKeys?: string[]) {
  const id = identityFromKeys(
    x25519.utils.randomSecretKey(), ed25519.utils.randomSecretKey(),
    routingKeys ? { uri: URL_, accept: ['didcomm/v2'], routingKeys } : undefined,
  )
  Object.assign(allSecrets, id.secrets)
  return id
}

const alice = mkIdentity([mediatorIdentity.xKid])
const bob = mkIdentity()

/** Send a didcomm-node-packed message to our mediator, unpack its reply with
 * didcomm-node too — so both directions are checked against the reference. */
async function rpc(from: string, type: string, body: unknown): Promise<any> {
  const msg = new didcomm.Message({
    id: crypto.randomUUID(), typ: 'application/didcomm-plain+json',
    type, body, from, to: [mediatorIdentity.did],
  })
  const [packed] = await msg.pack_encrypted(mediatorIdentity.did, from, null, resolver, secretsResolver, { forward: false })
  const resp = await fetch(URL_, { method: 'POST', headers: { 'content-type': 'application/didcomm-encrypted+json' }, body: packed })
  if (!resp.ok) throw new Error(`HTTP ${resp.status} ${await resp.text()}`)
  const [unpacked] = await didcomm.Message.unpack(await resp.text(), resolver, secretsResolver, {})
  return unpacked.as_value()
}

console.log('\n=== didcomm-node（参照実装）→ biset の新 mediator ===')

const grant = await rpc(alice.did, 'https://didcomm.org/coordinate-mediation/2.0/mediate-request', {})
ok('mediate-request が didcomm-node で packed され、mediator が解ける',
  grant.type === 'https://didcomm.org/coordinate-mediation/2.0/mediate-grant', `type=${grant.type}`)
ok('mediate-grant が didcomm-node で unpack でき、routing_did が正しい',
  grant.body?.routing_did === mediatorIdentity.did, JSON.stringify(grant.body))

const kl = await rpc(alice.did, 'https://didcomm.org/coordinate-mediation/2.0/keylist-update', {
  updates: [{ recipient_did: alice.xKid, action: 'add' }],
})
ok('keylist-update が success を返す',
  kl.body?.updated?.[0]?.result === 'success', JSON.stringify(kl.body))

console.log('\n=== Routing 2.0: 参照実装が anoncrypt した forward ===')
// forward は didcomm-node に**手で**組ませる。`{forward: true}` の自動包装は使えない:
// didcomm-node が routing_keys を見つけられず (`messaging_service: null`)、素の
// authcrypt を返してくる。原因は didcomm-node 側の DIDDoc の受け口 — 同梱の
// .d.ts は `serviceEndpoint` と書いているが Rust の ServiceKind は
// `#[serde(tag="type")]` の内部タグ付き enum で、どちらの綴りでも
// messaging_service が埋まらなかった (`service_endpoint` にすると今度は DIDDoc
// ごと "Unable resolve recipient did" で落ちる)。**これは呼び出し側が
// didcomm-node にどう doc を渡すかの話**で、mediator が何を受理するかとは無関係
// — 本物の第三者エージェントは自前の resolver で自前の DIDDoc を組む。
//
// ここで確かめたいのは一点:「参照実装が anoncrypt した forward を我々が解けるか」。
// `from: null` で pack すると didcomm-node は anoncrypt する。
{
  const inner = new didcomm.Message({
    id: crypto.randomUUID(), typ: 'application/didcomm-plain+json',
    type: 'https://example.org/greeting', body: { hello: 'from-didcomm-node' },
    from: bob.did, to: [alice.did],
  })
  const [innerPacked] = await inner.pack_encrypted(alice.did, bob.did, null, resolver, secretsResolver, { forward: false })
  const fwd = new didcomm.Message({
    id: crypto.randomUUID(), typ: 'application/didcomm-plain+json',
    type: 'https://didcomm.org/routing/2.0/forward',
    body: { next: alice.xKid },
    to: [mediatorIdentity.did],
    attachments: [{ id: crypto.randomUUID(), data: { json: JSON.parse(innerPacked) } }],
  })
  // from を渡さない = anoncrypt（mediator に送信者を明かさない、Routing の要件）
  const [packed] = await fwd.pack_encrypted(mediatorIdentity.did, null, null, resolver, secretsResolver, { forward: false })
  const hdr = JSON.parse(Buffer.from(JSON.parse(packed).protected, 'base64url').toString())
  ok('参照実装の forward は本当に anoncrypt になっている', hdr.alg === 'ECDH-ES+A256KW', `alg=${hdr.alg}`)
  const resp = await fetch(URL_, { method: 'POST', headers: { 'content-type': 'application/didcomm-encrypted+json' }, body: packed })
  ok('参照実装が anoncrypt した forward を mediator が 202 で受理する', resp.status === 202, `HTTP ${resp.status} ${await resp.text().catch(() => '')}`)
}

const status = await rpc(alice.did, 'https://didcomm.org/messagepickup/3.0/status-request', { recipient_did: alice.xKid })
ok('status が 1 通を報告する', status.body?.message_count === 1, JSON.stringify(status.body))

console.log('\n=== Pickup 3.0: 参照実装で取り出して中身まで復号する ===')
{
  const delivery = await rpc(alice.did, 'https://didcomm.org/messagepickup/3.0/delivery-request', { recipient_did: alice.xKid, limit: 10 })
  ok('delivery が返る', delivery.type === 'https://didcomm.org/messagepickup/3.0/delivery', `type=${delivery.type}`)
  const att = delivery.attachments?.[0]?.data?.json
  ok('添付が1件ある', !!att)
  if (att) {
    // Bob の元メッセージ（authcrypt）を didcomm-node で開ける＝
    // mediator が中身を素通ししている証拠。
    const [inner] = await didcomm.Message.unpack(JSON.stringify(att), resolver, secretsResolver, {})
    const v = inner.as_value()
    ok('中身が Bob の送ったもので、didcomm-node が復号できる',
      v.body?.hello === 'from-didcomm-node', JSON.stringify(v.body))
    ok('送信者が Bob として認証される', v.from === bob.did, `from=${v.from}`)
  }
}

server.stop(true)
rmSync(dir, { recursive: true, force: true })
console.log(`\n  ${fails === 0 ? '全て通過 — 参照実装と相互運用できる' : fails + ' 件失敗'}\n`)
process.exit(fails === 0 ? 0 : 1)
