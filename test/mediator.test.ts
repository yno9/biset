// Full DIDComm round-trip against the absorbed mediator, driven by biset's
// REAL client code (coordinate/pickup/send) — not a hand-rolled mock of it.
// Both sides are now our own implementation, so this is the test that matters:
// it would pass trivially if both were wrong in the same way, which is why the
// interop check against didcomm-node was done separately when crypto.ts was
// written. What's verified here is the mediator's own logic — allow-listing,
// queueing, forward unwrapping, pickup.
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { identityFromKeys, generatePeerIdentity } from '../src/did/peer.ts'
import { createMediator } from '../src/anchor/mediator/server.ts'
import { loadMediatorIdentity } from '../src/anchor/mediator/identity.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist } from '../src/did/didcomm/coordinate.ts'
import { pickupStatus, pickupDeliver } from '../src/did/didcomm/pickup.ts'
import { sendDidComm } from '../src/did/didcomm/send.ts'
import { publicKeyOf } from '../src/did/didcomm/message.ts'
import { decodePeerDid2 } from '../src/did/peer.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

const dir = mkdtempSync(join(tmpdir(), 'medtest-'))
const PORT = 8901
const URL_ = `http://127.0.0.1:${PORT}`

const mediatorIdentity = loadMediatorIdentity(join(dir, 'mediator-identity.json'), URL_)
const mediator = createMediator({ mediator: mediatorIdentity })
const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const resp = await mediator.handle(req, new URL(req.url))
    return resp ?? new Response('not found', { status: 404 })
  },
})

console.log('\n=== mediator の身元 ===')
const info = await fetchMediatorInfo(URL_)
ok('.well-known/did.json がクライアントの fetchMediatorInfo で読める', info.did === mediatorIdentity.did)
ok('service に自分の公開URLが入っている（相手はここへ届ける）',
  info.doc.service?.[0]?.serviceEndpoint?.uri === URL_,
  JSON.stringify(info.doc.service))

// Alice は mediator 経由でしか受け取れない相手（＝ブラウザ）。routing_keys が
// mediator を指すので、送信側は forward で包む。
const aliceKeys = { x: x25519.utils.randomSecretKey(), ed: ed25519.utils.randomSecretKey() }
const alice = identityFromKeys(aliceKeys.x, aliceKeys.ed, {
  uri: URL_, accept: ['didcomm/v2'], routingKeys: [mediatorIdentity.xKid],
})
const aliceSender = { did: alice.did, xKid: alice.xKid, xPriv: alice.xPriv }
const bob = generatePeerIdentity()
const bobSender = { did: bob.did, xKid: bob.xKid, xPriv: bob.xPriv }

console.log('\n=== Coordinate Mediation 2.0 ===')
const grant = await requestMediation(info, aliceSender)
ok('mediate-request → mediate-grant が routing_did を返す', grant.routingDid === mediatorIdentity.did, `got ${grant.routingDid}`)

console.log('\n=== 未登録の宛先は拒否される（オープンリレー化の防止）===')
{
  let err: string | null = null
  try { await sendDidComm(bobSender, alice.did, alice.doc, { type: 'https://example.org/x', body: { n: 0 } }) }
  catch (e: any) { err = e.message }
  ok('keylist-update 前の forward は 401 で弾かれる', !!err && err.includes('401'), `err=${err}`)
  ok('弾かれた分はキューに入っていない', (await pickupStatus(info, aliceSender)) === 0)
}

await updateKeylist(info, aliceSender, alice.xKid, 'add')

console.log('\n=== Routing 2.0（Bob → mediator → Alice）===')
await sendDidComm(bobSender, alice.did, alice.doc, { type: 'https://example.org/greeting', body: { hello: 'alice' } })
ok('forward 後に status が 1 を返す', (await pickupStatus(info, aliceSender)) === 1)

console.log('\n=== Pickup 3.0 ===')
const resolveSender = (kid: string) => publicKeyOf(decodePeerDid2(kid.split('#')[0]!), kid)
const got = await pickupDeliver(info, aliceSender, resolveSender)
ok('delivery が 1 通返す', got.length === 1, `got ${got.length}`)
ok('中身が Bob の送ったものと一致する',
  (got[0]?.plaintext as any)?.body?.hello === 'alice',
  JSON.stringify(got[0]?.plaintext))
ok('送信者が Bob だと認証されている（mediator は中身を触っていない）',
  got[0]?.senderKid === bob.xKid, `senderKid=${got[0]?.senderKid}`)
ok('取り出した分はキューから消える', (await pickupStatus(info, aliceSender)) === 0)

console.log('\n=== keylist-update remove ===')
await updateKeylist(info, aliceSender, alice.xKid, 'remove')
{
  let err: string | null = null
  try { await sendDidComm(bobSender, alice.did, alice.doc, { type: 'https://example.org/x', body: { n: 2 } }) }
  catch (e: any) { err = e.message }
  ok('remove 後の forward はふたたび 401', !!err && err.includes('401'), `err=${err}`)
}

console.log('\n=== mediator の身元は再起動をまたいで安定する ===')
{
  // 同じ data ディレクトリから作り直す。ここが変わると、既存の登録が全部孤児になる。
  const again = loadMediatorIdentity(join(dir, 'mediator-identity.json'), URL_)
  ok('同じ DID が復元される', again.did === mediatorIdentity.did)
  const fresh = loadMediatorIdentity(join(dir, 'other-identity.json'), URL_)
  ok('別ファイルなら別の DID（＝本当に鍵を読んでいる）', fresh.did !== mediatorIdentity.did)
}

server.stop(true)
rmSync(dir, { recursive: true, force: true })
console.log(`\n  ${fails === 0 ? '全て通過' : fails + ' 件失敗'}\n`)
process.exit(fails === 0 ? 0 : 1)
