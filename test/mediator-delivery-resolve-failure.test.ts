// The bug: DELIVERY_REQUEST used to call queue.take() (destructive — splices
// the batch out, server.ts's queue.ts) BEFORE packReplyTo resolved the
// reply key. A did:dht identity's key resolve is a network round-trip
// (through a Pkarr gateway) and can fail transiently — found live, the
// anchor's own logs showed exactly this: "unresolvable did:dht peer ...#k1"
// thrown from inside packReplyTo, called from handle(), unhandled. When that
// happened, the messages had ALREADY been taken off the queue by the time the
// reply failed to encrypt — gone, with no response ever reaching the client
// to say so. A device polling for its mail during a network hiccup lost that
// mail permanently, not just delayed it.
//
// The fix reorders DELIVERY_REQUEST to resolve the reply key FIRST — a
// resolve failure now leaves the queue untouched and returns a clean error,
// so the same poll (or the next one) can just retry and actually get the
// message. This test proves both halves: a mid-flight resolve failure loses
// nothing, and a subsequent successful poll still delivers it.
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { x25519 } from '@noble/curves/ed25519.js'
import { generatePeerIdentity, b64url } from '../src/did/peer.ts'
import { createMediator } from '../src/anchor/mediator/server.ts'
import { loadMediatorIdentity } from '../src/anchor/mediator/identity.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist } from '../src/did/didcomm/coordinate.ts'
import { pickupStatus, pickupDeliver } from '../src/did/didcomm/pickup.ts'
import { sendDidComm } from '../src/did/didcomm/send.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

const dir = mkdtempSync(join(tmpdir(), 'medtest-delivery-resolve-'))
const PORT = 8903
const URL_ = `http://127.0.0.1:${PORT}`

// A fake did:dht resolver (unit test of server.ts's own ordering, not of real
// DHT resolution — mediator-multidevice.test.ts uses the same approach) whose
// Nth call can be made to fail on demand, so the test can fail EXACTLY the
// reply-key resolve inside one specific request without also failing the
// request's own sender-authentication resolve (which must succeed, or the
// request never reaches DELIVERY_REQUEST's handler at all).
const IDENTITY_DID = 'did:dht:testresolvefailure'
const deviceKey = { priv: x25519.utils.randomSecretKey(), pub: undefined as unknown as Uint8Array }
deviceKey.pub = x25519.getPublicKey(deviceKey.priv)
const keysByKid = new Map<string, Uint8Array>([[`${IDENTITY_DID}#k1`, deviceKey.pub]])
let callCount = 0
let failAtCall = -1
const resolveDidDht = async (_did: string, kid: string): Promise<Uint8Array | null> => {
  callCount++
  if (callCount === failAtCall) return null
  return keysByKid.get(kid) ?? null
}

const mediatorIdentity = loadMediatorIdentity(join(dir, 'mediator-identity.json'), URL_)
const mediator = createMediator({ mediator: mediatorIdentity, resolveDidDht })
const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const resp = await mediator.handle(req, new URL(req.url))
    return resp ?? new Response('not found', { status: 404 })
  },
})

const info = await fetchMediatorInfo(URL_)
const device = { did: IDENTITY_DID, xKid: `${IDENTITY_DID}#k1`, xPriv: deviceKey.priv }

console.log('\n=== 登録 ===')
await requestMediation(info, device)
await updateKeylist(info, device, device.xKid, 'add')
ok('登録が成功する', true)

console.log('\n=== Bobがメッセージを1通送る ===')
const bob = generatePeerIdentity()
const bobSender = { did: bob.did, xKid: bob.xKid, xPriv: bob.xPriv }
const recipientDoc = {
  id: device.did,
  keyAgreement: [device.xKid],
  authentication: [],
  verificationMethod: [{ id: device.xKid, type: 'JsonWebKey2020', controller: device.did, publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: b64url(deviceKey.pub) } }],
  service: [{ id: `${device.did}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: URL_, accept: ['didcomm/v2'], routing_keys: [mediatorIdentity.xKid] } }],
}
await sendDidComm(bobSender, device.did, recipientDoc, { type: 'https://didcomm.org/basicmessage/2.0/message', body: { content: 'hello', id: 'm1' } })
const count1 = await pickupStatus(info, device)
ok('1通キューに入っている', count1 === 1, `count=${count1}`)

console.log('\n=== 受信中に返信鍵のresolveが一時的に失敗する ===')
// This request's OWN sender-auth resolve must succeed (call #1); the reply
// resolve inside DELIVERY_REQUEST is call #2 — that's the one made to fail,
// simulating the exact live failure (a transient did:dht hiccup encrypting
// the reply back to the very device asking).
callCount = 0
failAtCall = 2
let deliveryThrew = false
try {
  await pickupDeliver(info, device, async () => bob.xPub)
} catch {
  deliveryThrew = true
}
ok('resolve失敗時、pickupDeliverはエラーになる（クラッシュせず明確に失敗する）', deliveryThrew)
failAtCall = -1 // back to normal for the rest of this test

const count2 = await pickupStatus(info, device)
ok('resolve失敗後もメッセージはキューに残っている（消えていない — これが直したバグ）', count2 === 1, `count=${count2}`)

console.log('\n=== 再度受信すると、今度は正常に届く ===')
const delivered = await pickupDeliver(info, device, async () => bob.xPub)
ok('リトライで1通受信できる', delivered.length === 1, `got ${delivered.length}`)
ok('中身がBobの送ったものと一致', (delivered[0]?.plaintext as any)?.body?.content === 'hello')
const count3 = await pickupStatus(info, device)
ok('取り出した後はキューが空', count3 === 0, `count=${count3}`)

console.log(fails === 0 ? '\n  全て通過 — 返信鍵のresolve失敗はメッセージを消さず、リトライで届く\n' : `\n  ${fails} 件失敗\n`)
server.stop()
rmSync(dir, { recursive: true, force: true })
process.exit(fails === 0 ? 0 : 1)
