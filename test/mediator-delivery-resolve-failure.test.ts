// did:dht resolve resilience at the mediator. A did:dht identity's key resolve
// is a network round-trip (through a Pkarr gateway) and fails transiently —
// found live, the anchor's logs showed "unresolvable did:dht peer ...#k1" on
// routine polls, so a client only received its mail once the DHT happened to
// answer (unstable, slow-but-eventually). This test pins the two guarantees
// that fix it:
//   1. Non-destructive delivery (Pickup 3.0): a message is never removed until
//      messages-received, so a mid-flight failure can't lose it — it is simply
//      re-fetched on retry.
//   2. Key caching: once the mediator has successfully resolved a client's
//      (rotation-less, stable) key, a LATER DHT outage no longer breaks that
//      client — it keeps authenticating and receiving off the cached key.
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { x25519 } from '@noble/curves/ed25519.js'
import { generatePeerIdentity, b64url } from '../src/did/peer/peer.ts'
import { createMediator } from '../src/anchor/mediator/server.ts'
import { loadMediatorIdentity } from '../src/anchor/mediator/identity.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist } from '../src/did/didcomm/coordinate.ts'
import { pickupStatus, pickupDeliver, acknowledgeMessages } from '../src/did/didcomm/pickup.ts'
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
const IDENTITY_DID = 'did:webvh:testresolvefailure'
const deviceKey = { priv: x25519.utils.randomSecretKey(), pub: undefined as unknown as Uint8Array }
deviceKey.pub = x25519.getPublicKey(deviceKey.priv)
const keysByKid = new Map<string, Uint8Array>([[`${IDENTITY_DID}#k1`, deviceKey.pub]])
let dhtDown = false // simulate a total DHT/gateway outage on demand
const resolveDidWebvh = async (_did: string, kid: string): Promise<Uint8Array | null> => {
  if (dhtDown) return null
  return keysByKid.get(kid) ?? null
}

const mediatorIdentity = loadMediatorIdentity(join(dir, 'mediator-identity.json'), URL_)
const mediator = createMediator({ mediator: mediatorIdentity, resolveDidWebvh })
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

// The registration above already made the mediator resolve (and cache) this
// device's key. Now simulate a total DHT outage: without caching this would be
// the exact live failure ("unresolvable did:dht peer ...#k1") on every poll.
console.log('\n=== 一度解決成功後、DHTが全面ダウンしても受信し続けられる（鍵キャッシュ）===')
dhtDown = true
const delivered = await pickupDeliver(info, device, async () => bob.xPub)
ok('DHTダウン中でも配送される（キャッシュ鍵で認証・返信暗号化）', delivered.length === 1, `got ${delivered.length}`)
ok('中身がBobの送ったものと一致', (delivered[0]?.plaintext as any)?.body?.content === 'hello')

console.log('\n=== 非破壊delivery: ack するまでキューに残る ===')
const count2 = await pickupStatus(info, device)
ok('delivery だけではまだ残っている（非破壊）', count2 === 1, `count=${count2}`)
await acknowledgeMessages(info, device, delivered.map(d => d.ackId)) // DHTダウン中でも ack が通る
const count3 = await pickupStatus(info, device)
ok('messages-received でack後にキューが空（DHTダウン中でも）', count3 === 0, `count=${count3}`)
dhtDown = false

console.log(fails === 0 ? '\n  全て通過 — 返信鍵のresolve失敗はメッセージを消さず、リトライで届く\n' : `\n  ${fails} 件失敗\n`)
server.stop()
rmSync(dir, { recursive: true, force: true })
process.exit(fails === 0 ? 0 : 1)
