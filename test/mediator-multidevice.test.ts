// Multi-device DIDComm delivery (DID⊥relay orthogonality): one did:dht
// identity, TWO devices, each with its OWN keyAgreement key at its own
// positional kid (document.ts's DidKeyAgreement note). Proves the actual bug
// this fixed — the mediator used to collapse Forward/keylist/pickup targets
// down to the bare DID (stripFragment), so whichever device polled
// DELIVERY_REQUEST first silently drained messages meant for every device,
// starving the rest. normalizeKid keeps the kid distinct instead.
//
// Uses a FAKE resolveDidDht (an in-memory kid->pubkey map) rather than a real
// DHT/pkarr gateway — this is a unit test of the mediator's own kid-routing
// logic, not of DHT publish/resolve (covered elsewhere).
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { x25519 } from '@noble/curves/ed25519.js'
import { generatePeerIdentity } from '../src/did/peer.ts'
import { createMediator } from '../src/anchor/mediator/server.ts'
import { loadMediatorIdentity } from '../src/anchor/mediator/identity.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist } from '../src/did/didcomm/coordinate.ts'
import { pickupDeliver } from '../src/did/didcomm/pickup.ts'
import { sendDidComm } from '../src/did/didcomm/send.ts'
import type { PeerDidDoc } from '../src/did/peer.ts'
import { b64url } from '../src/did/peer.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

const dir = mkdtempSync(join(tmpdir(), 'medtest-multidevice-'))
const PORT = 8902
const URL_ = `http://127.0.0.1:${PORT}`

// The identity under test: one did:dht, two devices. Not a real did:dht
// (no seed/DHT needed for this) — just a fixed identifier string and an
// in-memory keyAgreementKeys map the fake resolver reads.
const IDENTITY_DID = 'did:dht:testmultidevice'
const deviceAKey = { priv: x25519.utils.randomSecretKey(), pub: undefined as unknown as Uint8Array }
deviceAKey.pub = x25519.getPublicKey(deviceAKey.priv)
const deviceBKey = { priv: x25519.utils.randomSecretKey(), pub: undefined as unknown as Uint8Array }
deviceBKey.pub = x25519.getPublicKey(deviceBKey.priv)

const keysByKid = new Map<string, Uint8Array>([
  [`${IDENTITY_DID}#k1`, deviceAKey.pub],
  [`${IDENTITY_DID}#k2`, deviceBKey.pub],
])
const resolveDidDht = async (_did: string, kid: string): Promise<Uint8Array | null> => keysByKid.get(kid) ?? null

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

const deviceA = { did: IDENTITY_DID, xKid: `${IDENTITY_DID}#k1`, xPriv: deviceAKey.priv }
const deviceB = { did: IDENTITY_DID, xKid: `${IDENTITY_DID}#k2`, xPriv: deviceBKey.priv }

console.log('\n=== 2台の端末が同じ identity として、それぞれ自分の kid で登録する ===')
await requestMediation(info, deviceA)
await updateKeylist(info, deviceA, deviceA.xKid, 'add')
await requestMediation(info, deviceB)
await updateKeylist(info, deviceB, deviceB.xKid, 'add')
ok('両方の登録が成功する（例外なし）', true)

// Bob (a real did:peer sender) resolves the identity to a doc listing BOTH
// devices' kids — exactly what didDhtToPeerDidDocShape produces from a
// document with two keyAgreementKeys entries.
const bob = generatePeerIdentity()
const bobSender = { did: bob.did, xKid: bob.xKid, xPriv: bob.xPriv }
const toDoc: PeerDidDoc = {
  id: IDENTITY_DID,
  keyAgreement: [deviceA.xKid, deviceB.xKid],
  authentication: [],
  verificationMethod: [
    { id: deviceA.xKid, type: 'JsonWebKey2020', controller: IDENTITY_DID, publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: b64url(deviceAKey.pub) } },
    { id: deviceB.xKid, type: 'JsonWebKey2020', controller: IDENTITY_DID, publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: b64url(deviceBKey.pub) } },
  ],
  service: [{ id: `${IDENTITY_DID}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: URL_, accept: ['didcomm/v2'], routing_keys: [mediatorIdentity.xKid] } }],
}

console.log('\n=== Bob が1回 send.ts で送る（両端末に fan-out するはず） ===')
const marker = 'hello both devices'
await sendDidComm(bobSender, IDENTITY_DID, toDoc, { type: 'https://didcomm.org/basicmessage/2.0/message', body: { content: marker } })

const resolveSenderKeyForBob = async (kid: string) => (kid === bob.xKid ? bob.xPub : (() => { throw new Error('unexpected sender') })())

console.log('\n=== 両端末が独立に受信できる（片方が先に取っても、もう片方は starve しない） ===')
const deliveredToA = await pickupDeliver(info, deviceA, resolveSenderKeyForBob)
ok('端末Aが1通受信', deliveredToA.length === 1, `got ${deliveredToA.length}`)
ok('端末Aの中身が一致', (deliveredToA[0]?.plaintext as any)?.body?.content === marker)

const deliveredToB = await pickupDeliver(info, deviceB, resolveSenderKeyForBob)
ok('端末Bも1通受信（Aが先に取っても消えていない — これが直したバグ）', deliveredToB.length === 1, `got ${deliveredToB.length}`)
ok('端末Bの中身も一致', (deliveredToB[0]?.plaintext as any)?.body?.content === marker)

console.log('\n=== 取り出した後は両方とも空 ===')
const secondA = await pickupDeliver(info, deviceA, resolveSenderKeyForBob)
const secondB = await pickupDeliver(info, deviceB, resolveSenderKeyForBob)
ok('端末Aは2回目は空', secondA.length === 0)
ok('端末Bも2回目は空', secondB.length === 0)

console.log(fails === 0 ? '\n  全て通過 — multi-device fan-out はどちらの端末も starve しない\n' : `\n  ${fails} 件失敗\n`)
server.stop()
rmSync(dir, { recursive: true, force: true })
process.exit(fails === 0 ? 0 : 1)
