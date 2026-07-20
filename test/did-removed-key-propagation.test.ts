// The bug: create-standalone.ts's removeDeviceKey deletes a sibling kid from
// the ACTING device's own local cache (didCommRemovedKeys) and republishes —
// but every OTHER device of the same identity has its OWN independent local
// sibling cache that never heard about the removal. grow-only means that
// other device's very next routine republish (syncDevicePosition) just
// re-adds the removed kid right back, because nothing ever told IT to stop.
// Found live: deleted from device A, disappeared there, reappeared when
// checking from device B.
//
// The fix: document.ts's `removedKeyNs` rides the removal along on the
// published document itself (a `rm=` field) — every device's own
// syncDevicePosition reads it on resolve and folds it into ITS OWN removed
// set (and prunes its own stale cache against it), so the removal actually
// propagates through the same channel siblings already learn about each
// other from. This test proves that path directly: device B, still carrying
// a removed kid in its local cache, resolves a document where device A has
// already published the removal — and must drop it, not re-affirm it.
import { ed25519 } from '@noble/curves/ed25519.js'
import { buildBisetDocument, type DidDocument } from '../src/did/document.ts'
import { buildSignedPayload } from '../src/did/packet.ts'
import { didFromRootPublicKey } from '../src/did/keys.ts'
import { syncDevicePosition } from '../src/did/create-standalone.ts'
import type { DidRecord } from '../src/did/store.ts'
import { useSeqStore } from '../src/did/freshness.ts'

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

const backing = new Map<string, Uint8Array>()
const PORT = 18411
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

const rootPriv = ed25519.utils.randomSecretKey()
const rootPub = ed25519.getPublicKey(rootPriv)
const did = didFromRootPublicKey(rootPub)

const deviceAKey = ed25519.utils.randomSecretKey()
const deviceBKey = ed25519.utils.randomSecretKey()

console.log('\n=== デバイスAが、まだ生きてるsibling #k2(デバイスB)を巻き込んで公開済み ===')
const publishedDoc: DidDocument = {
  ...buildBisetDocument(did, rootPub, [], []),
  keyAgreementKeys: [
    { n: 1, publicKey: deviceAKey.slice(0, 32) },
    { n: 2, publicKey: deviceBKey.slice(0, 32) },
  ],
}
await fetch(`${URL_}/${did.replace('did:dht:', '')}`, { method: 'PUT', body: buildSignedPayload(rootPriv, publishedDoc) })

console.log('\n=== デバイスBのローカルには#k1(デバイスA)がsiblingとしてキャッシュ済み ===')
const deviceBRec: DidRecord = {
  did, email: did,
  rootPrivateKey: bytesToHex(rootPriv), rootPublicKey: bytesToHex(rootPub),
  nostrPrivateKey: '', nostrPublicKey: '',
  didCommOwnKid: '#k2', didCommPublicKey: bytesToHex(deviceBKey.slice(0, 32)),
  didCommSiblingKeys: [{ kid: '#k1', publicKey: bytesToHex(deviceAKey.slice(0, 32)) }],
}

console.log('\n=== デバイスAが#k1自身...ではなく、他の何か(#k1目線ではsiblingとして#k1を消す状況を模す代わりに)デバイスAがrm=1を公開 ===')
// Simulate device A's own removeDeviceKey having already run: it republishes
// the document with #k1 (itself, hypothetically revoked by a THIRD party
// scenario is unrealistic — more realistically this models device A removing
// some OTHER now-gone slot; what matters for this test is purely that `rm=`
// on the wire reaches device B and evicts a cached sibling) marked removed.
const docWithRemoval: DidDocument = {
  ...buildBisetDocument(did, rootPub, [], []),
  keyAgreementKeys: [{ n: 2, publicKey: deviceBKey.slice(0, 32) }],
  removedKeyNs: [1],
}
await fetch(`${URL_}/${did.replace('did:dht:', '')}`, { method: 'PUT', body: buildSignedPayload(rootPriv, docWithRemoval, 2) })

console.log('\n=== デバイスBがsyncDevicePositionを走らせる ===')
await syncDevicePosition(deviceBRec, [URL_]).catch(() => {})

const siblings = deviceBRec.didCommSiblingKeys ?? []
ok('#k1はもうsiblingに残っていない（rm=で伝播した削除を反映）', !siblings.some(s => s.kid === '#k1'), JSON.stringify(siblings))
ok('デバイスB自身は#k1を今後の republish でも removed として引き継ぐ', (deviceBRec.didCommRemovedKeys ?? []).includes('#k1'), JSON.stringify(deviceBRec.didCommRemovedKeys))

console.log('\n=== 削除されたはずのデバイスが、実際にはまだ生きてて自分で再publishしてきた ===')
// A separate identity, same reason did-sync-device-position.test.ts's own
// mismatch scenario uses one: resolve()'s 60s cache is keyed by DID, and
// would otherwise just hand back the previous scenario's already-resolved
// (still #k1-removed) result instead of hitting the gateway again here.
const rootPriv2 = ed25519.utils.randomSecretKey()
const rootPub2 = ed25519.getPublicKey(rootPriv2)
const did2 = didFromRootPublicKey(rootPub2)
const deviceCKey = ed25519.utils.randomSecretKey()
const deviceDKey = ed25519.utils.randomSecretKey()

const deviceDRec: DidRecord = {
  did: did2, email: did2,
  rootPrivateKey: bytesToHex(rootPriv2), rootPublicKey: bytesToHex(rootPub2),
  nostrPrivateKey: '', nostrPublicKey: '',
  didCommOwnKid: '#k2', didCommPublicKey: bytesToHex(deviceDKey.slice(0, 32)),
  didCommSiblingKeys: [],
  didCommRemovedKeys: ['#k1'], // device D already tombstoned #k1 locally
}
// #k1 shows up in a freshly resolved, validly-signed document — proof it's
// actually still alive, not the ghost the removal assumed.
const docWithK1Alive: DidDocument = {
  ...buildBisetDocument(did2, rootPub2, [], []),
  keyAgreementKeys: [
    { n: 1, publicKey: deviceCKey.slice(0, 32) },
    { n: 2, publicKey: deviceDKey.slice(0, 32) },
  ],
}
await fetch(`${URL_}/${did2.replace('did:dht:', '')}`, { method: 'PUT', body: buildSignedPayload(rootPriv2, docWithK1Alive) })

console.log('\n=== デバイスDがsyncDevicePositionを走らせる ===')
await syncDevicePosition(deviceDRec, [URL_]).catch(() => {})

const siblingsAfterReturn = deviceDRec.didCommSiblingKeys ?? []
ok('#k1が生きてる証拠(再publish)を見て、siblingとして復帰する', siblingsAfterReturn.some(s => s.kid === '#k1'), JSON.stringify(siblingsAfterReturn))
ok('#k1のtombstoneは解除される（forgive）', !(deviceDRec.didCommRemovedKeys ?? []).includes('#k1'), JSON.stringify(deviceDRec.didCommRemovedKeys))

console.log('\n=== 自分自身のkidがrm=で伝播してきても、自分では絶対にtombstoneしない（found live: y@biset.md #k1）===')
// Another device's bulk removal named a kid that's actually still alive — the
// device THAT kid belongs to must never end up believing it removed itself.
const rootPriv3 = ed25519.utils.randomSecretKey()
const rootPub3 = ed25519.getPublicKey(rootPriv3)
const did3 = didFromRootPublicKey(rootPub3)
const deviceEKey = ed25519.utils.randomSecretKey()
const deviceFKey = ed25519.utils.randomSecretKey()

const docNamingSelfRemoved: DidDocument = {
  ...buildBisetDocument(did3, rootPub3, [], []),
  keyAgreementKeys: [
    { n: 1, publicKey: deviceEKey.slice(0, 32) },
    { n: 2, publicKey: deviceFKey.slice(0, 32) },
  ],
  removedKeyNs: [1], // some OTHER device wrongly marked #k1 (device E itself) as removed
}
await fetch(`${URL_}/${did3.replace('did:dht:', '')}`, { method: 'PUT', body: buildSignedPayload(rootPriv3, docNamingSelfRemoved) })

const deviceERec: DidRecord = {
  did: did3, email: did3,
  rootPrivateKey: bytesToHex(rootPriv3), rootPublicKey: bytesToHex(rootPub3),
  nostrPrivateKey: '', nostrPublicKey: '',
  didCommOwnKid: '#k1', didCommPublicKey: bytesToHex(deviceEKey.slice(0, 32)),
  didCommSiblingKeys: [],
}
await syncDevicePosition(deviceERec, [URL_]).catch(() => {})
ok('自分のkid(#k1)は自分のremovedKeysに入らない', !(deviceERec.didCommRemovedKeys ?? []).includes('#k1'), JSON.stringify(deviceERec.didCommRemovedKeys))
ok('自分のkidは変わらず#k1のまま（自己排除しない）', deviceERec.didCommOwnKid === '#k1')

console.log('\n=== 既に汚染済み（過去に自分のkidが自分のremovedKeysに入ってしまっていた）場合も、次のsyncで浄化される ===')
const alreadyPoisonedRec: DidRecord = {
  did: did3, email: did3,
  rootPrivateKey: bytesToHex(rootPriv3), rootPublicKey: bytesToHex(rootPub3),
  nostrPrivateKey: '', nostrPublicKey: '',
  didCommOwnKid: '#k1', didCommPublicKey: bytesToHex(deviceEKey.slice(0, 32)),
  didCommSiblingKeys: [],
  didCommRemovedKeys: ['#k1'], // already poisoned from an earlier sync, before this fix
}
await syncDevicePosition(alreadyPoisonedRec, [URL_]).catch(() => {})
ok('既に汚染済みでも、次のsyncで自分のkidはremovedKeysから消える', !(alreadyPoisonedRec.didCommRemovedKeys ?? []).includes('#k1'), JSON.stringify(alreadyPoisonedRec.didCommRemovedKeys))

console.log(fails === 0 ? '\n  全て通過 — 削除がrm=経由で他デバイスのローカルキャッシュにも伝播し、生存証明があれば復帰でき、自分自身は絶対に自己排除しない\n' : `\n  ${fails} 件失敗\n`)
server.stop()
process.exit(fails === 0 ? 0 : 1)
