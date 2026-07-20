// Proves DIDComm messages render through the SAME left-column-inbox /
// right-column-thread machinery every other conversation uses — no separate
// "/didcomm" page, no separate data model (did/didcomm/channel.ts's whole
// point). Drives the REAL wire protocol (sendDidComm/pickupDeliver, proven
// separately in mediator-multidevice.test.ts) against a real in-process
// mediator, converts delivered messages with the SAME didCommToEmail the
// production poll loop uses, stores them in the SAME store/messages.ts Map,
// and asserts app.ts's loadInboxSummaries()/getInboxEmails() — the actual
// functions left-pane.ts and the thread view call — surface them correctly.
// Skips persist.flushMessage (IndexedDB, browser-only) — messages.put() is
// the same in-memory store either way, so this covers the rendering path
// exactly, just not the reload-durability side (covered by inspection: see
// channel.ts's own comment on why pickup being destructive requires it).
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
import { didCommToEmail } from '../src/did/didcomm/channel.ts'
import { addSession, accountKey, DIDCOMM_SERVER_URL, sessions } from '../src/context.ts'
import * as messages from '../src/store/messages.ts'
import { loadInboxSummaries, getInboxEmails } from '../src/app.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

const dir = mkdtempSync(join(tmpdir(), 'medtest-channel-'))
const PORT = 8903
const URL_ = `http://127.0.0.1:${PORT}`

const ALICE_DID = 'did:dht:testchannelalice'
const aliceKey = { priv: x25519.utils.randomSecretKey(), pub: undefined as unknown as Uint8Array }
aliceKey.pub = x25519.getPublicKey(aliceKey.priv)

// A second device for Alice's SAME identity (her #k2) — document.ts's
// DidKeyAgreement design has every registered device add its own
// keyAgreement entry to the one shared did:dht document, which is what lets
// a single send fan out to every device (mediator-multidevice.test.ts) AND
// is the whole mechanism channel.ts's syncToSiblingDevices piggybacks on to
// reach a SECOND device with the OWNER'S OWN sent messages (self-sync test
// below) — no separate roster, no new mediator API.
const aliceKey2 = { priv: x25519.utils.randomSecretKey(), pub: undefined as unknown as Uint8Array }
aliceKey2.pub = x25519.getPublicKey(aliceKey2.priv)

const keysByKid = new Map<string, Uint8Array>([[`${ALICE_DID}#k1`, aliceKey.pub], [`${ALICE_DID}#k2`, aliceKey2.pub]])
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
const alice = { did: ALICE_DID, xKid: `${ALICE_DID}#k1`, xPriv: aliceKey.priv }
await requestMediation(info, alice)
await updateKeylist(info, alice, alice.xKid, 'add')

// Alice's second device — registers independently, same identity, own kid.
const aliceDevice2 = { did: ALICE_DID, xKid: `${ALICE_DID}#k2`, xPriv: aliceKey2.priv }
await requestMediation(info, aliceDevice2)
await updateKeylist(info, aliceDevice2, aliceDevice2.xKid, 'add')

// Bob: a real did:peer sender (mirrors an ordinary correspondent, not
// necessarily another relay-less biset user).
const bob = generatePeerIdentity()
const bobSender = { did: bob.did, xKid: bob.xKid, xPriv: bob.xPriv }
const aliceDoc: PeerDidDoc = {
  id: ALICE_DID,
  keyAgreement: [alice.xKid],
  authentication: [],
  verificationMethod: [{ id: alice.xKid, type: 'JsonWebKey2020', controller: ALICE_DID, publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: b64url(aliceKey.pub) } }],
  service: [{ id: `${ALICE_DID}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: URL_, accept: ['didcomm/v2'], routing_keys: [mediatorIdentity.xKid] } }],
}

console.log('\n=== Bob が Alice に DIDComm でメッセージを送る ===')
const marker = 'hey alice, same UI please'
await sendDidComm(bobSender, ALICE_DID, aliceDoc, { type: 'https://didcomm.org/basicmessage/2.0/message', body: { content: marker } })

console.log('\n=== Alice が pickup し、channel.ts と同じ変換で Email として store に入れる ===')
const resolveSenderKeyForBob = async (kid: string) => (kid === bob.xKid ? bob.xPub : (() => { throw new Error('unexpected sender') })())
const delivered = await pickupDeliver(info, alice, resolveSenderKeyForBob)
ok('1通届く', delivered.length === 1, `got ${delivered.length}`)

const d = delivered[0]!
const content = (d.plaintext as any)?.body?.content as string
const fromDid = d.senderKid.split('#')[0]!
const email = didCommToEmail(crypto.randomUUID(), ALICE_DID, fromDid, ALICE_DID, content, new Date().toISOString())
const acct = accountKey({ email: ALICE_DID, serverUrl: DIDCOMM_SERVER_URL })
;(email as any)._account = acct
;(email as any)._relay = DIDCOMM_SERVER_URL
messages.put(email)

console.log('\n=== 合成 session を登録し、app.ts の実関数（UIが呼ぶのと同じもの）を通す ===')
addSession({
  account: { serverUrl: DIDCOMM_SERVER_URL, email: ALICE_DID, password: '', did: ALICE_DID },
  jmapAccountId: '',
  jmapClient: null as any,
  eventSourceUrl: null,
})
ok('sessions[] に登録された', sessions.some(s => s.account.did === ALICE_DID))

const inboxes = await loadInboxSummaries()
const row = inboxes.find(i => i.contact === bob.did)
ok('loadInboxSummaries() に Bob との会話が1行出る', !!row, JSON.stringify(inboxes.map(i => i.contact)))
ok('unread としてカウントされる', row?.has_unread === true)
ok('latest_body が届いた本文と一致', row?.latest_body === marker)

if (row) {
  const emails = getInboxEmails(row.mailbox, row.contact, ALICE_DID, ALICE_DID)
  ok('getInboxEmails() が1通返す（右カラムのスレッド用）', emails.length === 1, `got ${emails.length}`)
  ok('中身も一致', (Object.values(emails[0]?.bodyValues ?? {})[0] as any)?.value === marker)
}

console.log('\n=== Alice が Bob に返信 — 自分の送信コピーが自分のスレッドに乗る（送信者側 mailbox の回帰テスト）===')
// Mirrors exactly what sendViaDidComm (channel.ts) does for its own local
// optimistic copy: mailboxDid = fromDid = the SENDER (Alice, filed in HER
// OWN mailbox), toDid = the recipient (Bob). The bug this guards against
// swapped mailboxDid for toDid, filing a sender's own outgoing messages
// under the RECIPIENT's mailbox instead — invisible in the sender's own UI
// (sendViaDidComm itself isn't called here: ownSender() needs IndexedDB,
// unavailable in this headless test — see channel.ts's own note on that).
const replyMarker = 'thanks bob, replying'
// A distinct, guaranteed-later timestamp — two new Date().toISOString() calls
// back-to-back can land on the same millisecond, making "latest" ambiguous
// and this test flaky depending on system timing.
const replyTs = new Date(Date.now() + 1000).toISOString()
const replyEmail = didCommToEmail(crypto.randomUUID(), ALICE_DID, ALICE_DID, bob.did, replyMarker, replyTs)
;(replyEmail as any)._account = acct
;(replyEmail as any)._relay = DIDCOMM_SERVER_URL
messages.put(replyEmail)

const inboxes2 = await loadInboxSummaries()
const row2 = inboxes2.find(i => i.contact === bob.did)
ok('返信後も Bob との会話が1行のまま', !!row2, JSON.stringify(inboxes2.map(i => i.contact)))
ok('latest_body が自分の返信に更新される', row2?.latest_body === replyMarker)
if (row2) {
  const emails2 = getInboxEmails(row2.mailbox, row2.contact, ALICE_DID, ALICE_DID)
  ok('getInboxEmails() が自分の送信コピーを含め2通返す', emails2.length === 2, `got ${emails2.length}`)
}

console.log('\n=== relay持ちアイデンティティのDIDComm送信 — account.email(relay) ≠ DID の回帰テスト ===')
// Every prior check above used a session whose account.email IS the DID
// (ALICE_DID) — the pure-standalone shape — which can never expose this bug:
// loadInboxSummaries/getInboxEmails's "is this MY OWN sent message" check
// compared a DIDComm message's `from` (always a DID) against account.email/
// jmapAccountId only, never the DID. A relay-backed identity that ALSO
// registers DIDComm (the common case, not the edge case — y@biset.md in
// production) has account.email = its relay address, so that check was
// ALWAYS false for its own sent DIDComm messages: the inbox summary read
// them as "received FROM myself" (contact ends up being the identity's own
// DID, indistinguishable from its own mailbox), and it counted its own sent
// messages as unread. This is the exact "mailbox and contact are the same
// DID" / "sent message never leaves the pending/dim state" bug reported live.
const CAROL_DID = 'did:dht:testchannelcarol'
const CAROL_RELAY_EMAIL = 'carol@relay.example' // deliberately NOT equal to CAROL_DID
addSession({
  account: { serverUrl: 'https://relay.example', email: CAROL_RELAY_EMAIL, password: '', did: CAROL_DID },
  jmapAccountId: '',
  jmapClient: null as any,
  eventSourceUrl: null,
})
addSession({
  account: { serverUrl: DIDCOMM_SERVER_URL, email: CAROL_DID, password: '', did: CAROL_DID },
  jmapAccountId: '',
  jmapClient: null as any,
  eventSourceUrl: null,
})
const carolAcct = accountKey({ email: CAROL_DID, serverUrl: DIDCOMM_SERVER_URL })
const carolSentEmail = didCommToEmail(crypto.randomUUID(), CAROL_DID, CAROL_DID, bob.did, 'hi bob, from carol', new Date().toISOString())
;(carolSentEmail as any)._account = carolAcct
;(carolSentEmail as any)._relay = DIDCOMM_SERVER_URL
messages.put(carolSentEmail)

const carolInboxes = await loadInboxSummaries()
// Keyed on user===CAROL_RELAY_EMAIL specifically, not contact===bob.did —
// Alice (registered earlier in this file) also messages bob.did, and would
// wrongly satisfy an OR'd match.
const carolRow = carolInboxes.find(i => i.user === CAROL_RELAY_EMAIL)
ok('相手(bob)とのスレッドとして出る（自分自身とのスレッドになっていない）', carolRow?.contact === bob.did, JSON.stringify(carolRow))
ok('自分の送信は未読扱いにならない', carolRow?.has_unread === false, JSON.stringify(carolRow))
if (carolRow) {
  const carolEmails = getInboxEmails(carolRow.mailbox, carolRow.contact, CAROL_RELAY_EMAIL, CAROL_DID)
  ok('getInboxEmails() が自分の送信コピーを返す', carolEmails.length === 1, `got ${carolEmails.length}`)
}

console.log('\n=== マルチデバイス自己同期 — Aliceのデバイス1がBobに送った分がデバイス2にも届く ===')
// Exactly what channel.ts's syncToSiblingDevices does: encrypt the SAME
// message a second time, addressed to Alice's OWN other device kid (#k2),
// with keyAgreement filtered down to just that sibling — verificationMethod
// keeps both entries (publicKeyOf needs #k1's own entry to exist even though
// it's not a send target), mirroring the `{ ...selfDoc, keyAgreement:
// siblings }` shape the real code builds from a resolved self-document.
const aliceSelfDocForDevice2: PeerDidDoc = {
  id: ALICE_DID,
  keyAgreement: [aliceDevice2.xKid],
  authentication: [],
  verificationMethod: [
    { id: alice.xKid, type: 'JsonWebKey2020', controller: ALICE_DID, publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: b64url(aliceKey.pub) } },
    { id: aliceDevice2.xKid, type: 'JsonWebKey2020', controller: ALICE_DID, publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: b64url(aliceKey2.pub) } },
  ],
  service: [{ id: `${ALICE_DID}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: URL_, accept: ['didcomm/v2'], routing_keys: [mediatorIdentity.xKid] } }],
}
const syncMarker = 'hey bob, sent from my other browser'
const syncSentAt = new Date(Date.now() + 2000).toISOString()
const syncId = crypto.randomUUID()
await sendDidComm(alice, ALICE_DID, aliceSelfDocForDevice2, {
  type: 'https://didcomm.org/basicmessage/2.0/message',
  body: { content: syncMarker, id: syncId, syncTo: bob.did, sentAt: syncSentAt, fromName: 'Alice' },
})

const resolveSenderKeyForAliceDevice1 = async (kid: string) => (kid === alice.xKid ? aliceKey.pub : (() => { throw new Error('unexpected sender') })())
const deliveredToDevice2 = await pickupDeliver(info, aliceDevice2, resolveSenderKeyForAliceDevice1)
ok('デバイス2に1通届く', deliveredToDevice2.length === 1, `got ${deliveredToDevice2.length}`)

if (deliveredToDevice2[0]) {
  const d2 = deliveredToDevice2[0]
  const senderDid2 = d2.senderKid.split('#')[0]!
  ok('送信者が自分自身(Alice)だと認証される', senderDid2 === ALICE_DID, senderDid2)
  const body2 = d2.plaintext as any
  ok('中身が一致', body2?.body?.content === syncMarker)
  ok('syncTo に本当の宛先(Bob)が乗っている', body2?.body?.syncTo === bob.did)

  // channel.ts's pollDidCommOnce isOwnSync branch, inlined exactly — same
  // reason the rest of this file inlines didCommToEmail calls instead of
  // calling pollDidCommOnce itself: ownSender() needs IndexedDB.
  const syncEmail = didCommToEmail(body2.id, ALICE_DID, ALICE_DID, body2.body.syncTo, body2.body.content, body2.body.sentAt, body2.body.fromName, '')
  ;(syncEmail.keywords as any)['$seen'] = true
  ;(syncEmail as any)._account = acct // same acctKey as device 1 — same identity, same synthetic session shape
  ;(syncEmail as any)._relay = DIDCOMM_SERVER_URL
  messages.put(syncEmail)

  // Own $seen flag, not the thread's aggregate has_unread — this Bob thread
  // already carries an earlier, genuinely-unread message from him (the first
  // test above), so the aggregate staying true is that message's, not a sign
  // this sync copy was mis-filed as unread.
  ok('自分の送信として $seen が立っている', !!(syncEmail.keywords as any)['$seen'])

  const device2Inboxes = await loadInboxSummaries()
  const device2Row = device2Inboxes.find(i => i.contact === bob.did)
  ok('デバイス2のUIにも Bob とのスレッドとして出る（自分宛の会話になっていない）', device2Row?.contact === bob.did, JSON.stringify(device2Row))
  ok('本文がデバイス1で送った内容と一致', device2Row?.latest_body === syncMarker)
}

console.log(fails === 0 ? '\n  全て通過 — DIDComm は既存の inbox/thread と同じ経路で描画される\n' : `\n  ${fails} 件失敗\n`)
server.stop()
rmSync(dir, { recursive: true, force: true })
process.exit(fails === 0 ? 0 : 1)
