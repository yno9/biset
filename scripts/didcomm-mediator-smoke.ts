import { generatePeerIdentity } from '../src/didcomm/peer.ts'
import { buildPlaintext } from '../src/didcomm/message.ts'
import { packAnoncrypt, packAuthcrypt } from '../src/didcomm/crypto.ts'
import { fetchMediatorInfo } from '../src/didcomm/mediator-transport.ts'
import { queryKeylist, updateKeylist } from '../src/didcomm/mediator-coordinate.ts'
import { registerWithMediator } from '../src/didcomm/mediator-sync.ts'
import { acknowledgeMessages, pickupDeliver, pickupStatus } from '../src/didcomm/mediator-pickup.ts'

const url = (process.argv[2] ?? '').replace(/\/$/, '')
if (!url) throw new Error('usage: bun run scripts/didcomm-mediator-smoke.ts https://mediator.example')

const alice = generatePeerIdentity()
const bobPeer = generatePeerIdentity()
const bob = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv }
let registered = false

try {
  const mediator = await registerWithMediator(url, bob)
  registered = true
  const keys = await queryKeylist(mediator, bob)
  if (!keys.some(entry => entry.kid === bob.xKid)) throw new Error('registered key is absent from keylist-query')

  const inner = buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content: 'production canary' }, alice.did, bob.did)
  const innerJwe = packAuthcrypt(
    new TextEncoder().encode(JSON.stringify(inner)),
    { kid: alice.xKid, privateKey: alice.xPriv },
    { kid: bob.xKid, publicKey: bobPeer.xPub },
  )
  const forward = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next: bob.xKid })
  forward.attachments = [{ id: 'canary', data: { json: innerJwe } }]
  const forwardJwe = packAnoncrypt(
    new TextEncoder().encode(JSON.stringify(forward)),
    { kid: mediator.xKid, publicKey: mediator.xPub },
  )
  const accepted = await fetch(`${url}/`, {
    method: 'POST',
    headers: { 'content-type': 'application/didcomm-encrypted+json' },
    body: JSON.stringify(forwardJwe),
  })
  if (accepted.status !== 202) throw new Error(`Forward was not accepted: HTTP ${accepted.status} ${await accepted.text()}`)
  if (await pickupStatus(mediator, bob) !== 1) throw new Error('accepted Forward is absent from pickup status')
  const pauseAfterForwardMs = Number(Bun.env.MEDIATOR_SMOKE_PAUSE_AFTER_FORWARD_MS ?? 0)
  if (pauseAfterForwardMs > 0) {
    console.info(JSON.stringify({ stage: 'forward-accepted', pauseAfterForwardMs }))
    await new Promise(resolve => setTimeout(resolve, pauseAfterForwardMs))
  }

  const delivered = await pickupDeliver(mediator, bob, async kid => {
    if (kid !== alice.xKid) throw new Error(`unexpected sender kid ${kid}`)
    return alice.xPub
  })
  if (delivered.length !== 1) throw new Error(`expected one delivery, got ${delivered.length}`)
  const plaintext = delivered[0]!.plaintext as { body?: { content?: string } }
  if (plaintext.body?.content !== 'production canary') throw new Error('delivered plaintext does not match canary')
  if (await acknowledgeMessages(mediator, bob, [delivered[0]!.ackId]) !== 0) throw new Error('ACK did not empty canary queue')

  console.info(JSON.stringify({ ok: true, service: 'biset-didcomm-mediator', url, mediatorDid: (await fetchMediatorInfo(url)).did }))
} finally {
  if (registered) {
    const mediator = await fetchMediatorInfo(url)
    await updateKeylist(mediator, bob, bob.xKid, 'remove').catch(error => {
      console.error(`canary cleanup failed: ${error instanceof Error ? error.message : String(error)}`)
      process.exitCode = 1
    })
  }
}
