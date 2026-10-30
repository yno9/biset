import { generatePeerIdentity } from '../src/protocol/didcomm/peer.ts'
import { buildPlaintext } from '../src/protocol/didcomm/message.ts'
import { packAnoncrypt, packAuthcrypt } from '../src/protocol/didcomm/crypto.ts'
import { fetchMediatorInfo } from '../src/protocol/didcomm/mediator-transport.ts'
import { queryRecipients, updateRecipient } from '../src/protocol/didcomm/mediator-coordinate.ts'
import { registerWithMediator } from '../src/client/didcomm/mediator-sync.ts'
import { acknowledgeMessages, pickupDeliver, pickupStatus } from '../src/protocol/didcomm/mediator-pickup.ts'

const url = (process.argv[2] ?? '').replace(/\/$/, '')
if (!url) throw new Error('usage: node scripts/didcomm-mediator-smoke.ts https://mediator.example')

const alice = generatePeerIdentity()
const bobPeer = generatePeerIdentity()
const bob = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'smoke-canary' }
let registered = false

try {
  const mediator = await registerWithMediator(url, bob)
  registered = true
  const keys = await queryRecipients(mediator, bob)
  // recipient-query lists when each inbox was last used, never its label.
  if (keys.length !== 1) throw new Error(`recipient-query lists ${keys.length} inboxes for a fresh DID, expected 1`)

  const inner = buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content: 'production canary' }, alice.did, bob.did)
  const innerJwe = packAuthcrypt(
    new TextEncoder().encode(JSON.stringify(inner)),
    { kid: alice.xKid, privateKey: alice.xPriv },
    [{ kid: bob.xKid, publicKey: bobPeer.xPub }],
  )
  const forward = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next: bob.xKid })
  forward.attachments = [{ id: 'canary', data: { json: innerJwe } }]
  const forwardJwe = packAnoncrypt(
    new TextEncoder().encode(JSON.stringify(forward)),
    [{ kid: mediator.xKid, publicKey: mediator.xPub }],
  )
  const accepted = await fetch(`${url}/`, {
    method: 'POST',
    headers: { 'content-type': 'application/didcomm-encrypted+json' },
    body: JSON.stringify(forwardJwe),
  })
  if (accepted.status !== 202) throw new Error(`Forward was not accepted: HTTP ${accepted.status} ${await accepted.text()}`)
  if ((await pickupStatus(mediator, bob)).messageCount !== 1) throw new Error('accepted Forward is absent from pickup status')
  const pauseAfterForwardMs = Number(process.env.MEDIATOR_SMOKE_PAUSE_AFTER_FORWARD_MS ?? 0)
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
  if ((await acknowledgeMessages(mediator, bob, [delivered[0]!.ackId])).messageCount !== 0) throw new Error('ACK did not empty canary queue')

  console.info(JSON.stringify({ ok: true, service: 'biset-didcomm-mediator', url, mediatorDid: (await fetchMediatorInfo(url)).did }))
} finally {
  if (registered) {
    const mediator = await fetchMediatorInfo(url)
    await updateRecipient(mediator, bob, 'remove').catch(error => {
      console.error(`canary cleanup failed: ${error instanceof Error ? error.message : String(error)}`)
      process.exitCode = 1
    })
  }
}
