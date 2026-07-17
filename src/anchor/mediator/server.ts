// The DIDComm v2 mediator: Coordinate Mediation 2.0, Routing 2.0, Pickup 3.0.
// A client that can't hold a socket open (a browser) registers here, gives the
// mediator's URL out as its own DIDComm endpoint, and collects what arrives
// whenever it's next running.
//
// **This speaks biset's own DIDComm implementation (`src/did/didcomm/`), not a
// library.** It previously used `didcomm-node`, which loads its Rust core from
// a `.wasm` file it reads off disk at runtime (`readFileSync(__dirname +
// '/index_bg.wasm')`) — so `bun build --compile` cannot fold it into a
// standalone binary, and the anchor's "one artifact, no runtime dependencies"
// property could not survive absorbing it. Using our own is not a compromise
// forced by that: the client already had to implement pack/unpack to run in a
// browser, both sides of every message here are ours, and one implementation is
// the whole reason the mediator moved into this repo.
import { decodePeerDid2, type PeerIdentity, type PeerDidDoc } from '../../did/peer.ts'
import { buildPlaintext, publicKeyOf, type DidCommPlaintext } from '../../did/didcomm/message.ts'
import { packAuthcrypt, unpackAuthcrypt, unpackAnoncrypt, b64urlToBytes, type DidCommJWE } from '../../did/didcomm/crypto.ts'
import { MessageQueue } from './queue.ts'
import { ConnectionStore } from './connections.ts'

const MEDIATE_REQUEST = 'https://didcomm.org/coordinate-mediation/2.0/mediate-request'
const MEDIATE_GRANT = 'https://didcomm.org/coordinate-mediation/2.0/mediate-grant'
const KEYLIST_UPDATE = 'https://didcomm.org/coordinate-mediation/2.0/keylist-update'
const KEYLIST_UPDATE_RESPONSE = 'https://didcomm.org/coordinate-mediation/2.0/keylist-update-response'
const FORWARD = 'https://didcomm.org/routing/2.0/forward'
const STATUS_REQUEST = 'https://didcomm.org/messagepickup/3.0/status-request'
const STATUS = 'https://didcomm.org/messagepickup/3.0/status'
const DELIVERY_REQUEST = 'https://didcomm.org/messagepickup/3.0/delivery-request'
const DELIVERY = 'https://didcomm.org/messagepickup/3.0/delivery'

const DIDCOMM_CT = 'application/didcomm-encrypted+json'

/** Forward's `next`, keylist registrations and Pickup's `recipient_did` must
 * all agree on one spelling of a recipient, and callers legitimately send
 * either a bare DID or a full kid URL. Normalize every one of them to the bare
 * DID so the three line up. */
function stripFragment(didOrKidUrl: string): string {
  const i = didOrKidUrl.indexOf('#')
  return i === -1 ? didOrKidUrl : didOrKidUrl.slice(0, i)
}

/** did:peer:2 is self-certifying — the keys are *in* the DID string, so every
 * resolution here is a decode, never a network call. That is exactly why the
 * mediator can be strict about senders without needing a DHT gateway. */
function docFor(did: string): PeerDidDoc {
  return decodePeerDid2(did)
}

function xKidOf(doc: PeerDidDoc): string {
  const kid = doc.keyAgreement[0]
  if (!kid) throw new Error(`${doc.id} has no keyAgreement key`)
  return kid
}

const utf8 = (s: string) => new TextEncoder().encode(s)

export interface MediatorOptions {
  mediator: PeerIdentity
  queue?: MessageQueue
  connections?: ConnectionStore
}

export interface MediatorHandler {
  /** Handles a mediator request, or returns null if the path isn't ours. */
  handle(req: Request, url: URL): Promise<Response | null>
  mediatorDid: string
}

export function createMediator({ mediator, queue = new MessageQueue(), connections = new ConnectionStore() }: MediatorOptions): MediatorHandler {
  const ownRecipient = { kid: mediator.xKid, privateKey: mediator.xPriv }

  /** The sender's key comes out of its own did:peer string, so a forged `skid`
   * cannot name a key the sender doesn't hold — authcrypt then fails to
   * decrypt, which is the authentication. */
  function resolveSenderKey(senderKid: string): Uint8Array {
    const did = stripFragment(senderKid)
    const doc = docFor(did)
    return publicKeyOf(doc, senderKid === did ? xKidOf(doc) : senderKid)
  }

  function packReplyTo(toDid: string, type: string, body: unknown, attachments?: DidCommPlaintext['attachments']): string {
    const plaintext = buildPlaintext(type, body, mediator.did, toDid)
    if (attachments) plaintext.attachments = attachments
    const toDoc = docFor(toDid)
    const toKid = xKidOf(toDoc)
    const jwe = packAuthcrypt(
      utf8(JSON.stringify(plaintext)),
      { kid: mediator.xKid, privateKey: mediator.xPriv },
      { kid: toKid, publicKey: publicKeyOf(toDoc, toKid) },
    )
    return JSON.stringify(jwe)
  }

  const reply = (packed: string) => new Response(packed, { status: 200, headers: { 'content-type': DIDCOMM_CT } })

  /** Unpacks either flavour. The `alg` header decides: Forward is anoncrypt by
   * design — the whole point of routing is that the mediator learns where to
   * queue, not who sent it — while everything else is authcrypt'd and carries
   * a verified sender. */
  async function unpack(raw: string): Promise<{ msg: DidCommPlaintext; senderKid: string | null }> {
    const jwe = JSON.parse(raw) as DidCommJWE
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
    if (header.alg === 'ECDH-ES+A256KW') {
      const plaintext = await unpackAnoncrypt(jwe, ownRecipient)
      return { msg: JSON.parse(new TextDecoder().decode(plaintext)), senderKid: null }
    }
    const { plaintext, senderKid } = await unpackAuthcrypt(jwe, ownRecipient, resolveSenderKey)
    return { msg: JSON.parse(new TextDecoder().decode(plaintext)), senderKid }
  }

  async function handle(req: Request, url: URL): Promise<Response | null> {
    if (req.method === 'GET' && url.pathname === '/.well-known/did.json') {
      return Response.json(mediator.doc)
    }
    if (url.pathname !== '/' || req.method !== 'POST') return null

    let msg: DidCommPlaintext
    try {
      ;({ msg } = await unpack(await req.text()))
    } catch (e) {
      return Response.json({ error: String(e) }, { status: 400 })
    }

    // `from` is the sender's own claim, but authcrypt already proved they hold
    // that DID's key (resolveSenderKey above), so it is safe to trust here.
    const fromDid: string | undefined = msg.from
    if (msg.type !== FORWARD && !fromDid) {
      return Response.json({ error: 'message has no `from` — this message type requires an authenticated sender' }, { status: 400 })
    }

    switch (msg.type) {
      case MEDIATE_REQUEST: {
        connections.register(fromDid!)
        return reply(packReplyTo(fromDid!, MEDIATE_GRANT, { routing_did: mediator.did }))
      }

      case KEYLIST_UPDATE: {
        const updates: Array<{ recipient_did: string; action: 'add' | 'remove' }> = (msg.body as any)?.updates ?? []
        const updated = updates.map(u => {
          const kid = stripFragment(u.recipient_did)
          if (u.action === 'add') connections.addKey(fromDid!, kid)
          else connections.removeKey(fromDid!, kid)
          return { recipient_did: u.recipient_did, action: u.action, result: 'success' }
        })
        return reply(packReplyTo(fromDid!, KEYLIST_UPDATE_RESPONSE, { updated }))
      }

      case FORWARD: {
        // Routing 2.0's shape, which biset's own send.ts builds: `next` in the
        // body, the opaque re-wrapped JWE as the single attachment. We never
        // decrypt that inner message — we can't, and that's the point.
        const next = (msg.body as any)?.next
        const forwarded = msg.attachments?.[0]?.data?.json
        if (!next || forwarded === undefined) {
          return Response.json({ error: 'forward is missing `next` or its attachment' }, { status: 400 })
        }
        const kid = stripFragment(next)
        if (!connections.isAuthorized(kid)) {
          return Response.json({ error: 'uncoordinated recipient — no keylist-update registered this kid' }, { status: 401 })
        }
        queue.push(kid, JSON.stringify(forwarded))
        return new Response(null, { status: 202 })
      }

      case STATUS_REQUEST: {
        const kid = stripFragment((msg.body as any)?.recipient_did ?? fromDid!)
        return reply(packReplyTo(fromDid!, STATUS, { recipient_did: kid, message_count: queue.count(kid) }))
      }

      case DELIVERY_REQUEST: {
        const kid = stripFragment((msg.body as any)?.recipient_did ?? fromDid!)
        const limit: number = (msg.body as any)?.limit ?? 10
        const batch = queue.take(kid, limit)
        if (batch.length === 0) {
          return reply(packReplyTo(fromDid!, STATUS, { recipient_did: kid, message_count: 0 }))
        }
        const attachments = batch.map((packed, i) => ({
          id: `msg-${i}-${crypto.randomUUID()}`,
          data: { json: JSON.parse(packed) },
        }))
        return reply(packReplyTo(fromDid!, DELIVERY, { recipient_did: kid }, attachments))
      }

      default:
        return Response.json({ error: 'unsupported message type', type: msg.type }, { status: 400 })
    }
  }

  return { handle, mediatorDid: mediator.did }
}
