// Multi-hop relay: this mediator's own client-role identity, registered
// with an UPSTREAM mediator so it can be named as an intermediate hop in a
// recipient's routing.json (webvh-routing.ts's `routingKeys`, ordered
// outermost-first). Polls the upstream for whatever a sender Forward-wrapped
// to THIS hop's kid, unwraps one anoncrypt layer, and re-Forwards the still-
// opaque payload into this mediator's own queue via `deliverLocally`.
//
// Neither mediator's dispatch() needs to change for this to work (the
// 2026-08-30 hop-chain discussion's whole point): from the upstream's point
// of view this poller is an ordinary registered connection, like any
// end-user device (mediator-sync.ts's startMediatorPolling); from this
// mediator's point of view the re-Forward it produces is an ordinary
// inbound Forward request, indistinguishable from one a real sender built
// directly.
import { fetchMediatorInfo, requestMediation, updateKeylist, type MediatorInfo } from '../../shared/didcomm/mediator-coordinate.ts'
import { acknowledgeMessages } from '../../shared/didcomm/mediator-pickup.ts'
import { sendAndUnpack, type DidCommSender } from '../../shared/didcomm/mediator-transport.ts'
import { unpackAnoncrypt, parseJwe, type DidCommJWE } from '../../shared/didcomm/crypto.ts'
import { wrapForward } from '../../shared/didcomm/forward-wrap.ts'
import { FORWARD, STATUS, DELIVERY_REQUEST, DELIVERY } from '../../shared/didcomm/mediator-protocol.ts'
import type { DidCommPlaintext } from '../../shared/didcomm/message.ts'
import { defaultFetch } from '../../client/app/net-fetch.ts'

/** Same self-heal shape as mediator-sync.ts's registerWithMediator: safe to
 * call on every tick before we know whether the upstream already has us. */
async function registerAsHop(upstreamUrl: string, own: DidCommSender, fetchImpl: typeof fetch): Promise<MediatorInfo> {
  const mediator = await fetchMediatorInfo(upstreamUrl, fetchImpl)
  await requestMediation(mediator, own, fetchImpl)
  await updateKeylist(mediator, own, own.xKid, 'add', fetchImpl)
  return mediator
}

export interface RelayPollHandle {
  stop(): void
}

export interface RelayPollOptions {
  intervalMs?: number
  fetch?: typeof fetch
  /** Called with whatever the poll tick itself failed on (upstream down,
   * transport error, a malformed queued item, …). The loop keeps running
   * either way. */
  onError?: (e: unknown) => void
}

/** Starts polling `upstreamUrl` for messages queued at `own.xKid` (this
 * mediator's own relay-poller identity, `SqliteMediatorStore.
 * loadRelayPollerIdentity`). Each delivered item is expected to be an
 * anoncrypt Routing 2.0 Forward addressed to `own.xKid` -- the layer a
 * sender built for THIS hop (didcomm/forward-wrap.ts's `wrapForward`,
 * possibly nested further inside another Forward for a hop beyond this
 * one). Unwraps exactly one layer, then re-Forwards the inner attachment
 * to `localRoutingKid` (this mediator's OWN routing kid) via
 * `deliverLocally` -- ordinary self-addressed Forward, queued by this same
 * mediator's dispatch loop for whichever `next` kid the sender named. */
export function startRelayPoller(
  upstreamUrl: string,
  own: DidCommSender,
  localRoutingKid: string,
  deliverLocally: (outbound: DidCommJWE) => Promise<void>,
  opts: RelayPollOptions = {},
): RelayPollHandle {
  const intervalMs = opts.intervalMs ?? 15_000
  const fetchImpl = opts.fetch ?? defaultFetch()
  let stopped = false
  let inFlight = false
  let registered = false

  const tick = async () => {
    if (stopped || inFlight) return
    inFlight = true
    try {
      const mediator = registered
        ? await fetchMediatorInfo(upstreamUrl, fetchImpl)
        : await registerAsHop(upstreamUrl, own, fetchImpl)
      registered = true

      const reply = await sendAndUnpack(mediator, own, DELIVERY_REQUEST, { recipient_did: own.xKid, limit: 10 }, fetchImpl)
      if (reply.type === STATUS) return // nothing queued
      if (reply.type !== DELIVERY) throw new Error(`relay poll: unexpected reply type ${reply.type}`)

      const attachments = reply.attachments ?? []
      const ackIds: string[] = []
      for (const att of attachments) {
        try {
          const queued = parseJwe(att.data.json)
          if (!queued) throw new Error('queued attachment is not a DIDComm JWE')
          const plaintextBytes = await unpackAnoncrypt(queued, { kid: own.xKid, privateKey: own.xPriv })
          const forward = JSON.parse(new TextDecoder().decode(plaintextBytes)) as DidCommPlaintext
          if (forward.type !== FORWARD) throw new Error(`relay poll: queued item is not a Forward (${forward.type})`)
          const next = (forward.body as { next?: unknown } | undefined)?.next
          const forwarded = forward.attachments?.[0]?.data?.json as DidCommJWE | undefined
          if (typeof next !== 'string' || !next || forwarded === undefined) {
            throw new Error('relay poll: forward is missing `next` or its attachment')
          }
          await deliverLocally(wrapForward(forwarded, next, localRoutingKid))
          ackIds.push(att.id)
        } catch (e) {
          // One malformed/undeliverable item must not block the rest of the
          // batch or leave it acknowledged -- left queued for retry, same
          // resilience shape as mediator-pickup.ts's own per-attachment try.
          opts.onError?.(e)
          console.warn(`[mediator] relay poll of ${upstreamUrl} skipped an item (${att.id}):`, e instanceof Error ? e.message : e)
        }
      }
      if (ackIds.length) await acknowledgeMessages(mediator, own, ackIds, fetchImpl)
    } catch (e) {
      opts.onError?.(e)
      console.warn(`[mediator] relay poll of ${upstreamUrl} failed (will retry next tick):`, e instanceof Error ? e.message : e)
    } finally {
      inFlight = false
    }
  }

  const timer = setInterval(() => { void tick() }, intervalMs)
  void tick()

  return {
    stop() {
      if (stopped) return
      stopped = true
      clearInterval(timer)
    },
  }
}
