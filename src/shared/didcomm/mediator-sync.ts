// Registration (self-heal on every boot) + a per-mediator poll loop. A
// device may be registered with several independent mediators at once
// (ARC.md's 2026-08-27 redesign -- non-centralization is the point), so
// this is deliberately per-mediator-URL: the caller starts one of these per
// registered mediator, never a single shared loop.
//
// Ported in spirit from src.bak/did/didcomm/channel.ts's
// reassertKeylistRegistration + startDidCommPolling, but without that
// file's did:dht-era session/IndexedDB record bookkeeping (getDidRecord,
// storeDidRecord, sessions) -- biset's own DIDComm identity is the
// identity-shared vault credential (vault/didcomm-credential.ts), already
// resolved by the caller into a plain DidCommSender, so this module only
// needs the mediator URL and that sender.
import { fetchMediatorInfo, requestMediation, updateKeylist, type MediatorInfo } from './mediator-coordinate.ts'
import { pickupDeliver, acknowledgeMessages, type DeliveredMessage } from './mediator-pickup.ts'
import type { DidCommSender } from './mediator-transport.ts'
import type { ResolveSenderKey } from './crypto.ts'
import { defaultFetch } from '../../client/app/net-fetch.ts'

/** mediate-request + keylist-update(add), unconditionally -- both are
 * idempotent (keylist-update reports `no_change` rather than erroring when
 * already registered), so calling this on every boot is the self-heal: it
 * repairs a mediator that lost this device's registration (its
 * ConnectionStore was reset, say) without needing to detect that case
 * specially. Safe to call repeatedly; the caller decides the cadence. */
export async function registerWithMediator(mediatorUrl: string, own: DidCommSender, fetchImpl: typeof fetch = defaultFetch()): Promise<MediatorInfo> {
  const mediator = await fetchMediatorInfo(mediatorUrl, fetchImpl)
  await requestMediation(mediator, own, fetchImpl)
  await updateKeylist(mediator, own, own.xKid, 'add', fetchImpl)
  return mediator
}

export interface MediatorPollHandle {
  stop(): void
}

export interface MediatorPollOptions {
  intervalMs?: number
  fetch?: typeof fetch
  /** Called with whatever the poll tick itself failed on (mediator down,
   * transport error, …) -- never for a single undeliverable message inside
   * a batch, which pickupDeliver already skips and logs on its own. The
   * loop keeps running either way; this is for the caller's own visibility
   * (a status indicator, say), not a signal to stop. */
  onError?: (e: unknown) => void
}

/** Starts polling ONE mediator for messages queued at `own.xKid`. Each
 * successfully-handled message (onMessage did not throw) is acknowledged;
 * one that throws is left unacknowledged so the mediator redelivers it next
 * tick (mirrors pickupDeliver's own per-message resilience, one level up:
 * an ingress-projector failure for one message must not lose the rest of
 * the batch or stop the loop). Returns a handle whose `stop()` cancels the
 * interval -- call it once (idempotent; a repeat stop is a no-op). */
export function startMediatorPolling(
  mediatorUrl: string,
  own: DidCommSender,
  resolveSenderKey: ResolveSenderKey,
  onMessage: (msg: DeliveredMessage) => Promise<void> | void,
  opts: MediatorPollOptions = {},
): MediatorPollHandle {
  const intervalMs = opts.intervalMs ?? 15_000
  const fetchImpl = opts.fetch ?? defaultFetch()
  let stopped = false
  let inFlight = false
  let registered = false

  const tick = async () => {
    if (stopped || inFlight) return
    inFlight = true
    try {
      // Enrollment is part of the polling invariant, not a fire-and-forget
      // caller precondition. In particular the first tick runs immediately:
      // racing it against a separate keylist-update used to produce a noisy
      // e.p.req.not_enroll problem report on every fresh page boot. Keeping
      // `registered` false after a failure also makes a live tab self-heal
      // when the mediator was unavailable at boot, rather than waiting for
      // the next full page reload to attempt registration again.
      const mediator = registered
        ? await fetchMediatorInfo(mediatorUrl, fetchImpl)
        : await registerWithMediator(mediatorUrl, own, fetchImpl)
      registered = true
      const delivered = await pickupDeliver(mediator, own, resolveSenderKey, 10, fetchImpl)
      const ackIds: string[] = []
      for (const msg of delivered) {
        try {
          await onMessage(msg)
          ackIds.push(msg.ackId)
        } catch (e) {
          console.warn(`[didcomm] onMessage failed for ${msg.ackId}, leaving it queued for retry:`, e instanceof Error ? e.message : e)
        }
      }
      if (ackIds.length) await acknowledgeMessages(mediator, own, ackIds, fetchImpl)
    } catch (e) {
      opts.onError?.(e)
      console.warn(`[didcomm] poll of ${mediatorUrl} failed (will retry next tick):`, e instanceof Error ? e.message : e)
    } finally {
      inFlight = false
    }
  }

  const timer = setInterval(() => { void tick() }, intervalMs)
  void tick() // don't wait a full interval for the first poll

  return {
    stop() {
      if (stopped) return
      stopped = true
      clearInterval(timer)
    },
  }
}
