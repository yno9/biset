// Per-mediator pickup poll loop -- Mail Mediator's counterpart to
// mediator-sync.ts's startMediatorPolling, adapted to pickup-request/
// messages-received instead of Pickup 3.0's status/delivery-request. One
// loop per (mediatorUrl, relationship credential) pair, exactly like the
// DIDComm one is per (mediatorUrl, own kid) pair.
import { fetchMediatorInfo } from './mediator-transport.ts'
import type { DidCommSender } from './mediator-transport.ts'
import { pickupMail, acknowledgeMail } from './mail-mediator-client.ts'
import type { PickupItem } from '../mail-mediator/protocol.ts'
import { defaultFetch } from '../net-fetch.ts'

export interface MailMediatorPollHandle {
  stop(): void
}

export interface MailMediatorPollOptions {
  intervalMs?: number
  fetch?: typeof fetch
  onError?: (e: unknown) => void
}

/** Starts polling ONE Mail Mediator for spooled mail addressed to
 * `address`, authenticated as `relationship` (never the front-door kid --
 * server.ts refuses that). Each successfully-handled item (onItem did not
 * throw) is acknowledged; one that throws is left unacknowledged so the
 * mediator redelivers it next tick (mirrors mediator-sync.ts's own
 * per-message resilience). Returns a handle whose `stop()` cancels the
 * interval -- call it once (idempotent). */
export function startMailMediatorPolling(
  mediatorUrl: string,
  relationship: DidCommSender,
  address: string,
  onItem: (item: PickupItem) => Promise<void> | void,
  opts: MailMediatorPollOptions = {},
): MailMediatorPollHandle {
  const intervalMs = opts.intervalMs ?? 15_000
  const fetchImpl = opts.fetch ?? defaultFetch()
  let stopped = false
  let inFlight = false

  const tick = async () => {
    if (stopped || inFlight) return
    inFlight = true
    try {
      const mediator = await fetchMediatorInfo(mediatorUrl, fetchImpl)
      const { items } = await pickupMail(mediator, relationship, 10, fetchImpl)
      const ackIds: string[] = []
      for (const item of items) {
        try {
          await onItem(item)
          ackIds.push(item.spoolId)
        } catch (e) {
          console.warn(`[mail-mediator] onItem failed for ${item.spoolId}, leaving it queued for retry:`, e instanceof Error ? e.message : e)
        }
      }
      if (ackIds.length) await acknowledgeMail(mediator, relationship, address, ackIds, fetchImpl)
    } catch (e) {
      opts.onError?.(e)
      console.warn(`[mail-mediator] poll of ${mediatorUrl} failed (will retry next tick):`, e instanceof Error ? e.message : e)
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
