// Registration (self-heal on every boot) + a per-mediator poll loop. A
// device may be registered with several independent mediators at once
// (ARC.md's 2026-08-27 redesign -- non-centralization is the point), so
// this is deliberately per-mediator-URL: the caller starts one of these per
// registered mediator, never a single shared loop.
//
// Ported in spirit from src.bak/did/didcomm/channel.ts's
// reassertKeylistRegistration + startDidCommPolling, but without that
// file's did:dht-era session/IndexedDB record bookkeeping -- the caller
// hands over one ready MediatorInboxClient (protocol/didcomm/
// mediator-device.ts), so this module only needs the mediator URL and that.
import { fetchMediatorInfo, pushWebvhLog, queryRecipients, requestMediation, updateRecipient, type RecipientEntry, type MediatorInfo } from '../../protocol/didcomm/mediator-coordinate.ts'
import { MAX_DEVICES_PROBLEM } from '../../protocol/didcomm/mediator-protocol.ts'
import { DidCommProblemError } from '../../protocol/didcomm/problems.ts'
import { pickupDeliver, acknowledgeMessages, type DeliveredMessage } from '../../protocol/didcomm/mediator-pickup.ts'
import type { MediatorInboxClient } from '../../protocol/didcomm/mediator-transport.ts'
import type { ResolveSenderKey } from '../../protocol/didcomm/crypto.ts'
import { serializeLog } from '../../protocol/webvh/log.ts'
import { defaultFetch } from '../../protocol/net-fetch.ts'
import { fetchCurrentLog, freshFetch } from '../identity/webvh/log-io.ts'

/** mediate-request + recipient-update(add), unconditionally -- both are
 * idempotent (`no_change` when the inbox already exists), so calling this on
 * every boot is the self-heal for a mediator that lost this inbox. A
 * did:webvh inbox first hands the mediator the DID's current log, read past
 * the CDN: the mediator authenticates a did:webvh key only against the
 * latest log it holds, and a key added moments ago is not in a cached one. */
export async function registerWithMediator(mediatorUrl: string, inbox: MediatorInboxClient, fetchImpl: typeof fetch = defaultFetch()): Promise<MediatorInfo> {
  const mediator = await fetchMediatorInfo(mediatorUrl, fetchImpl)
  if (inbox.did.startsWith('did:webvh:')) {
    const { entries } = await fetchCurrentLog(inbox.did, freshFetch(fetchImpl))
    await pushWebvhLog(mediator, serializeLog(entries), fetchImpl)
  }
  await requestMediation(mediator, inbox, fetchImpl)
  try {
    await updateRecipient(mediator, inbox, 'add', fetchImpl)
  } catch (error) {
    if (!(error instanceof DidCommProblemError) || error.code !== MAX_DEVICES_PROBLEM) throw error
    throw new MediatorDeviceLimitError(error.args[2] ?? '?', await queryRecipients(mediator, inbox, fetchImpl).catch(() => []))
  }
  return mediator
}

/** The mediator refused this device's inbox: the identity already has the
 * mediator's maximum number of devices. Thrown on every registration path
 * (sign-in, boot, relationship), and its message is written to be shown to
 * the user as-is -- the account page's mediator card displays it. */
export class MediatorDeviceLimitError extends Error {
  constructor(readonly limit: string, readonly devices: readonly RecipientEntry[]) {
    const seen = devices.map(device => new Date(device.lastSeen).toISOString().slice(0, 10)).join(', ')
    super(`This account already has ${limit} devices registered for messaging${seen ? ` (last active: ${seen})` : ''}. Remove the devices you no longer use (choose another device in the Account page's device list; this removes all other devices), then reload.`)
    this.name = 'MediatorDeviceLimitError'
  }
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

/** Starts polling ONE mediator inbox. Each
 * successfully-handled message (onMessage did not throw) is acknowledged;
 * one that throws is left unacknowledged so the mediator redelivers it next
 * tick (mirrors pickupDeliver's own per-message resilience, one level up:
 * an ingress-projector failure for one message must not lose the rest of
 * the batch or stop the loop). Returns a handle whose `stop()` cancels the
 * interval -- call it once (idempotent; a repeat stop is a no-op). */
export function startMediatorPolling(
  mediatorUrl: string,
  inbox: MediatorInboxClient,
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
      // racing it against a separate recipient-update used to produce a noisy
      // e.p.req.not_enroll problem report on every fresh page boot. Keeping
      // `registered` false after a failure also makes a live tab self-heal
      // when the mediator was unavailable at boot, rather than waiting for
      // the next full page reload to attempt registration again.
      const mediator = registered
        ? await fetchMediatorInfo(mediatorUrl, fetchImpl)
        : await registerWithMediator(mediatorUrl, inbox, fetchImpl)
      registered = true
      const delivered = await pickupDeliver(mediator, inbox, resolveSenderKey, 10, fetchImpl)
      const ackIds: string[] = []
      for (const msg of delivered) {
        try {
          await onMessage(msg)
          ackIds.push(msg.ackId)
        } catch (e) {
          console.warn(`[didcomm] onMessage failed for ${msg.ackId}, leaving it queued for retry:`, e instanceof Error ? e.message : e)
        }
      }
      if (ackIds.length) await acknowledgeMessages(mediator, inbox, ackIds, fetchImpl)
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
