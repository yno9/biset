// Everything about notifications/badging that BOTH sides need — the window
// (utils.ts, ui/*) and the Service Worker (sw.ts). Deliberately dependency-free
// beyond route.ts: sw.js is fetched and parsed from scratch on every background
// push wake-up, so anything imported here is paid for on every push.
//
// Keeping the storage-key names, the badge call and the notification shape in
// one place is the point: the two sides used to carry their own copy of each,
// and they drifted (two different badge implementations, a notification the
// window raised with `new Notification()` that iOS never shows).
import { hashSeg } from '../route.ts'

// Keys inside store/idb.ts's `accounts` object store. The account list itself
// is the only entry the window writes ('all', see context.ts); the rest is the
// Service Worker's own bookkeeping, kept here so both sides agree on the names.
export const SW_KEYS = {
  // Mirror of context.ts's DURABLE StoredAccount[] — the SW has no
  // localStorage. For a DID-bound account its `password` is empty, so this is
  // a fallback only; see sessionAccounts.
  accounts: 'all',
  // The credentials that actually authenticate: the live sessions' accounts,
  // carrying the device-signed session token a DID-bound account logs in with
  // (context.ts's mirrorSessionAccounts). Preferred over `accounts`, which for
  // such an account holds an empty password and produced a 401 on every call
  // the Service Worker made.
  sessionAccounts: 'sw_session_accounts',
  // Ids of the real messages we have already raised a notification for.
  notifiedIds: 'sw_notified_ids',
  // Pre-cleanup name of the same thing (it once held a timestamp, then an id
  // list). Read once to seed `notifiedIds`, then deleted — without the seed,
  // the first push after an update would re-notify every currently-unread
  // message at once.
  legacyNotifiedIds: 'sw_last_notified_ts',
  // Permalink hash of the conversation the window is showing right now, or ''
  // when it is showing something else. Lets the SW skip notifying for the
  // thread the user is literally looking at.
  activeView: 'sw_active_view',
  // How many DIDComm messages are unread in the LOCAL store, published by the
  // window (left-pane.ts's renderLeftInboxes).
  //
  // The badge is the one number both sides compute, and only the window can
  // see this part of it. A DIDComm message leaves the mediator's queue the
  // moment it is picked up and from then on exists only in the local store —
  // no JMAP account holds it, so the Service Worker's own scan cannot count
  // it. Without this the badge collapsed to "server unread + queue" on every
  // push, i.e. a background arrival dropped it from 7 to 1.
  localDidcommUnread: 'sw_local_didcomm_unread',
  // The window's view of the JMAP (mail + ActivityPub) unread count. The
  // Service Worker computes this part itself and prefers its own answer — but
  // a scan that fails must fall back to the last known figure rather than
  // contributing zero, which silently subtracted every unread mail from the
  // badge on any relay hiccup.
  localJmapUnread: 'sw_local_jmap_unread',
  // Diagnostics read back by /debug.
  debug: 'sw_last_push_debug',
  version: 'sw_active_version',
} as const

// Home-screen icon badge (Badging API — installed PWA only, iOS 16.4+/Android
// Chrome). No-op elsewhere; wrapped since older browsers lack the methods.
// `navigator` resolves to WorkerNavigator inside the Service Worker, which
// carries the same two methods.
export function syncAppBadge(count: number): void {
  const nav = navigator as any
  if (count > 0) nav.setAppBadge?.(count).catch(() => {})
  else nav.clearAppBadge?.().catch(() => {})
}

// The permalink for the conversation a message belongs to — the same shape
// utils.ts's inboxToHash produces, so main.ts's router resolves it. Group id
// wins when present (a group message's sender is not its conversation); the
// parse side normalizes addresses through contactIdentityKey, so emitting the
// literal sender address here still finds a DID-grouped inbox.
export function conversationHash(from: string, groupId?: string): string {
  return '#' + hashSeg(groupId ? `group:${groupId}` : from)
}

export interface NotificationTarget {
  hash: string      // conversationHash() — click target and tag identity
  /** The sender, which iOS renders as the banner's "from …" line. EMPTY when
   * there is no sender to name — a DIDComm arrival, where the mediator cannot
   * know who sent it (sw.ts's PushPayload). Empty on purpose rather than
   * falling back to "biset": that fallback is what produced a banner reading
   * "from biset", naming the app as the correspondent. */
  title: string
  count: number     // how many unnotified messages this conversation has
}

// One notification per conversation, replacing that conversation's previous
// one. `renotify` matters: with a stable tag and renotify unset, every message
// after the first silently swaps the banner out instead of alerting.
//
// The body never carries message content — the SW can decrypt, but a lock
// screen is not the place to spill it.
export function notificationOptions(t: NotificationTarget): [string, any] {
  const body = t.count > 1 ? `${t.count} new messages` : 'New message'
  return [t.title, {
    body,
    tag: `biset:${t.hash}`,
    renotify: true,
    data: { hash: t.hash },
  }]
}
