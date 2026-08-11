// The browser's instance of did/keycache.ts: sender public keys, kept across
// reloads in IndexedDB.
//
// This sits on the single hottest blocking path in the app. authcrypt is
// ECDH-1PU, so pickup.ts cannot decrypt ANY incoming message without the
// sender's public key first — and resolving that key meant a Pkarr gateway
// round trip, measured at 3-6.5s against production whenever the record had
// fallen out of the 60s document cache underneath. That delay is the bulk of
// the gap between a push notification arriving and the message appearing in
// the thread.
//
// Persisting is what actually removes it. An in-memory cache only helps the
// second message of a session; a chat where the other person writes every few
// minutes never got a hit at all, and neither did the first message after
// every reload — which, on a phone, is most of them. What makes persistence
// safe is the property keycache.ts's own header spells out: a kid names one
// key permanently (rotation-less identities, one new `#kN` slot per new
// device). And where that ever stops holding, the caller has a repair:
// pickup.ts retries a failed unpack once with `fresh`, which replaces the
// stored key instead of letting a wrong one fail forever.
import * as idb from '../../store/idb.ts'
import { hexToBytes, bytesToHex } from '../../utils.ts'
import { ResolvedKeyCache, type KeyCachePersistence, type KeyResolver } from '../keycache.ts'

// One blob, not one record per kid: the whole set is a handful of entries (the
// contacts this device talks to, times their devices) and it is read exactly
// once per page load.
const STORE_KEY = 'didcomm_sender_keys'

// Long, because the underlying fact barely changes (see the header) — this is
// the interval at which a key is re-checked in the BACKGROUND, never something
// a message waits on.
const KEY_TTL_MS = 60 * 60 * 1000

type StoredKeys = Record<string, string> // kid -> hex public key

const persistence: KeyCachePersistence = (() => {
  let mirror: StoredKeys = {}
  let flush: ReturnType<typeof setTimeout> | null = null
  // Coalesced: a batch of messages from the same new correspondent would
  // otherwise write the same growing blob once per message.
  const schedule = () => {
    if (flush) return
    flush = setTimeout(() => {
      flush = null
      idb.put(idb.STORES.accounts, { ...mirror }, STORE_KEY).catch(() => {})
    }, 500)
  }
  return {
    async load() {
      const raw = await idb.get(idb.STORES.accounts, STORE_KEY).catch(() => undefined)
      const out = new Map<string, Uint8Array>()
      if (raw && typeof raw === 'object') {
        mirror = { ...(raw as StoredKeys) }
        for (const [kid, hex] of Object.entries(mirror)) {
          if (typeof hex === 'string' && hex.length > 0) out.set(kid, hexToBytes(hex))
        }
      }
      return out
    },
    save(kid, key) { mirror[kid] = bytesToHex(key); schedule() },
    drop(kid) { delete mirror[kid]; schedule() },
  }
})()

const cache = new ResolvedKeyCache({
  ttlMs: KEY_TTL_MS,
  label: 'didcomm sender',
  // Never make a message wait on a re-check: the cached key is correct by
  // construction, and if it somehow isn't, pickup.ts's `fresh` retry is what
  // fixes it — not a delay every recipient pays on the chance that it might.
  staleWhileRevalidate: true,
  persist: persistence,
})

/** The public key for `senderKid`, from cache when possible. `fresh` forces a
 * real resolve and replaces the stored entry — for pickup.ts's one retry after
 * an unpack failed with the cached key. */
export function cachedSenderKey(
  senderKid: string, resolve: KeyResolver, opts?: { fresh?: boolean },
): Promise<Uint8Array> {
  return cache.get(senderKid, resolve, opts)
}
