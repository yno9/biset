// ── DeltaChat contact avatars (Chat-User-Avatar) ──────────────────────────────
//
// DeltaChat transmits a contact's profile picture as a protected header plus an
// attached image part inside the encrypted MIME:
//   - `Chat-User-Avatar: <name>`  → an avatar image is attached (learn it)
//   - `Chat-User-Avatar: 0`       → the user cleared their avatar (forget it)
//   - header absent               → this message carries no avatar info (leave as-is;
//                                    DeltaChat only re-sends the avatar occasionally)
//
// Kept out of the generic MIME/UI layers: crypto.ts only exposes raw attachments;
// all "Chat-User-Avatar" semantics + persistence live here. UI reads avatars via
// the synchronous `avatarDataUrl()` cache (primed at startup).

import type { DecryptedMime } from '../pgp/crypto.ts'
import { bytesToDataUrl as encodeDataUrl } from '../utils.ts'

const CHAT_USER_AVATAR = 'chat-user-avatar'
const CHAT_GROUP_AVATAR = 'chat-group-avatar'

// Cache key namespace for group avatars, distinct from contact addresses
// (a group id never contains '@', so this can't collide with a real address).
// Exported so callers building an InboxSummary can look up the same avatar
// via avatarDataUrl(groupCacheKey(groupId)) without duplicating the format.
export function groupCacheKey(groupId: string): string {
  return `group:${groupId}`
}

const DB_NAME = 'biset-deltachat'
const DB_VERSION = 2
const STORE = 'avatars'
const NAME_STORE = 'names'

interface AvatarRecord { addr: string; dataUrl: string }
interface NameRecord { addr: string; name: string }

// In-memory cache for synchronous UI access (keyed by lowercased address).
const cache = new Map<string, string>()

// The From-header display name last seen for a plain (non-DID) address —
// DeltaChat/chatmail contacts have no JSContact Card (contacts.ts's Card is
// DID-rooted only), so this is the only place their display name is learned
// from. Kept alongside the avatar cache since it's the same per-address,
// learned-from-incoming-mail shape and persistence needs.
const nameCache = new Map<string, string>()

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE, { keyPath: 'addr' })
      if (!req.result.objectStoreNames.contains(NAME_STORE)) req.result.createObjectStore(NAME_STORE, { keyPath: 'addr' })
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

// Loads all persisted avatars + names into the in-memory caches. Call once at
// startup so the synchronous UI lookups have data without awaiting IndexedDB
// per render.
export async function primeAvatarCache(): Promise<void> {
  try {
    const db = await openDB()
    const recs: AvatarRecord[] = await new Promise((resolve, reject) => {
      const req = db.transaction(STORE, 'readonly').objectStore(STORE).getAll()
      req.onsuccess = () => resolve(req.result as AvatarRecord[])
      req.onerror = () => reject(req.error)
    })
    for (const r of recs) cache.set(r.addr, r.dataUrl)
  } catch { /* no avatars yet */ }
  try {
    const db = await openDB()
    const recs: NameRecord[] = await new Promise((resolve, reject) => {
      const req = db.transaction(NAME_STORE, 'readonly').objectStore(NAME_STORE).getAll()
      req.onsuccess = () => resolve(req.result as NameRecord[])
      req.onerror = () => reject(req.error)
    })
    for (const r of recs) nameCache.set(r.addr, r.name)
  } catch { /* no names yet */ }
}

// Synchronous display-name lookup for a plain address (contacts.ts's
// displayLabelFor fallback chain). Returns undefined if none was ever
// observed on an incoming From header.
export function contactNameFor(addr: string): string | undefined {
  return nameCache.get(addr.toLowerCase())
}

// Learns (or updates) the display name for `addr`, taken verbatim from an
// incoming email's From-header phrase (cleartext even for chatmail — unlike
// Chat-Group-ID it's never protected, since the outer envelope needs it for
// delivery). Last-seen-wins: no attempt to reconcile conflicting names.
export async function learnContactName(addr: string, name: string): Promise<void> {
  const trimmed = name.trim()
  if (!trimmed) return
  const key = addr.toLowerCase()
  if (nameCache.get(key) === trimmed) return
  nameCache.set(key, trimmed)
  try {
    const db = await openDB()
    await new Promise<void>((resolve, reject) => {
      const req = db.transaction(NAME_STORE, 'readwrite').objectStore(NAME_STORE).put({ addr: key, name: trimmed } as NameRecord)
      req.onsuccess = () => resolve()
      req.onerror = () => reject(req.error)
    })
  } catch { /* non-fatal */ }
}

// Synchronous avatar lookup for rendering. Returns a data: URL or undefined.
export function avatarDataUrl(addr: string): string | undefined {
  return cache.get(addr.toLowerCase())
}

// Stores an avatar (data: URL) for an address — used both for learned contact
// avatars and for the user's own avatar (keyed by their account email).
export async function saveAvatar(addr: string, dataUrl: string): Promise<void> {
  const key = addr.toLowerCase()
  cache.set(key, dataUrl)
  await persist(key, dataUrl)
}

// Returns the raw base64 payload of an account's own avatar (no data: prefix),
// for emitting `Chat-User-Avatar: base64:<...>` on outgoing DeltaChat messages.
export function ownAvatarBase64(account: string): string | undefined {
  const dataUrl = cache.get(account.toLowerCase())
  if (!dataUrl) return undefined
  const comma = dataUrl.indexOf(',')
  return comma >= 0 ? dataUrl.slice(comma + 1) : undefined
}

// Inline avatars often carry no reliable content-type — sniff from magic
// bytes when the given one isn't already image/*, then delegate to the
// shared encoder (utils.ts; also used for general message attachments).
function bytesToDataUrl(bytes: Uint8Array, contentType: string): string {
  const ct = /^image\//i.test(contentType) ? contentType : sniffImageType(bytes)
  return encodeDataUrl(bytes, ct)
}

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64.replace(/\s+/g, '')), c => c.charCodeAt(0))
}

// Detects the image type from magic bytes (inline avatars carry no content-type).
function sniffImageType(b: Uint8Array): string {
  if (b[0] === 0x89 && b[1] === 0x50) return 'image/png'
  if (b[0] === 0xff && b[1] === 0xd8) return 'image/jpeg'
  if (b[0] === 0x47 && b[1] === 0x49) return 'image/gif'
  if (b[0] === 0x52 && b[1] === 0x49) return 'image/webp'
  return 'image/jpeg'
}

async function persist(addr: string, dataUrl: string): Promise<void> {
  try {
    const db = await openDB()
    await new Promise<void>((resolve, reject) => {
      const req = db.transaction(STORE, 'readwrite').objectStore(STORE).put({ addr, dataUrl } as AvatarRecord)
      req.onsuccess = () => resolve()
      req.onerror = () => reject(req.error)
    })
  } catch { /* non-fatal */ }
}

async function forget(addr: string): Promise<void> {
  cache.delete(addr)
  try {
    const db = await openDB()
    db.transaction(STORE, 'readwrite').objectStore(STORE).delete(addr)
  } catch { /* non-fatal */ }
}

// Learns (or clears) a contact avatar from a decrypted DeltaChat message.
// `from` is the sender address the avatar belongs to. No-op when the message
// carries no Chat-User-Avatar header.
export async function learnAvatar(from: string, dec: DecryptedMime): Promise<void> {
  const hdr = dec.headers?.[CHAT_USER_AVATAR]
  if (hdr === undefined) return
  const addr = from.toLowerCase()
  const raw = hdr.trim()
  if (raw === '0') { await forget(addr); return }

  // DeltaChat inlines the avatar directly in the header as `base64:<image>` (folded
  // across lines, so whitespace must be stripped). Older/other clients instead
  // reference an attached image part named by the header — kept as a fallback.
  let bytes: Uint8Array | null = null
  let ct = ''
  const b64 = raw.match(/^base64:(.*)$/s)
  if (b64) {
    try { bytes = base64ToBytes(b64[1]) } catch { bytes = null }
  } else {
    const img = (dec.attachments ?? []).find(a => /^image\//i.test(a.contentType))
    if (img) { bytes = img.bytes; ct = img.contentType }
  }
  if (!bytes || !bytes.length) return

  const dataUrl = bytesToDataUrl(bytes, ct)
  cache.set(addr, dataUrl)
  await persist(addr, dataUrl)
}

// Learns (or clears) a DeltaChat group's avatar from a decrypted message.
// Unlike Chat-User-Avatar, DeltaChat always sends the group image as an
// attached MIME part named by the header value (never base64-inline) — see
// chatmail spec.md. Keyed separately from contact addresses (groupCacheKey)
// so group and 1:1 avatars share the same cache without colliding.
export async function learnGroupAvatar(groupId: string, dec: DecryptedMime): Promise<void> {
  const hdr = dec.headers?.[CHAT_GROUP_AVATAR]
  if (hdr === undefined) return
  const key = groupCacheKey(groupId)
  const raw = hdr.trim()
  if (raw === '0' || raw === '') { await forget(key.toLowerCase()); return }

  const attachments = dec.attachments ?? []
  const img = attachments.find(a => a.filename === raw && /^image\//i.test(a.contentType))
    ?? attachments.find(a => /^image\//i.test(a.contentType))
  if (!img || !img.bytes.length) return

  const dataUrl = bytesToDataUrl(img.bytes, img.contentType)
  await saveAvatar(key, dataUrl)
}
