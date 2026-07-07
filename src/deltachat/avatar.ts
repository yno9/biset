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

const CHAT_USER_AVATAR = 'chat-user-avatar'

const DB_NAME = 'biset-deltachat'
const DB_VERSION = 1
const STORE = 'avatars'

interface AvatarRecord { addr: string; dataUrl: string }

// In-memory cache for synchronous UI access (keyed by lowercased address).
const cache = new Map<string, string>()

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE, { keyPath: 'addr' })
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

// Loads all persisted avatars into the in-memory cache. Call once at startup so
// the synchronous UI lookups have data without awaiting IndexedDB per render.
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

function bytesToDataUrl(bytes: Uint8Array, contentType: string): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  const ct = /^image\//i.test(contentType) ? contentType : sniffImageType(bytes)
  return `data:${ct};base64,${btoa(bin)}`
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
