// ── DeltaChat / Autocrypt compatibility layer ─────────────────────────────────
//
// All knowledge of DeltaChat's on-the-wire protocol lives here so the rest of
// biset (jmap / vault / ui / generic pgp) stays free of "Chat-*" magic strings.
//
// Protocol references:
//   - Chat-Group-ID / Chat-Group-Name / Chat-Version headers (DeltaChat groups)
//   - Autocrypt Level 1 §gossip (per-member key propagation)
//   - DeltaChat treats any "chat-*" header as *protected*: for encrypted mail it
//     ignores the cleartext copies and only trusts the ones found INSIDE the
//     encrypted MIME part. Group headers therefore have to be emitted twice:
//     in the JMAP draft (outer, for non-DeltaChat clients) AND inside the
//     encrypted payload (see buildProtectedHeaders).

import type { Email } from 'jmap-rfc-types'
import * as openpgp from 'openpgp'
import { ownAvatarBase64 } from './avatar.ts'

export const CHAT_GROUP_ID = 'Chat-Group-ID'
export const CHAT_GROUP_NAME = 'Chat-Group-Name'
export const CHAT_VERSION = 'Chat-Version'
export const CHAT_VERSION_VALUE = '1.0'
export const CHAT_USER_AVATAR = 'Chat-User-Avatar'
export const CHAT_EDIT = 'Chat-Edit'
export const CHAT_DELETE = 'Chat-Delete'

export interface GroupOpts { id: string; name: string }

// Generates a DeltaChat-compatible group id.
//
// DeltaChat validates group ids with `validate_id`: URL-safe base64 alphabet
// and length 11..=32. Its own ids are 18 random bytes → URL-safe base64 (24
// chars). crypto.randomUUID() produces 36 chars, which FAILS the `<= 32` check,
// so DeltaChat ignores the Chat-Group-ID entirely and drops the message into a
// read-only ad-hoc group. Match DeltaChat's create_id() instead.
export function newGroupId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(18))
  const b64 = btoa(String.fromCharCode(...bytes))
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

type RawHeader = { name: string; value: string }

function rawHeaders(email: Email): RawHeader[] {
  return ((email as any).headers as RawHeader[] | undefined) ?? []
}

function findHeader(email: Email, name: string): string | undefined {
  const lc = name.toLowerCase()
  const v = rawHeaders(email).find(h => h.name.toLowerCase() === lc)?.value?.trim()
  return v || undefined
}

// SecureJoin handshake messages (vc-*/vg-*) carry the fixed subject "Secure-Join".
// Both DeltaChat and biset use it. These are pure protocol noise: incoming ones are
// destroyed in session.ts, but biset's OWN sent copies (vc-pubkey/vc-contact-confirm)
// linger in the Sent mailbox and would otherwise spawn a phantom 1:1 inbox. Filter
// them out of inbox summaries + message lists.
export function isSecurejoinEmail(email: Email): boolean {
  return (email.subject as string | undefined)?.trim() === 'Secure-Join'
}

// ── Reading incoming mail ─────────────────────────────────────────────────────

export interface GroupHeaders { id?: string; name?: string }

// Extracts the DeltaChat group id/name from an Email's decoded headers.
export function readGroupHeaders(email: Email): GroupHeaders {
  return {
    id: findHeader(email, CHAT_GROUP_ID),
    name: findHeader(email, CHAT_GROUP_NAME),
  }
}

// Parses an "Autocrypt: addr=..; keydata=<base64>" header from a decrypted MIME
// header map. chatmail/DeltaChat carry the sender's Autocrypt key INSIDE the
// encrypted part, so this is the only place a recipient can learn it. Returns
// the sender address and the raw binary transferable public key.
export function parseAutocryptKey(headers: Record<string, string>): { addr: string; key: Uint8Array } | null {
  return parseAcValue(headers['autocrypt'])
}

// Parses every "Autocrypt-Gossip: addr=..; keydata=<base64>" header (one per group
// member). DeltaChat/chatmail carry other members' keys ONLY via gossip inside the
// encrypted part, so this is how a recipient learns the key of a member who hasn't
// messaged directly yet — required to encrypt replies to the whole group.
export function parseGossipKeys(gossip: string[] | undefined): { addr: string; key: Uint8Array }[] {
  if (!gossip) return []
  return gossip.map(parseAcValue).filter((x): x is { addr: string; key: Uint8Array } => x != null)
}

// Parses a single "addr=..; keydata=<base64>" Autocrypt(-Gossip) header value.
function parseAcValue(v: string | undefined): { addr: string; key: Uint8Array } | null {
  if (!v) return null
  const addr = v.match(/addr=([^;]+)/i)?.[1]?.trim()
  const b64 = v.match(/keydata=([A-Za-z0-9+/=\s]+)/i)?.[1]?.replace(/\s+/g, '')
  if (!addr || !b64) return null
  try {
    return { addr, key: Uint8Array.from(atob(b64), c => c.charCodeAt(0)) }
  } catch { return null }
}

// Reads group id/name from a decrypted MIME header map (lowercased keys).
// DeltaChat carries Chat-Group-ID/Name as *protected* headers inside the
// encrypted payload, so incoming DeltaChat group messages only expose them here.
export function readGroupHeadersFromMime(headers: Record<string, string>): GroupHeaders {
  return {
    id: headers[CHAT_GROUP_ID.toLowerCase()]?.trim() || undefined,
    name: headers[CHAT_GROUP_NAME.toLowerCase()]?.trim() || undefined,
  }
}

// Caches decrypted group id/name onto an Email's outer `headers` array so the
// synchronous routing helpers (readGroupHeaders) can see them. Idempotent.
export function cacheGroupHeaders(email: Email, g: GroupHeaders): void {
  if (!g.id) return
  const hdrs = ((email as any).headers ??= []) as RawHeader[]
  if (hdrs.some(h => h.name.toLowerCase() === CHAT_GROUP_ID.toLowerCase())) return
  hdrs.push({ name: CHAT_GROUP_ID, value: g.id })
  if (g.name) hdrs.push({ name: CHAT_GROUP_NAME, value: g.name })
}

// ── Message editing / deletion (spec.md "Request editing" / "Request deletion") ─
//
// Both Chat-Edit and Chat-Delete are protected headers (unlisted in the RFC 9788
// hcp_chat policy, so they never appear in a cleartext copy) — only readable
// once decrypted, exactly like Chat-Group-ID. Chat-Edit's target text also rides
// inside the encrypted body, optionally prefixed with a quote + "✏️" marker that
// the spec requires receivers to strip.

export function readChatEditTarget(headers: Record<string, string>): string | undefined {
  return headers[CHAT_EDIT.toLowerCase()]?.trim() || undefined
}

export function readChatDeleteTarget(headers: Record<string, string>): string | undefined {
  return headers[CHAT_DELETE.toLowerCase()]?.trim() || undefined
}

const EDIT_MARKER = '✏️'

// Strips the optional "On <date>, <sender> wrote:\n> quote\n\n✏️" preamble a
// DeltaChat-compatible edit body MAY carry. No marker present (e.g. biset's own
// sends without the ornament) → the whole body is already the new text.
export function parseEditBody(body: string): string {
  const idx = body.lastIndexOf(EDIT_MARKER)
  return (idx >= 0 ? body.slice(idx + EDIT_MARKER.length) : body).trim()
}

// Builds an edit body in DeltaChat's own convention so DeltaChat clients render
// the familiar "quoted original + ✏️ new text" edit indicator.
export function buildEditBody(newText: string, originalText: string, originalSender: string, originalDate: Date): string {
  const dateStr = originalDate.toISOString().slice(0, 10)
  const quoted = originalText.trim().split('\n').map(l => '> ' + l).join('\n')
  return `On ${dateStr}, ${originalSender} wrote:\n${quoted}\n\n${EDIT_MARKER}${newText}`
}

export interface EditInfo { targetMessageId: string; newText: string; from: string }

// Cached onto the edit-request Email object at sync time (mirrors
// mail/reactions.ts's cacheReaction) so later reads don't need to re-decrypt.
export function cacheEdit(email: Email, info: EditInfo): void {
  (email as any)._chatEdit = info
}

export function readCachedEdit(email: Email): EditInfo | null {
  return (email as any)._chatEdit ?? null
}

// An edit-request email is protocol noise, not a chat message — exclude it
// from inbox summaries / message lists the same way isReaction() is excluded.
export function isEdit(email: Email): boolean {
  return !!readCachedEdit(email)
}

// Builds target-messageId → latest edit text for one identity's emails. Only
// accepts an edit if its sender matches the TARGET message's own sender — a
// group member editing someone else's message would otherwise be possible,
// since Chat-Edit itself carries no such restriction beyond PGP-authenticating
// who sent the *edit request*.
export function collectEdits(emails: Email[]): Map<string, string> {
  const byMessageId = new Map<string, Email>()
  for (const e of emails) {
    const mid = (e.messageId as string[] | undefined)?.[0]
    if (mid) byMessageId.set(mid, e)
  }
  const latest = new Map<string, { text: string; ts: number }>()
  for (const e of emails) {
    const info = readCachedEdit(e)
    if (!info) continue
    const target = byMessageId.get(info.targetMessageId)
    const targetFrom = (target?.from as any[] | undefined)?.[0]?.email as string | undefined
    if (!targetFrom || targetFrom.toLowerCase() !== info.from.toLowerCase()) continue
    const ts = e.receivedAt ? new Date(e.receivedAt as string).getTime() : 0
    const existing = latest.get(info.targetMessageId)
    if (!existing || ts >= existing.ts) latest.set(info.targetMessageId, { text: info.newText, ts })
  }
  const out = new Map<string, string>()
  for (const [k, v] of latest) out.set(k, v.text)
  return out
}

// ── Composing outgoing mail ───────────────────────────────────────────────────

// JMAP Email/set `header:<Name>:asText` create properties for a group message.
// These land in the *outer* (cleartext) headers; DeltaChat ignores them for
// encrypted mail but non-DeltaChat clients (Apple Mail, threading) use them.
export function groupDraftHeaders(opts: GroupOpts): Record<string, string> {
  return {
    [`header:${CHAT_GROUP_ID}:asText`]: opts.id,
    [`header:${CHAT_GROUP_NAME}:asText`]: opts.name,
    [`header:${CHAT_VERSION}:asText`]: CHAT_VERSION_VALUE,
  }
}

// Builds an "Autocrypt-Gossip: addr=<email>; keydata=<base64>" header, folding
// the base64 keydata across continuation lines (leading space) per RFC 5322.
function autocryptGossipHeader(email: string, key: openpgp.PublicKey): string {
  const b64 = btoa(String.fromCharCode(...key.write()))
  const prefix = `Autocrypt-Gossip: addr=${email}; keydata=`
  const chunks: string[] = []
  for (let i = 0; i < b64.length; i += 72) chunks.push(b64.slice(i, i + 72))
  return prefix + chunks.join('\r\n ') + '\r\n'
}

export interface ChatAction { editTarget?: string; deleteTarget?: string }

// Builds the DeltaChat "protected" headers that must live INSIDE the encrypted
// MIME part: Chat-Version, the group id/name (so the group is writable, not a
// read-only ad-hoc group), one Autocrypt-Gossip per member (so every member
// learns all others' keys and can reply encrypted), and — for edit/delete
// requests — Chat-Edit / Chat-Delete referencing the target message-id.
export function buildProtectedHeaders(
  recipients: string[],
  recipientKeys: (openpgp.PublicKey | null)[],
  groupOpts?: GroupOpts,
  senderEmail?: string,
  action?: ChatAction,
): string {
  let out = `${CHAT_VERSION}: ${CHAT_VERSION_VALUE}\r\n`
  if (action?.editTarget) out += `${CHAT_EDIT}: ${action.editTarget}\r\n`
  if (action?.deleteTarget) out += `${CHAT_DELETE}: ${action.deleteTarget}\r\n`
  if (groupOpts) {
    out += `${CHAT_GROUP_ID}: ${groupOpts.id}\r\n${CHAT_GROUP_NAME}: ${groupOpts.name}\r\n`
  }
  // The sender's own profile picture, inlined as `base64:<image>` (DeltaChat's
  // format), folded across continuation lines like other long protected headers.
  const avatarB64 = senderEmail ? ownAvatarBase64(senderEmail) : undefined
  if (avatarB64) {
    const prefix = `${CHAT_USER_AVATAR}: base64:`
    const chunks: string[] = []
    for (let i = 0; i < avatarB64.length; i += 72) chunks.push(avatarB64.slice(i, i + 72))
    out += prefix + chunks.join('\r\n ') + '\r\n'
  }
  if (recipients.length > 1) {
    for (let i = 0; i < recipients.length; i++) {
      const k = recipientKeys[i]
      if (k) out += autocryptGossipHeader(recipients[i], k)
    }
  }
  return out
}
