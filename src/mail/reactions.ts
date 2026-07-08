// RFC 9078 "Simple Mail Reactions" — a generic IETF email standard, not a
// DeltaChat invention (DeltaChat just implements it as-is, see spec.md). A
// reaction is its own email: Content-Disposition: reaction, In-Reply-To
// pointing at the target message's Message-ID, body = one or more emoji.
// chatmail's extension (mirroring XEP-0444): a new reaction from a sender
// replaces their previous one on that message; an empty body retracts it.
import type { Email } from 'jmap-rfc-types'

const DISPOSITION_HEADER = 'content-disposition'

// Cleartext case: Content-Disposition is a plain outer header, visible once
// jmap/email.ts requests the generic JMAP `headers` property.
export function isReactionEmail(email: Email): boolean {
  const headers = ((email as any).headers as { name: string; value: string }[] | undefined) ?? []
  const v = headers.find(h => h.name.toLowerCase() === DISPOSITION_HEADER)?.value
  return (v ?? '').trim().toLowerCase() === 'reaction'
}

// Encrypted case: Content-Disposition rides inside the PGP/MIME payload like
// any other header; decryptAndParse already captures it into `.headers`.
export function isReactionDisposition(headers: Record<string, string> | undefined): boolean {
  return (headers?.[DISPOSITION_HEADER] ?? '').trim().toLowerCase() === 'reaction'
}

export interface ReactionInfo { emoji: string; from: string; targetMessageId: string }

// Cached onto the reaction Email object at sync time (mirrors
// deltachat/protocol.ts's cacheGroupHeaders) so later reads — building the
// per-message reaction list for display — don't need to re-decrypt.
export function cacheReaction(email: Email, info: ReactionInfo): void {
  (email as any)._reaction = info
}

export function readCachedReaction(email: Email): ReactionInfo | null {
  return (email as any)._reaction ?? null
}

// True if this email is a reaction (already tagged during sync, or — as a
// fallback for messages that weren't — a cleartext reaction detectable now).
export function isReaction(email: Email): boolean {
  return !!readCachedReaction(email) || isReactionEmail(email)
}

// Builds target-messageId → reactions for one identity's emails. Empty-body
// reactions (retractions) already deleted the sender's earlier entry when
// applied — see applyReactions below — so this is a straight collection pass.
export function collectReactions(emails: Email[]): Map<string, ReactionInfo[]> {
  // Latest reaction per (target, sender) wins, and an empty emoji retracts —
  // so first bucket by (target, from), keeping only the latest by receivedAt,
  // then drop empties.
  const latest = new Map<string, ReactionInfo & { ts: number }>() // key: target\0from
  for (const email of emails) {
    const info = readCachedReaction(email)
    if (!info) continue
    const ts = email.receivedAt ? new Date(email.receivedAt as string).getTime() : 0
    const key = `${info.targetMessageId}\0${info.from}`
    const existing = latest.get(key)
    if (!existing || ts >= existing.ts) latest.set(key, { ...info, ts })
  }
  const out = new Map<string, ReactionInfo[]>()
  for (const { ts: _ts, ...info } of latest.values()) {
    if (!info.emoji) continue // retraction — nothing to show
    if (!out.has(info.targetMessageId)) out.set(info.targetMessageId, [])
    out.get(info.targetMessageId)!.push(info)
  }
  return out
}
