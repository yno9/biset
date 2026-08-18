import type { Email } from 'jmap-rfc-types'
import * as messages from '../store/messages.ts'

export interface FilterNewResult {
  /** Genuinely new — safe to store and decrypt. */
  fresh: Email[]
  /** Already known by Message-ID, but under a DIFFERENT JMAP id within the
   * SAME account — the server has reissued this message's id (a recreated
   * mailbox/account is the live case, 2026-08-17: y@biset.md's relay account
   * went through multiple genesis resets this session, and every cached
   * message's id predates the last one). Silently dropping these (the old
   * behaviour) left `messages.forAccount` never containing the new id, so
   * session.ts's reconcile step re-fetched the SAME "missing" batch on every
   * single sync forever, never converging — the relay card's spinner never
   * stopped. Caller re-keys the existing local record to the new id instead.
   */
  idDrift: Array<{ oldId: string; newEmail: Email }>
}

// Returns emails not already in the store, scoped by Message-ID header.
// Emails with no messageId are always considered new (nothing to dedup by).
export function filterNew(account: string, emails: Email[]): FilterNewResult {
  const byMessageId = new Map<string, Email>()
  for (const e of messages.all()) {
    for (const mid of (e.messageId as string[] | undefined) ?? []) {
      if (!byMessageId.has(mid)) byMessageId.set(mid, e)
    }
  }
  const fresh: Email[] = []
  const idDrift: FilterNewResult['idDrift'] = []
  for (const e of emails) {
    const ids = (e.messageId as string[] | undefined) ?? []
    const dupe = ids.length ? ids.map(id => byMessageId.get(id)).find(Boolean) : undefined
    if (!dupe) { fresh.push(e); continue }
    if (messages.accountOf(dupe) === account && dupe.id !== e.id) {
      idDrift.push({ oldId: dupe.id as string, newEmail: e })
    }
    // else: a genuine duplicate (same id, or a different account entirely —
    // store/messages.ts's own partitioning note says those get their own
    // copies, not merged) — dropped, same as before.
  }
  return { fresh, idDrift }
}
