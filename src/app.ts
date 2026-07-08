import type { Email } from 'jmap-rfc-types'
import type { AccountSession, StoredAccount, InboxSummary } from './types.ts'
import { readGroupHeaders, groupDraftHeaders, isSecurejoinEmail, type GroupOpts } from './deltachat/protocol.ts'
import { avatarDataUrl } from './deltachat/avatar.ts'
import {
  sessions, addSession, setCurrentInbox, currentInbox, activeSession, sessionFor, sessionForRelay,
  loadStoredAccounts, saveStoredAccounts, identities as listIdentities, isApRelay,
} from './context.ts'
import { initSession } from './jmap/client.ts'
import * as messages from './store/messages.ts'
import * as mailboxes from './store/mailboxes.ts'
import * as identities from './store/identities.ts'
import * as jmapEmail from './jmap/email.ts'
import * as jmapSubmission from './jmap/submission.ts'
import * as jmapIdentity from './jmap/identity.ts'
import * as jmapMailbox from './jmap/mailbox.ts'
import { initPGP } from './pgp/index.ts'
import { encryptText } from './pgp/crypto.ts'
import { deleteAllKeys } from './pgp/keys.ts'
import { clearAll as clearLocalCache } from './store/cache.ts'
import { loginViaEnvelope, authTokenToBasicAuth } from './cryptenv.ts'
import { mailboxNameFromId } from './utils.ts'
import type { ProcessedMessage } from './state.ts'

export { loginViaEnvelope, authTokenToBasicAuth }
export { initSession }

// ── Email → ProcessedMessage.msg ──────────────────────────────────────────────

export function emailToMsg(email: Email, _selfAddr: string): ProcessedMessage['msg'] {
  const from = (email.from as any[])?.[0]
  const body = (Object.values((email.bodyValues as any) ?? {}) as any[])[0]?.value as string ?? ''
  const { id: groupId, name: groupName } = readGroupHeaders(email)
  return {
    from: (from?.email as string) ?? '',
    from_name: (from?.name as string) || (from?.email as string) || '',
    body: body as string,
    subject: (email.subject as string) ?? '',
    ts: email.receivedAt ? new Date(email.receivedAt as string).getTime() : 0,
    message_id: ((email.messageId as string[])?.[0]) ?? (email.id as string),
    jmap_id: email.id as string,
    in_reply_to: ((email.inReplyTo as string[])?.[0]) ?? '',
    thread_id: (email.threadId as string) ?? '',
    to_addrs: ((email.to as any[]) ?? []).map((a: any) => a.email as string),
    cc_addrs: ((email.cc as any[]) ?? []).map((a: any) => a.email as string),
    group_id: groupId,
    group_name: groupName,
    seen: !!((email.keywords as any)?.['$seen']),
    keywords: (email.keywords as Record<string, boolean>) ?? {},
  }
}

// ── Inbox summaries ───────────────────────────────────────────────────────────

export async function loadInboxSummaries(): Promise<InboxSummary[]> {
  const result = new Map<string, InboxSummary>()

  const groupParticipants = new Map<string, Set<string>>()

  for (const userEmail of listIdentities()) {
    // An identity (email) may span multiple relays (mail + AP); jmapAccountId is
    // usually the email itself. Use the identity for the own/sent check.
    const accountId = userEmail

    // This identity's messages, merged across all its relays.
    const ownMessages = messages.forIdentity(userEmail)

    // First pass: build threadId → groupId mapping for routing replies.
    const threadToGroup = new Map<string, string>()
    const threadToGroupName = new Map<string, string>()
    for (const email of ownMessages) {
      const { id: gid, name: gname } = readGroupHeaders(email)
      if (gid) {
        const tid = email.threadId as string
        if (tid) {
          threadToGroup.set(tid, gid)
          if (gname) threadToGroupName.set(tid, gname)
        }
      }
    }

    for (const email of ownMessages) {
      // SecureJoin handshake noise (incl. biset's own sent vc-* copies) never
      // gets its own inbox. Fix B: kills the phantom "Secure-Join" 1:1 inbox.
      if (isSecurejoinEmail(email)) continue

      const mbxIds = Object.keys((email.mailboxIds as any) ?? {})
      const mbxName = mbxIds.map(id => mailboxNameFromId(id)).find(n => n) ?? ''

      const tid = email.threadId as string
      const hdrs = readGroupHeaders(email)
      const groupId = hdrs.id ?? (tid ? threadToGroup.get(tid) : undefined)
      const groupName = hdrs.name ?? (tid ? threadToGroupName.get(tid) : undefined)

      const ts = email.receivedAt ? new Date(email.receivedAt as string).getTime() : 0
      const body = (Object.values((email.bodyValues as any) ?? {}) as any[])[0]?.value as string ?? ''
      // Unread = an INCOMING message we haven't seen. Own sent mail never carries
      // $seen, so counting it would keep every conversation permanently unread.
      const senderEmail = (email.from as any[])?.[0]?.email as string ?? ''
      const isOwn = senderEmail === userEmail || senderEmail === accountId
      const has_unread = !isOwn && !((email.keywords as any)?.['$seen'])

      if (groupId) {
        // Group email: key by group ID, accumulate participants
        const key = `${userEmail}\0\0group:${groupId}`
        const allAddrs = [
          ...((email.to as any[]) ?? []).map((a: any) => a.email as string),
          ...((email.cc as any[]) ?? []).map((a: any) => a.email as string),
          ((email.from as any[])?.[0]?.email as string ?? ''),
        ].filter(a => a && a !== userEmail)
        if (!groupParticipants.has(key)) groupParticipants.set(key, new Set())
        for (const a of allAddrs) groupParticipants.get(key)!.add(a)

        const existing = result.get(key)
        if (!existing || ts > (existing.latest_ts ?? 0)) {
          result.set(key, {
            user: userEmail,
            mailbox: '',
            contact: `group:${groupId}`,
            inbox_type: 'group',
            group_id: groupId,
            group_name: groupName,
            latest_ts: ts,
            latest_body: body,
            latest_subject: groupName ?? (email.subject as string) ?? '',
            has_unread: existing?.has_unread || has_unread,
            archived: !!((email.keywords as any)?.['$archived']),
            relay: (email as any)._relay,
          })
        } else if (has_unread) {
          existing.has_unread = true
        }
        continue
      }

      const fromEmail = (email.from as any[])?.[0]?.email as string ?? ''
      const toEmails = ((email.to as any[]) ?? []).map((a: any) => a.email as string)

      const isSent = fromEmail === userEmail || fromEmail === accountId
      const contact = isSent ? (toEmails[0] ?? '') : fromEmail
      if (!contact || !mbxName) continue

      const key = `${userEmail}\0${mbxName}\0${contact}`
      const existing = result.get(key)

      if (!existing || ts > (existing.latest_ts ?? 0)) {
        result.set(key, {
          user: userEmail,
          mailbox: mbxName,
          contact,
          latest_ts: ts,
          latest_body: body,
          latest_subject: email.subject as string ?? '',
          has_unread: existing?.has_unread || has_unread,
          avatar_url: avatarDataUrl(contact),
          // Archived state tracks the *latest* message, so a new incoming
          // message (which lacks $archived) automatically un-archives the chat.
          archived: !!((email.keywords as any)?.['$archived']),
          relay: (email as any)._relay,
        })
      } else if (has_unread) {
        existing.has_unread = true
      }
    }
  }

  // Attach accumulated participants to group entries
  for (const [key, addrs] of groupParticipants) {
    const entry = result.get(key)
    if (entry) entry.participants = [...addrs]
  }

  return Array.from(result.values()).sort((a, b) => (b.latest_ts ?? 0) - (a.latest_ts ?? 0))
}

// ── Messages for inbox ────────────────────────────────────────────────────────

export function getInboxEmails(mailbox: string, contact: string, selfAddr: string, account: string): Email[] {
  if (contact.startsWith('group:')) {
    const groupId = contact.slice(6)
    const allMsgs = messages.forIdentity(account)
    const groupThreadIds = new Set<string>()
    for (const email of allMsgs) {
      if (readGroupHeaders(email).id === groupId) {
        const tid = email.threadId as string
        if (tid) groupThreadIds.add(tid)
      }
    }
    return allMsgs.filter(email => {
      if (readGroupHeaders(email).id === groupId) return true
      const tid = email.threadId as string
      return tid ? groupThreadIds.has(tid) : false
    })
  }
  // Fix A: group-bearing emails belong to their group inbox only. Build the set of
  // thread ids that touch ANY group so threadId-matched replies (which may lack the
  // Chat-Group-ID header) are excluded from 1:1 lists too — otherwise a group's
  // messages leak into a per-contact inbox via from/to matching.
  const allMsgs = messages.forIdentity(account)
  const groupThreadIds = new Set<string>()
  for (const email of allMsgs) {
    if (readGroupHeaders(email).id) {
      const tid = email.threadId as string
      if (tid) groupThreadIds.add(tid)
    }
  }
  return allMsgs.filter(email => {
    if (isSecurejoinEmail(email)) return false
    if (readGroupHeaders(email).id) return false
    const tid = email.threadId as string
    if (tid && groupThreadIds.has(tid)) return false

    const mbxIds = Object.keys((email.mailboxIds as any) ?? {})
    const mbxName = mbxIds.map(id => mailboxNameFromId(id)).find(n => n) ?? ''
    if (mbxName !== mailbox) return false

    const fromEmail = (email.from as any[])?.[0]?.email as string ?? ''
    const toEmails = ((email.to as any[]) ?? []).map((a: any) => a.email as string)
    const isSent = fromEmail === selfAddr
    const emailContact = isSent ? (toEmails[0] ?? '') : fromEmail
    return emailContact === contact
  })
}

export async function fetchInboxMessages(inboxSummary: InboxSummary): Promise<ProcessedMessage['msg'][]> {
  const session = activeSession()
  if (!session) return []
  const selfAddr = session.jmapAccountId || session.account.email
  const emails = getInboxEmails(inboxSummary.mailbox, inboxSummary.contact, selfAddr, session.account.email)
  const msgs = emails.map(e => emailToMsg(e, selfAddr)).sort((a, b) => a.ts - b.ts)
  // Fill in group metadata for threadId-matched replies that lack Chat-Group-ID header.
  if (inboxSummary.group_id) {
    for (const msg of msgs) {
      if (!msg.group_id) {
        msg.group_id = inboxSummary.group_id
        msg.group_name = inboxSummary.group_name
      }
    }
  }
  return msgs
}

// ── Send ──────────────────────────────────────────────────────────────────────

export interface Recipients { to: string[]; cc?: string[]; bcc?: string[] }

export async function jmapCreateEmail(
  recips: string[] | Recipients, body: string, subject = '', inReplyTo = '',
  groupOpts?: GroupOpts,
  references: string[] = [],
  senderEmail?: string,
  relayUrl?: string,
): Promise<{ ok: boolean; fromEmail?: string; error?: string }> {
  // Array form (legacy callers): first entry is To, the rest are Cc, no Bcc.
  // Object form (the #new composer): explicit To/Cc/Bcc from the recipient rows.
  const to = Array.isArray(recips) ? recips.slice(0, 1) : recips.to
  const cc = Array.isArray(recips) ? recips.slice(1) : (recips.cc ?? [])
  const bcc = Array.isArray(recips) ? [] : (recips.bcc ?? [])
  // senderEmail lets the caller (the #new "From" selector) pick which logged-in
  // account sends; falls back to the active session for every other call site.
  // Route to a specific relay when given (reply → conversation's origin relay;
  // new compose → the protocol chosen from the recipient's AP badge). Fall back
  // to any relay for the sender, then the active session.
  const session = (senderEmail && relayUrl ? sessionForRelay(senderEmail, relayUrl) : null)
    ?? (senderEmail ? sessionFor(senderEmail) : null)
    ?? activeSession()
  if (!session) { console.warn('[send] fail: no active session'); return { ok: false } }

  const { jmapClient: client, jmapAccountId: accountId } = session

  // Init race: on first load the sync that populates the mailbox/identity stores
  // may not have finished yet (Safari/Brave lose the race Chrome usually wins),
  // leaving these stores empty and failing the send. Fetch on demand so the
  // very first compose after load works regardless of sync timing.
  if (!mailboxes.all().length) {
    try { mailboxes.set((await jmapMailbox.get(client, accountId)).mailboxes) }
    catch (e) { console.warn('[send] Mailbox.get failed', e) }
  }
  if (!identities.all().length) {
    try { identities.set((await jmapIdentity.get(client, accountId)).identities) }
    catch (e) { console.warn('[send] Identity.get failed', e) }
  }

  const fromEmail = session.account.email

  // Pick a mailbox owned by the SENDING account. The global `mailboxes` store is
  // overwritten per-account on sync (mailboxes.set replaces the whole list), so
  // it may currently hold a *different* account's mailboxes; filing the sent copy
  // into those tags it with the wrong mailboxId and splits the thread across
  // inboxes after re-sync. Prefer this account's own mailboxes (its inbox is
  // named after the account email); fetch them on demand if the global store
  // holds someone else's.
  let acctMailboxes = mailboxes.all().filter(m => m.name === fromEmail)
  if (!acctMailboxes.length) {
    try { acctMailboxes = (await jmapMailbox.get(client, accountId)).mailboxes } catch { /* keep empty */ }
  }
  const mbx = acctMailboxes.find(m => (m as any).role === 'inbox')
    ?? acctMailboxes.find(m => m.name === fromEmail)
    ?? acctMailboxes[0]
    ?? (currentInbox ? mailboxes.byName(currentInbox.mailbox) : null)
    ?? mailboxes.all()[0]
  if (!mbx) { console.warn('[send] fail: no mailbox', { fromEmail, count: mailboxes.all().length }); return { ok: false } }
  const identityList = identities.all()
  const identity = identityList.find(i => (i.email as string) === fromEmail) ?? identityList[0]
  if (!identity) { console.warn('[send] fail: no identity', { count: identityList.length }); return { ok: false } }

  let emailBody = body
  const serverUrl = session.account.serverUrl
  const password = session.account.password
  // To+Cc are the visible recipients (gossiped); Bcc keys are added for
  // decryption but kept out of the gossip (see encryptText). Skip PGP entirely
  // for ActivityPub sends — fediverse Notes are plaintext and the AP relay has
  // no peer-key/WKD surface, so encrypting there just fails a lookup with noise.
  if (!isApRelay(serverUrl)) {
    const enc = await encryptText(body, [...to, ...cc], fromEmail, serverUrl, password, inReplyTo, groupOpts, bcc)
    if (enc) emailBody = enc
  }

  const draft: Record<string, any> = {
    mailboxIds: { [mbx.id as string]: true },
    keywords: { $draft: true },
    from: [{ email: fromEmail }],
    to: to.map(e => ({ email: e })),
    subject: subject || '',
    textBody: [{ partId: '1', type: 'text/plain' }],
    bodyValues: { '1': { value: emailBody, isEncodingProblem: false, isTruncated: false } },
  }
  if (cc.length) draft['cc'] = cc.map(e => ({ email: e }))
  if (bcc.length) draft['bcc'] = bcc.map(e => ({ email: e }))
  if (inReplyTo) draft['inReplyTo'] = [inReplyTo]
  if (references.length) draft['references'] = references
  if (groupOpts) Object.assign(draft, groupDraftHeaders(groupOpts))

  try {
    await jmapSubmission.send(client, accountId, draft, identity.id as string)
    return { ok: true, fromEmail }
  } catch (e1) {
    console.warn('[send] EmailSubmission.send failed, trying draft save', e1)
    try {
      await (client.api as any).Email.set({ accountId, create: { draft } })
    } catch (e2) { console.warn('[send] draft Email.set also failed', e2) }
    return { ok: false, fromEmail, error: (e1 as Error).message }
  }
}

export async function currentSenderEmail(): Promise<string> {
  return activeSession()?.account.email ?? ''
}

export interface Sender { email: string; name: string }
export function currentSenderSync(): Sender {
  const sess = activeSession()
  const email = sess?.account.email ?? ''
  return { email, name: email.split('@')[0] }
}

export async function getIdentityId(): Promise<string | null> {
  const sess = activeSession()
  if (!sess) return null
  const email = sess.account.email
  const list = identities.all()
  return (list.find(i => (i.email as string) === email) ?? list[0])?.id as string ?? null
}

// ── PGP ───────────────────────────────────────────────────────────────────────

export async function initPGPForSession(session: AccountSession, kek?: Uint8Array): Promise<void> {
  if (!session.account.email.includes('@')) return
  // ActivityPub relays have no PGP key store (no /pgp/* routes, no CORS). Skip
  // them so account creation doesn't fire failing cross-origin key fetches.
  if (isApRelay(session.account.serverUrl)) return
  if (!kek) return
  try {
    await initPGP(session, kek)
  } catch (e) {
    console.error('[pgp] initPGPForSession failed', e)
  }
}

// ── Account management ────────────────────────────────────────────────────────

export async function addAccount(stored: StoredAccount): Promise<AccountSession | null> {
  const session = await initSession(stored)
  if (!session) return null

  const existing = loadStoredAccounts()
  if (!existing.some(a => a.email === stored.email)) {
    saveStoredAccounts([...existing, stored])
  }
  if (!sessions.some(s => s.account.email === stored.email)) {
    addSession(session)
  }
  return session
}

export function removeAccount(email: string): void {
  saveStoredAccounts(loadStoredAccounts().filter(a => a.email !== email))
  const idx = sessions.findIndex(s => s.account.email === email)
  if (idx >= 0) sessions.splice(idx, 1)
}

export async function logout(): Promise<void> {
  saveStoredAccounts([])
  sessions.length = 0
  setCurrentInbox(null)
  // Clear all localStorage keys belonging to biset
  const toRemove = Object.keys(localStorage).filter(k =>
    k.startsWith('biset') || k.startsWith('jmap_notif_') || k.startsWith('sjoin_invites_')
  )
  toRemove.forEach(k => localStorage.removeItem(k))
  await deleteAllKeys()
  await clearLocalCache()
  location.href = '/'
}
