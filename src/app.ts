import type { Email } from 'jmap-rfc-types'
import type { AccountSession, StoredAccount, InboxSummary } from './types.ts'
import { readGroupHeaders, groupDraftHeaders, isSecurejoinEmail, isEdit, collectEdits, type GroupOpts, type ChatAction } from './deltachat/protocol.ts'
import { isReaction, collectReactions } from './mail/reactions.ts'
import { avatarDataUrl, groupCacheKey, learnContactName, contactNameFor } from './deltachat/avatar.ts'
import {
  sessions, addSession, setCurrentInbox, currentInbox, activeSession, sessionFor, sessionForRelay,
  loadStoredAccounts, saveStoredAccounts, identityIds, relaysForId, identityKey, isApRelay, isDidCommRelay,
  accountKey,
} from './context.ts'
import { initSession } from './jmap/client.ts'
import * as messages from './store/messages.ts'
import * as threads from './store/threads.ts'
import * as mailboxes from './store/mailboxes.ts'
import * as identities from './store/identities.ts'
import * as jmapEmail from './jmap/email.ts'
import * as jmapSubmission from './jmap/submission.ts'
import * as jmapIdentity from './jmap/identity.ts'
import * as jmapMailbox from './jmap/mailbox.ts'
import { initPGP } from './pgp/index.ts'
import { encryptText, type OutgoingAttachment } from './pgp/crypto.ts'
import { loginViaEnvelope, authTokenToBasicAuth, fetchAccountAliases } from './cryptenv.ts'
import { mailboxNameFromId } from './utils.ts'
import { contactIdentityKey, allKnownAddressesFor, shortDid } from './did/contacts.ts'
import { stableIdKey } from './did/idkey.ts'
import { displayNameFor } from './did/displayname.ts'
import { conversations, groupAddress } from './mls/conversation.ts'
import type { ProcessedMessage } from './state.ts'

export { loginViaEnvelope, authTokenToBasicAuth }
export { initSession }

// A no-op `unload` listener, registered once at module load, purely to make
// this page ineligible for the back/forward cache (bfcache) — found live,
// 2026-08-12: logout()'s wipe-then-navigate below kept landing back on the
// account page it had just wiped, on at least one file:// browser, no matter
// which of four different navigation techniques triggered it (a straight
// `location.href` reassignment, `history.replaceState` + `location.reload()`,
// the same with `location.hash = ''` first, and a simulated real link click —
// see the dated history still in the comment below). Every one of those
// "worked" in the sense that the browser visibly navigated, yet
// `bootSessionsPromise` (main.ts, a MODULE-LEVEL memoized promise, reset only
// by the JS actually re-executing from a cold module load) kept answering
// with its pre-logout `{configured: true}` — which is exactly the signal
// route() uses to land on the account page (main.ts: `!sessions.length &&
// configured` → `showMenuPage('/account')`, which writes `#account` into the
// URL itself, deliberately — this was never a "stale hash survived" bug,
// the app was choosing that page correctly for what looked, from inside a
// bfcache-restored JS heap, like a still-configured identity). A page kept
// in bfcache is restored by replaying its exact in-memory state instead of
// re-running module top-level code, so a real navigation can "succeed" and
// still never touch `bootSessionsPromise` at all. An `unload` listener —
// even one that does nothing — is the standard, widely-supported way to opt
// a page out of bfcache eligibility, forcing every subsequent navigation
// away from it to be a genuine cold reload.
if (typeof window !== 'undefined') window.addEventListener('unload', () => {})

// ── Email → ProcessedMessage.msg ──────────────────────────────────────────────

// RFC 3676 signature delimiter: a line that is exactly "-- " on its own. Mail
// clients (and DeltaChat's per-message "status" footer) use this to mark
// everything below as a signature — without stripping it, a sender's status
// text repeats verbatim in every chat bubble (issue #3).
function stripSignature(body: string): string {
  const lines = body.split('\n')
  const idx = lines.findIndex(l => l.replace(/\r$/, '') === '-- ')
  if (idx < 0) return body
  return lines.slice(0, idx).join('\n').replace(/\s+$/, '')
}

export function emailToMsg(email: Email, _selfAddr: string): ProcessedMessage['msg'] {
  const from = (email.from as any[])?.[0]
  const rawBody = (Object.values((email.bodyValues as any) ?? {}) as any[])[0]?.value as string ?? ''
  const body = stripSignature(rawBody)
  const { id: groupId, name: groupName } = readGroupHeaders(email)
  return {
    from: (from?.email as string) ?? '',
    from_name: (from?.name as string) || '',
    body: body as string,
    subject: (email.subject as string) ?? '',
    ts: email.receivedAt ? new Date(email.receivedAt as string).getTime() : 0,
    message_id: ((email.messageId as string[])?.[0]) ?? (email.id as string),
    jmap_id: email.id as string,
    in_reply_to: ((email.inReplyTo as string[])?.[0]) ?? '',
    references: ((email.references as string[]) ?? []).filter(Boolean),
    thread_id: (email.threadId as string) ?? '',
    to_addrs: ((email.to as any[]) ?? []).map((a: any) => a.email as string),
    cc_addrs: ((email.cc as any[]) ?? []).map((a: any) => a.email as string),
    group_id: groupId,
    group_name: groupName,
    seen: !!((email.keywords as any)?.['$seen']),
    keywords: (email.keywords as Record<string, boolean>) ?? {},
  }
}

// Learns DeltaChat contact display names (deltachat/avatar.ts's
// learnContactName) from every message already sitting in the local store —
// sync/session.ts only does this for messages freshly fetched over JMAP, so a
// conversation synced before that code existed (or before its first sync
// after an app update) never got its sender's name recorded. Called once at
// startup after loadFromCache() populates the store, so existing history
// backfills without waiting for new mail.
// For a DeltaChat/chatmail contact the name lives ONLY in the protected From
// inside the encrypted part (readSenderNameFromMime), so the cleartext pass
// above finds nothing and the name would stay missing until that contact
// happens to send a NEW message. Decrypting all of history to fix that would
// cost hundreds of PGP operations at startup, so decrypt exactly one message
// per still-unnamed sender — their newest, which carries their current name.
// Bounded by contact count (a handful), and runs detached from the boot path.
async function backfillProtectedNames(): Promise<void> {
  const { decryptAndParse } = await import('./pgp/crypto.ts')
  const { readSenderNameFromMime } = await import('./deltachat/protocol.ts')

  // account key → the address whose private key decrypts that account's mail.
  const accountEmails = new Map(sessions.map(s => [accountKey(s.account), s.account.email]))

  const newestBySender = new Map<string, Email>()
  for (const email of messages.all()) {
    const addr = (email.from as any[] | undefined)?.[0]?.email as string | undefined
    if (!addr) continue
    if (sessions.some(s => s.account.email.toLowerCase() === addr.toLowerCase())) continue
    if (contactNameFor(addr)) continue
    const prev = newestBySender.get(addr.toLowerCase())
    const ts = email.receivedAt ? new Date(email.receivedAt as string).getTime() : 0
    const prevTs = prev?.receivedAt ? new Date(prev.receivedAt as string).getTime() : -1
    if (ts > prevTs) newestBySender.set(addr.toLowerCase(), email)
  }

  for (const [addr, email] of newestBySender) {
    const user = accountEmails.get(messages.accountOf(email))
    if (!user) continue
    const raw = (Object.values((email.bodyValues as any) ?? {}) as any[])[0]?.value as string ?? ''
    if (!raw.includes('-----BEGIN PGP MESSAGE-----')) continue
    try {
      const dec = await decryptAndParse(raw, user)
      const name = dec?.headers ? readSenderNameFromMime(dec.headers) : undefined
      if (name) await learnContactName(addr, name)
    } catch { /* one unreadable message shouldn't stop the rest */ }
  }
}

// Sweeps group history for a Chat-Group-Avatar. Needed because that header
// rides on the ONE message where the avatar was set — typically the group's
// oldest — rather than on the newest like a contact name, and because group
// messages historically weren't decrypted at all past the first one in a
// thread (see sync/session.ts's note on the removed decrypt-skip), so
// learnGroupAvatar never got a chance to see them. Oldest-first for that
// reason, stopping at the first hit.
//
// A group that has no avatar at all would otherwise be re-swept on every
// start, so the result is recorded either way (markGroupScanned) and the
// per-group work is capped. New messages still go through the normal sync
// path, so an avatar set later is picked up there without another sweep.
const GROUP_SWEEP_CAP = 250

async function backfillGroupAvatars(): Promise<boolean> {
  const { decryptAndParse } = await import('./pgp/crypto.ts')
  const { learnGroupAvatar, avatarDataUrl: lookup, groupCacheKey: gkey, wasGroupScanned, markGroupScanned } =
    await import('./deltachat/avatar.ts')

  const accountEmails = new Map(sessions.map(s => [accountKey(s.account), s.account.email]))

  const byGroup = new Map<string, Email[]>()
  for (const email of messages.all()) {
    const gid = readGroupHeaders(email).id
    if (!gid) continue
    if (lookup(gkey(gid)) || wasGroupScanned(gid)) continue
    const list = byGroup.get(gid)
    if (list) list.push(email)
    else byGroup.set(gid, [email])
  }

  if (!byGroup.size) return false
  console.log('[group-avatar] sweeping', byGroup.size, 'group(s) with no avatar yet')

  let learned = false
  for (const [gid, list] of byGroup) {
    list.sort((a, b) => {
      const ta = a.receivedAt ? new Date(a.receivedAt as string).getTime() : 0
      const tb = b.receivedAt ? new Date(b.receivedAt as string).getTime() : 0
      return ta - tb
    })
    // Counters exist to make a fruitless sweep diagnosable: "no avatar" and
    // "never got far enough to look" are indistinguishable from the outcome
    // alone, and they have completely different fixes.
    // Kept as counters rather than a bare outcome: "this group never carried
    // an avatar" and "the sweep never got far enough to look" produce the
    // same silence otherwise, and they have opposite fixes.
    let noAccount = 0, notPgp = 0, decryptFailed = 0, decrypted = 0, sawHeader = 0
    for (const email of list.slice(0, GROUP_SWEEP_CAP)) {
      const user = accountEmails.get(messages.accountOf(email))
      if (!user) { noAccount++; continue }
      const raw = (Object.values((email.bodyValues as any) ?? {}) as any[])[0]?.value as string ?? ''
      if (!raw.includes('-----BEGIN PGP MESSAGE-----')) { notPgp++; continue }
      try {
        const dec = await decryptAndParse(raw, user)
        if (!dec) { decryptFailed++; continue }
        decrypted++
        if (dec.headers?.['chat-group-avatar'] !== undefined) sawHeader++
        await learnGroupAvatar(gid, dec)
        if (lookup(gkey(gid))) { learned = true; break }
      } catch { decryptFailed++ }
    }
    // Flattened into the message string rather than passed as an object: the
    // console collapses objects to "Object" and the counters are the whole
    // point of the line.
    console.log(`[group-avatar] ${gid}: ${list.length} msgs decrypted=${decrypted} sawHeader=${sawHeader} decryptFailed=${decryptFailed} notPgp=${notPgp} noAccount=${noAccount} got=${!!lookup(gkey(gid))}`)
    // Only record the group as swept when the pass was actually conclusive.
    // A run that couldn't decrypt (no key yet at boot, a transient failure)
    // has NOT established that there's no avatar, and marking it would make
    // that temporary condition permanent.
    const conclusive = decryptFailed === 0 && noAccount === 0 && list.length <= GROUP_SWEEP_CAP
    if (conclusive || lookup(gkey(gid))) await markGroupScanned(gid)
  }
  return learned
}

// Learns whatever display identity (names, group avatars) is recoverable from
// history already in the store, for the cases the live sync path can't cover.
// Named for the cleartext pass it starts with; the two decrypt-based sweeps
// run detached behind it.
export function backfillContactNames(): void {
  for (const email of messages.all()) {
    const from = (email.from as any[] | undefined)?.[0]
    const addr = from?.email as string | undefined
    const name = from?.name as string | undefined
    if (!addr || !name) continue
    if (sessions.some(s => s.account.email.toLowerCase() === addr.toLowerCase())) continue
    learnContactName(addr, name)
  }
  // Detached: this is a display nicety, never worth delaying first paint.
  // Names land in a synchronous cache the left pane re-reads on its next
  // render pass, so those need no redraw of their own; a group avatar does,
  // since avatar_url is baked into the InboxSummary at build time.
  void (async () => {
    await backfillProtectedNames()
    const learned = await backfillGroupAvatars()
    if (learned) {
      const { loadLeftInboxes } = await import('./ui/left-pane.ts')
      loadLeftInboxes()
    }
  })()

  // Console hook: forces a fresh sweep regardless of stored markers. Without
  // it the only way to retry a sweep is to ship a SWEEP_VERSION bump, i.e. a
  // deploy per diagnostic attempt.
  ;(window as any).__bisetRescanGroupAvatars = async () => {
    const { clearGroupScanMarkers } = await import('./deltachat/avatar.ts')
    await clearGroupScanMarkers()
    const got = await backfillGroupAvatars()
    const { loadLeftInboxes } = await import('./ui/left-pane.ts')
    loadLeftInboxes()
    return got
  }
}

// ── Inbox summaries ───────────────────────────────────────────────────────────

export async function loadInboxSummaries(): Promise<InboxSummary[]> {
  const result = new Map<string, InboxSummary>()

  const groupParticipants = new Map<string, Set<string>>()
  // has_unread only tracks "at least one" — the left-pane's per-inbox count
  // badge needs the real number, so tally separately and attach at the end
  // (mirrors groupParticipants' same two-pass shape below).
  const unreadCounts = new Map<string, number>()

  for (const identityId of identityIds()) {
    // Identity-by-DID: identityId is the DID (or an email for a not-yet-derived
    // account). `user` is the identity's representative address — used for the
    // own/sent check, From, and reply routing (which resolves it through the DID
    // via relaysFor, so it works even across a moved identity's addresses).
    const endpoints = relaysForId(identityId)
    const userEmail = endpoints[0]?.account.email ?? identityId
    const accountId = userEmail
    // Every address this identity could plausibly send FROM — the login
    // identity (jmapCreateEmail's fromEmail, mailbox/PGP-keyed) for each
    // endpoint AND its display alias (what the From header actually
    // carries for a SCID-primary account, PLANSCID.md). A sent message's
    // own `from` is always the display address, never the login one, so
    // checking only `userEmail` here misclassified every SCID-primary
    // account's own sent mail as incoming — from itself — splitting the
    // conversation (found live, 2026-08-18, alongside the missing
    // References header).
    const selfAddrs = new Set(endpoints.flatMap(e => [e.account.email, e.account.displayEmail].filter((x): x is string => !!x)))

    // This identity's messages, merged across ALL its relays and addresses
    // (forIdentity resolves the DID's current sessions dynamically, so a
    // moved identity unifies without needing any stamped field to catch up).
    const ownMessages = messages.forIdentity(identityId)

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
      // RFC 9078 reactions aren't chat messages — they attach to their target
      // (see fetchInboxMessages) and never bump unread/latest previews here.
      if (isReaction(email)) continue
      // Chat-Edit requests aren't chat messages either — they overwrite their
      // target's text (see fetchInboxMessages) and shouldn't surface on their own.
      if (isEdit(email)) continue

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
      // `userEmail`/`accountId` are both whichever RELAY address happened to be
      // this identity's first session (see above) — a DIDComm message's own
      // `from` is always this identity's DID instead, which never equals
      // either for a relay-backed identity that also has DIDComm, so an own
      // sent DIDComm message was misread as an incoming one from a stranger
      // (wrongly unread, and — see isSent below — filed as if received FROM
      // itself). Comparing against `identityId` (this loop's own DID) too
      // covers the DIDComm case without disturbing the plain-relay one.
      const senderEmail = (email.from as any[])?.[0]?.email as string ?? ''
      // `identityId` is normalized (context.ts's identityKey → stableIdKey),
      // `senderEmail` is whatever went on the wire — a full DID for a DIDComm
      // message. Normalizing the sender too is what keeps this true across a
      // did:webvh domain move: messages sent under the PRE-move DID string are
      // still recognised as our own (PLANWEBVH.md §3.1).
      const isOwn = senderEmail === userEmail || senderEmail === accountId || stableIdKey(senderEmail) === identityId
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
        if (has_unread) unreadCounts.set(key, (unreadCounts.get(key) ?? 0) + 1)

        const existing = result.get(key)
        if (!existing || ts > (existing.latest_ts ?? 0)) {
          result.set(key, {
            user: userEmail,
            mailbox: '',
            contact: `group:${groupId}`,
            inbox_type: 'group',
            group_id: groupId,
            group_name: groupName,
            avatar_url: avatarDataUrl(groupCacheKey(groupId)),
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

      // Same DID-vs-relay-email gap as isOwn above — without identityId here,
      // an own sent DIDComm message's `contact` became its OWN did (fromEmail,
      // since isSent was wrongly false), producing an inbox row that pointed
      // at itself instead of the actual recipient. mailbox and contact ending
      // up identical (both this identity's own DID) is the exact symptom.
      const isSent = selfAddrs.has(fromEmail) || fromEmail === accountId || stableIdKey(fromEmail) === identityId
      const contact = isSent ? (toEmails[0] ?? '') : fromEmail
      if (!contact || !mbxName) continue

      // Group by the contact's DID when contacts.json has learned one, not the
      // literal address — so a contact who migrated relays mid-conversation
      // stays one inbox row instead of forking into two (see did/contacts.ts).
      const key = `${userEmail}\0${mbxName}\0${contactIdentityKey(contact)}`
      const existing = result.get(key)
      if (has_unread) unreadCounts.set(key, (unreadCounts.get(key) ?? 0) + 1)

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

  // Group conversations this device is IN but has no messages for yet.
  //
  // A conversation exists the moment the Welcome is accepted — before anyone
  // has said anything in it. Deriving the list purely from stored messages
  // would hide exactly that moment: someone adds you to a group and nothing
  // appears until they also happen to speak. The group's own state is the
  // authority on whether it exists; messages only decide where it sorts.
  for (const identityId of identityIds()) {
    if (!identityId.startsWith('did:')) continue
    const endpoints = relaysForId(identityId)
    const userEmail = endpoints[0]?.account.email ?? identityId
    for (const c of await conversations(identityId).catch(() => [])) {
      const address = groupAddress(c.id)
      const key = `${userEmail}\0\0group:${address}`
      const existing = result.get(key)
      if (existing) {
        // Membership comes from the ratchet tree, not from who happens to have
        // spoken — a member who has never sent anything is still a member.
        existing.participants = [...new Set([...(existing.participants ?? []), ...c.members.filter(m => m !== identityId)])]
        if (c.name && !existing.group_name) existing.group_name = c.name
        continue
      }
      result.set(key, {
        user: userEmail, mailbox: '', contact: `group:${address}`,
        inbox_type: 'group', group_id: address, group_name: c.name || 'Group',
        participants: c.members.filter(m => m !== identityId),
        latest_ts: c.updatedAt, latest_body: '', latest_subject: c.name || '',
      })
    }
  }

  // Attach accumulated participants to group entries
  for (const [key, addrs] of groupParticipants) {
    const entry = result.get(key)
    if (entry) entry.participants = [...addrs]
  }

  // Attach accumulated unread counts
  for (const [key, count] of unreadCounts) {
    const entry = result.get(key)
    if (entry) entry.unread_count = count
  }

  return Array.from(result.values()).sort((a, b) => (b.latest_ts ?? 0) - (a.latest_ts ?? 0))
}

// ── Messages for inbox ────────────────────────────────────────────────────────

// `identity` is the identity key (DID, or email for a DID-less relay) —
// forIdentity() resolves it to the matching `_account` set dynamically.
// Callers map their email through identityKey / identityKeyForEmail before calling.
export function getInboxEmails(mailbox: string, contact: string, selfAddr: string | string[], identity: string): Email[] {
  const selfAddrs = new Set(Array.isArray(selfAddr) ? selfAddr : [selfAddr])
  if (contact.startsWith('group:')) {
    const groupId = contact.slice(6)
    const allMsgs = messages.forIdentity(identity)
    const groupThreadIds = new Set<string>()
    for (const email of allMsgs) {
      if (readGroupHeaders(email).id === groupId) {
        const tid = email.threadId as string
        if (tid) groupThreadIds.add(tid)
      }
    }
    return allMsgs.filter(email => {
      if (isReaction(email)) return false
      if (isEdit(email)) return false
      if (readGroupHeaders(email).id === groupId) return true
      const tid = email.threadId as string
      return tid ? groupThreadIds.has(tid) : false
    })
  }
  // Fix A: group-bearing emails belong to their group inbox only. Build the set of
  // thread ids that touch ANY group so threadId-matched replies (which may lack the
  // Chat-Group-ID header) are excluded from 1:1 lists too — otherwise a group's
  // messages leak into a per-contact inbox via from/to matching.
  const allMsgs = messages.forIdentity(identity)
  const groupThreadIds = new Set<string>()
  for (const email of allMsgs) {
    if (readGroupHeaders(email).id) {
      const tid = email.threadId as string
      if (tid) groupThreadIds.add(tid)
    }
  }
  const contactAddrs = allKnownAddressesFor(contact)
  return allMsgs.filter(email => {
    if (isSecurejoinEmail(email)) return false
    if (isReaction(email)) return false
    if (isEdit(email)) return false
    if (readGroupHeaders(email).id) return false
    const tid = email.threadId as string
    if (tid && groupThreadIds.has(tid)) return false

    const mbxIds = Object.keys((email.mailboxIds as any) ?? {})
    const mbxName = mbxIds.map(id => mailboxNameFromId(id)).find(n => n) ?? ''
    if (mbxName !== mailbox) return false

    const fromEmail = (email.from as any[])?.[0]?.email as string ?? ''
    const toEmails = ((email.to as any[]) ?? []).map((a: any) => a.email as string)
    // `selfAddr` is whichever relay address(es) fetchInboxMessages's
    // activeSession() resolved to — both the login identity AND the
    // display alias now (a sent message's own `from` is always the
    // display one for a SCID-primary account, PLANSCID.md, never the
    // login address `selfAddr` used to be a bare string of). A DIDComm
    // message's own `from` is this identity's DID instead, which
    // `selfAddrs` alone never matches for a relay-backed identity that
    // also has DIDComm (loadInboxSummaries' isSent has the exact same gap
    // — see its note). `identity` is this call's DID (or email, for a
    // DID-less relay), so it's the one comparison that works for both.
    const isSent = selfAddrs.has(fromEmail) || stableIdKey(fromEmail) === identity
    const emailContact = isSent ? (toEmails[0] ?? '') : fromEmail
    // Match any address grouped under the same contact-DID as `contact` (not
    // just the literal address), so a merged inbox row (see loadInboxSummaries)
    // actually surfaces messages sent to/from every address the contact has used.
    //
    // Compared through stableIdKey on the candidate because contactAddrs holds
    // the contact's normalized identity key alongside their literal addresses
    // (allKnownAddressesFor). A plain address normalizes to itself and matches
    // as before; a DID normalizes to the key — which is what makes messages
    // addressed to a correspondent's PRE-move did:webvh string keep landing in
    // the same thread as their post-move ones (PLANWEBVH.md §3.1).
    return contactAddrs.includes(stableIdKey(emailContact))
  })
}

export async function fetchInboxMessages(inboxSummary: InboxSummary): Promise<ProcessedMessage['msg'][]> {
  const session = activeSession()
  if (!session) return []
  // Query by the identity key (DID, or email for a DID-less relay) — forIdentity()
  // resolves this to the account's current sessions dynamically, so the thread
  // isn't empty for a DID-bearing account (grouped by DID, not by literal email).
  const identity = identityKey(session)
  // Every address this identity's endpoints could send FROM — login identity
  // AND display alias for each (getInboxEmails' own note: a sent message's
  // `from` is always the display one for a SCID-primary account).
  const selfAddrs = relaysForId(identity).flatMap(s => [s.jmapAccountId, s.account.email, s.account.displayEmail].filter((x): x is string => !!x))
  const emails = getInboxEmails(inboxSummary.mailbox, inboxSummary.contact, selfAddrs, identity)
  const msgs = emails.map(e => emailToMsg(e, session.account.email)).sort((a, b) => a.ts - b.ts)
  // RFC 9078 reactions were filtered out of `emails` above (they're not chat
  // messages) — reattach them to their target message for display. Scan the
  // whole identity (not just this inbox's emails) since a reaction can arrive
  // over a different relay than its target (mail + AP for one identity).
  const reactionMap = collectReactions(messages.forIdentity(identity))
  for (const msg of msgs) {
    const rs = reactionMap.get(msg.message_id)
    if (rs?.length) msg.reactions = rs.map(r => ({ emoji: r.emoji, from: r.from }))
  }
  // Chat-Edit requests were filtered out of `emails` above too — apply the
  // latest one directly onto msg.body (pre-decrypt stage: it's already
  // plaintext, so processIncoming's PGP-marker check just passes it through).
  const editMap = collectEdits(messages.forIdentity(identity))
  for (const msg of msgs) {
    const editedText = editMap.get(msg.message_id)
    if (editedText !== undefined) { msg.body = editedText; msg.edited = true }
  }
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
  attachments: OutgoingAttachment[] = [],
  chatAction?: ChatAction,
  // `partial` is DIDComm-only: that transport fans a message out to each of the
  // recipient's registered devices individually, so "sent" can mean "reached
  // some of them" (see channel.ts's DidCommSendResult). Nothing else here can
  // partially succeed — a relay either accepts the submission or doesn't.
): Promise<{ ok: boolean; fromEmail?: string; error?: string; partial?: { delivered: number; total: number } }> {
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

  // A recipient addressed directly by DID (composed that way, or replying
  // within a DIDComm-sourced conversation whose session IS the synthetic
  // DIDComm one) sends over DIDComm instead of JMAP — regardless of which of
  // the sender's OWN relays happens to be selected as "From": the sending
  // identity is the same did:dht either way (DID⊥relay — one identity, many
  // endpoints), so `session.account.did` is what to send AS, not which
  // relay-session resolved. None of the mailbox/identity/PGP machinery below
  // applies (no server mailbox to look up, no WKD/relay peer-key surface —
  // DIDComm's own authcrypt already gives E2E confidentiality, the same
  // reasoning isApRelay's PGP skip uses). `to[0]` is the recipient's did:dht
  // string; cc/bcc/attachments aren't supported over this transport.
  // A group conversation is addressed by the group itself, not by its members
  // (mls/conversation.ts's `mls:` prefix): one submission goes to the group's
  // Delivery Service, which fans it out. Addressing the members individually
  // would be N separate 1:1 messages that happen to have the same text — not
  // the same conversation, and not readable as one by anybody.
  if (to[0]?.startsWith('mls:') && session.account.did) {
    const { sendToGroup } = await import('./did/didcomm/channel.ts')
    return await sendToGroup(session.account.did, to[0]!, body, subject)
  }
  const toIsDid = to[0]?.startsWith('did:')
  if ((isDidCommRelay(session.account.serverUrl) || toIsDid) && session.account.did) {
    const { sendViaDidComm } = await import('./did/didcomm/channel.ts')
    return await sendViaDidComm(session.account.did, to[0]!, body, subject)
  }

  const { jmapClient: client, jmapAccountId: accountId } = session

  // Init race: on first load the sync that populates the mailbox/identity stores
  // may not have finished yet (Safari/Brave lose the race Chrome usually wins),
  // leaving these stores empty and failing the send. Fetch on demand so the
  // very first compose after load works regardless of sync timing.
  if (!mailboxes.all().length) {
    try { mailboxes.set((await jmapMailbox.get(client, accountId)).mailboxes) }
    catch (e) { console.warn('[send] Mailbox.get failed', e) }
  }
  if (!identities.all(accountKey(session.account)).length) {
    try { identities.set(accountKey(session.account), (await jmapIdentity.get(client, accountId)).identities) }
    catch (e) { console.warn('[send] Identity.get failed', e) }
  }

  const fromEmail = session.account.email
  // What the recipient actually sees on the wire — the human-facing alias
  // for a SCID-primary account (PLANSCID.md), never the permanent login
  // identity. `fromEmail` itself has to stay the login address for
  // everything server-side (mailbox/identity lookups, PGP key lookup — all
  // keyed by the account's own login email), so this is a SEPARATE value
  // used only for the visible From header below. Without it, every SCID-
  // primary account's outgoing mail carried its 46-character SCID as the
  // From address — DeltaChat (and any client) treats a changed sender
  // address as a different contact, splitting an otherwise-continuous
  // conversation into a new thread on the recipient's end the moment they
  // replied to a message actually sent this way (found live, 2026-08-18,
  // alongside the missing References header — both needed fixing before a
  // reply reliably stayed in one thread).
  const displayFromEmail = session.account.displayEmail ?? fromEmail

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
  const identityList = identities.all(accountKey(session.account))
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
    const enc = await encryptText(body, [...to, ...cc], fromEmail, serverUrl, password, inReplyTo, groupOpts, bcc, attachments, chatAction, references)
    if (enc) emailBody = enc
  }

  // Identity.name (set via the "Change display name" modal) only reaches
  // recipients if it's on the From header — without it here, changing the
  // display name had no visible effect anywhere (issue #2).
  const fromName = (identity.name as string | undefined)?.trim()
  const draft: Record<string, any> = {
    mailboxIds: { [mbx.id as string]: true },
    keywords: { $draft: true },
    from: fromName ? [{ email: displayFromEmail, name: fromName }] : [{ email: displayFromEmail }],
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
  // A DIDComm conversation's messages always carry a DID as `from` — never
  // an email — but activeSession() picks WHICHEVER of this identity's
  // sessions (mail/AP/DIDComm) happens to be first in sessions[], usually a
  // relay session for a relay-backed identity that also has DIDComm. Every
  // endpoint of one identity shares the same `.did`, so the SEND itself
  // still worked either way — but the reply dock's optimistic pending stub
  // (shell.ts's addPendingMessage) used this relay email as its `from`,
  // which then never matched the DID `from` on the real message once it
  // arrived (addMessage's stub-drop check is a strict equality on `from`).
  // The stub was stuck at its dimmed pending opacity forever, correct
  // delivery notwithstanding — using the DID here for a DIDComm
  // conversation keeps the stub and the real message's `from` the same.
  if (isDidCommRelay(currentInbox?.relay) && sess?.account.did) {
    // `email` (the pending stub's `from`, matched exactly against the DID
    // once the real message arrives) must stay the raw DID — see the note
    // above. `name` is display-only and had no reason to be the same string:
    // it was showing the full did:dht:… everywhere a name renders (the
    // compose avatar initial, the pending bubble's sender label) right up
    // until the real message arrived with its own from_name — same source
    // sendViaDidComm (channel.ts) already resolves for that real message, so
    // resolving it here too means the pending stub matches from the start
    // instead of visibly changing once confirmed.
    const did = sess.account.did
    const name = displayNameFor(relaysForId(did).filter(s => !isDidCommRelay(s.account.serverUrl))) ?? shortDid(did)
    return { email: did, name }
  }
  // Display alias, not the login identity — the pending stub's `from` is
  // matched by strict equality against the REAL sent message's `from` once
  // it arrives (this function's own note above), and that real `from` is
  // always the display address for a SCID-primary account (PLANSCID.md),
  // never `account.email`. Using the login address here left the stub
  // permanently unmatched — stuck at pending opacity, or double-counted
  // once the real message landed under a different `from` (found live,
  // 2026-08-18, alongside the missing References header).
  const email = sess?.account.displayEmail ?? sess?.account.email ?? ''
  return { email, name: email.split('@')[0] }
}

export async function getIdentityId(): Promise<string | null> {
  const sess = activeSession()
  if (!sess) return null
  const email = sess.account.email
  const list = identities.all(accountKey(sess.account))
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

// Dedup-save `stored` to localStorage and register `session` in the live
// `sessions` list, keyed by (email, serverUrl) so mail and AP for the same
// identity coexist as separate sessions. Split out from connectAndPersist
// below for call sites that already resolved their own session (e.g.
// left-pane.ts's Log in, which tries a device-key reconnect before falling
// back to a password and would otherwise need to call initSession twice).
export function persistSession(stored: StoredAccount, session: AccountSession): void {
  const existing = loadStoredAccounts()
  if (!existing.some(a => a.email === stored.email && a.serverUrl === stored.serverUrl)) {
    saveStoredAccounts([...existing, stored])
  }
  if (!sessions.some(s => s.account.email === stored.email && s.account.serverUrl === stored.serverUrl)) {
    addSession(session)
  }
}

// The one place that turns a resolved StoredAccount into a live, persisted
// session — initSession, persistSession, and (if a kek is in hand) bring up
// PGP. Every login/signup/restore path (account-create.ts, custom-domain.ts,
// restore.ts) funnels its per-relay connect through here so the same steps
// can't drift out of sync across call sites again.
export async function connectAndPersist(stored: StoredAccount, kek?: Uint8Array): Promise<AccountSession | null> {
  const session = await initSession(stored).catch(e => {
    // initSession logs its own failures; this catch is for the ones it
    // throws rather than returns, which were being discarded entirely.
    console.error('[connectAndPersist] initSession threw:', stored.email, stored.serverUrl, e)
    return null
  })
  if (!session) return null
  persistSession(stored, session)
  if (kek) await initPGPForSession(session, kek)
  refreshDisplayEmail(session)
  healStaleMessageAccountKey(session)
  return session
}

/** Self-heals the exact damage a SCID migration (PLANSCID.md) leaves behind
 * on every OTHER device/reload after the one that ran it: every message
 * already synced before the migration is stamped with the OLD accountKey
 * (store/messages.ts's `_account`), and `forIdentity`'s join against the
 * now-current session stops matching any of them — an inbox with hundreds
 * of messages looks empty, though nothing was lost (found live, 2026-08-18,
 * the migration feature's first production use).
 *
 * Scoped safely by `displayEmail`, not by guessing: after a migration,
 * `displayEmail` IS the exact old login email for this same (serverUrl,
 * identity) pair (left-pane.ts's migration handler sets it to exactly
 * that) — never some OTHER identity's address that happens to share this
 * relay. Runs on every connect, not just once, and is a no-op once nothing
 * is left stamped under the old key (renameAccount's own early return) — so
 * this is safe to call unconditionally rather than tracking "have I healed
 * this session already" anywhere. */
function healStaleMessageAccountKey(session: AccountSession): void {
  const { email, displayEmail, serverUrl } = session.account
  if (!displayEmail || displayEmail === email) return
  const oldKey = accountKey({ email: displayEmail, serverUrl })
  const newKey = accountKey(session.account)
  import('./vault/persist.ts').then(persist => persist.renameMessageAccount(oldKey, newKey)).catch(() => {})
}

/** Fire-and-forget: corrects `session.account.displayEmail` (and the
 * persisted copy) against the relay's OWN live alias table, the moment a
 * session comes up — never blocks login on it. PLANSCID.md's display-layer
 * decision: a resolved DID document (what populates `displayEmail` at
 * claim/restore/sync time) is only ever a cache of this, and this is what
 * corrects the cache once an authenticated connection actually exists to
 * ask. No-op for an account still on the pre-SCID scheme (`aliases` comes
 * back empty there too — nothing to prefer over the login address itself).
 * `[0]` because a relay could in principle carry more than one alias; the
 * UI only ever has room to show one, and picking any live one beats a stale
 * cached guess. */
// Exported (was a private helper `connectAndPersist` alone called) so
// regular startup — `main.ts`'s `accounts.map(initSession)`, which does NOT
// go through `connectAndPersist` — can call it too. Without this, a
// `displayEmail` that drifted from reality (a migration, a rename, routing
// data lag) only ever self-corrected on the NEXT explicit connect action
// (login, restore, migrate) and never on a plain page reload — found live,
// 2026-08-18: an already-claimed, actively-syncing SCID account kept
// showing its permanent internal SCID address instead of its human alias
// across repeated reloads, because nothing on the reload path ever asked
// the relay again.
export function refreshDisplayEmail(session: AccountSession): void {
  const { serverUrl, email, password, displayEmail, did } = session.account
  fetchAccountAliases(serverUrl, email, password).then(async aliases => {
    if (!aliases?.length) return
    // Prefer the alias matching the DID's CURRENT did:webvh identifier
    // (jmapsmtp ARC.md §2.9's Lv2 — the one alias `did::alias_reconcile`
    // itself would keep current) over `aliases[0]`: the relay's own
    // `aliases_for` iterates a `BTreeMap<String, String>`, so index 0 is
    // whichever alias sorts first ALPHABETICALLY, which has nothing to do
    // with which one a human actually recognizes as "their" address.
    // Found live (2026-08-18): after a SCID-primary account's second
    // migration, its internal old-format address ("qmwpmygewt1...")
    // sorted before its real human alias ("y@..."), so this picked the
    // wrong one and the UI never self-corrected.
    let current = aliases[0]!
    if (did?.startsWith('did:webvh:')) {
      try {
        const { bisetWebvhUsername, parseWebvhDid } = await import('./did/webvh/identifier.ts')
        const username = bisetWebvhUsername(did)
        const domain = parseWebvhDid(did).domain
        const expected = username && `${username}@${domain}`
        if (expected && aliases.includes(expected)) current = expected
      } catch { /* not a path-shaped did:webvh — fall through to aliases[0] */ }
    }
    if (current === displayEmail) return
    session.account.displayEmail = current
    const accounts = loadStoredAccounts()
    const stored = accounts.find(a => a.serverUrl === serverUrl && a.email === email)
    if (stored) { stored.displayEmail = current; saveStoredAccounts(accounts) }
  }).catch(() => {})
}

export function removeAccount(email: string): void {
  saveStoredAccounts(loadStoredAccounts().filter(a => a.email !== email))
  const idx = sessions.findIndex(s => s.account.email === email)
  if (idx >= 0) sessions.splice(idx, 1)
}

/** The ONE full-logout path (DID.md "single teardown chokepoint"). Every
 * logout control routes here — the identity card's own hamburger menu
 * (left-pane.ts's renderAccountsList) is the only one the UI wires up, and a
 * caller once inlined its OWN wipe that skipped the deregister step entirely,
 * so every logout orphaned this device's DIDComm key in the mediator keylist
 * AND the published DID document forever (the whole "logout doesn't remove
 * the key" saga). There used to be a second, DEAD copy of this function too,
 * imported but never called — which is exactly how the divergence went
 * unnoticed. Keep this the sole implementation. */
export async function logout(): Promise<void> {
  // **No page navigation** (2026-08-12, user-requested, and it settles a long
  // fight): this used to end in a reload, and on file:// that reload kept not
  // happening — four different navigation techniques were tried on the
  // assumption that browsers were refusing the NAVIGATION, when the real
  // problem was that control often never reached it (an awaited cleanup step
  // hanging, each written as a bare `await` on the happy path). Logging out
  // doesn't actually need a fresh document: it needs the app to show the
  // account page in its zero-account state, which is a render, not a boot.
  // So the wipe now ends by re-rendering in place. Nothing here can leave
  // the user staring at a dead button any more.
  //
  // Because there's no reload, in-memory state has to be emptied explicitly
  // (stores below) rather than dying with the document — that's the one
  // thing a navigation was doing for free.
  //
  // Every cleanup step is still individually timeboxed and logged: they're
  // all best-effort local housekeeping (a re-login re-derives whatever a
  // failed step left behind), so none of them may block the re-render, and a
  // per-step trace is how the next silent failure gets diagnosed in one
  // round instead of four.
  const step = (name: string) => console.log('[logout] step:', name)
  // A step that never settles must not outlive its budget. 4s is generous
  // for local storage/IDB/cache work while still being far below a user's
  // patience for a button that looks dead.
  const bounded = async (label: string, work: () => Promise<unknown>): Promise<void> => {
    step(label)
    try {
      await Promise.race([
        work(),
        new Promise<void>(resolve => setTimeout(() => {
          console.warn(`[logout] ${label}: timed out, continuing anyway`)
          resolve()
        }, 4000)),
      ])
    } catch (e) {
      console.warn(`[logout] ${label}: failed, continuing anyway:`, e instanceof Error ? e.message : e)
    }
  }

  try {
    // Deregister this device from every identity's mediator BEFORE any wipe —
    // this is the ONE moment the keys that prove ownership of this device's
    // keyAgreement slot still exist locally. unregisterFromMediator does
    // keylist-update remove (point-to-point, authoritative — the mediator can't
    // be raced the way DHT gossip can) + republishes the DID document without
    // this device's key. Best-effort per identity, but NOT silent: a registered
    // device whose revoke genuinely fails would otherwise stay published with no
    // trace, indistinguishable from the ordinary "never registered" case.
    await bounded('unregister-from-mediators', async () => {
      const { unregisterFromMediator } = await import('./did/didcomm-devices.ts')
      await Promise.all(identityIds().map(did => unregisterFromMediator(did)
        .catch(e => console.warn(`[logout] unregisterFromMediator(${did}) failed — this device's DIDComm key may stay published:`, e instanceof Error ? e.message : e))))
    })

    step('clear-sessions')
    // Drop the unlocked at-rest key and the passkey handle guarding it
    // (did/store.ts, did/prf.ts) — the sealed records are about to be deleted
    // with the rest of IndexedDB, so keeping either would only leave a
    // credential pointing at nothing. The passkey itself stays in the
    // authenticator; a web page cannot remove one.
    try {
      const { lockIdentitySecrets } = await import('./did/store.ts')
      const { forgetPrfCredential } = await import('./did/prf.ts')
      lockIdentitySecrets()
      forgetPrfCredential()
    } catch { /* best-effort, same as every other step here */ }
    saveStoredAccounts([])
    sessions.length = 0
    setCurrentInbox(null)
    // In-memory stores too, since there's no reload to drop them (see this
    // function's header). Without this the wiped UI would re-render straight
    // out of RAM: the account list reads sessions[] (now empty, fine), but
    // the left pane's inbox rows and any open thread come from these.
    step('clear-in-memory-stores')
    messages.clear()
    threads.clear()
    mailboxes.set([])
    identities.clear()

    // Wipe ALL local data (the confirm text promises exactly this) EXCEPT the
    // did:dht rollback-defense floor (freshness.ts's 'biset_did_seq:' keys):
    // that store rejects a signed record with a LOWER seq than one already
    // trusted for a DID. Wiping it, then logging back into the same identity,
    // opened a real window where a stale gateway's ancient (pre-DIDComm)
    // document got accepted with no rollback check — wiping two live devices'
    // keys off the document in one shot (found live). It must survive exactly
    // this moment, so it's read out and restored across the clear().
    step('clear-web-storage')
    try {
      const keepSeq = Object.keys(localStorage)
        .filter(k => k.startsWith('biset_did_seq:'))
        .map(k => [k, localStorage.getItem(k)] as const)
      localStorage.clear()
      for (const [k, v] of keepSeq) if (v != null) localStorage.setItem(k, v)
    } catch (e) {
      console.warn('[logout] clear-web-storage failed, continuing anyway:', e instanceof Error ? e.message : e)
    }
    try { sessionStorage.clear() } catch { /* ignore */ }

    // Delete every app IndexedDB database — DID records included, so a re-login
    // mints a FRESH device key and re-syncs its slot from scratch instead of
    // reusing a stale local didCommOwnKid (that stale reuse is how a new device
    // landed back on an already-tombstoned slot number, found live).
    //
    // The prime hang suspect: a deleteDatabase with a live connection open
    // fires `blocked` and waits for that connection to close — which, for a
    // connection this very page holds, only happens on the reload this was
    // blocking. Timeboxed, so a blocked delete finishes on the next load
    // exactly as the original comment assumed it would.
    await bounded('delete-indexeddb', () => {
      const dbNames = ['biset-cache', 'biset-pgp', 'biset-did', 'biset-deltachat']
      return Promise.all(dbNames.map(name => new Promise<void>(resolve => {
        const req = indexedDB.deleteDatabase(name)
        req.onsuccess = () => resolve()
        req.onerror = () => resolve()
        req.onblocked = () => resolve()
      })))
    })

    // Caches + service worker so re-login lands on fresh app code, not a stale
    // cached bundle.
    if ('caches' in window) {
      await bounded('clear-caches', async () => {
        const keys = await caches.keys()
        await Promise.all(keys.map(k => caches.delete(k)))
      })
    }
    if ('serviceWorker' in navigator) {
      await bounded('unregister-service-workers', async () => {
        const regs = await navigator.serviceWorker.getRegistrations()
        await Promise.all(regs.map(r => r.unregister()))
      })
    }
  } finally {
    // Land on the account page in its zero-account state, unconditionally —
    // a render, not a navigation (see this function's header for why the
    // reload this replaces was the wrong tool). renderAccountsList already
    // draws exactly the right thing once sessions[] and the stored accounts
    // are empty: "No accounts" plus "+ New Relay", with the identity heading
    // hidden. loadLeftInboxes clears the left pane the same way, from the
    // stores emptied above.
    //
    // Dynamic imports: app.ts is imported BY the UI modules, so a static
    // import either way round would close a cycle.
    step('render-logged-out')
    try {
      const [{ showMenuPage, loadLeftInboxes, refreshAccountsList }, { showApp }] = await Promise.all([
        import('./ui/left-pane.ts'),
        import('./ui/shell.ts'),
      ])
      showApp()
      showMenuPage('/account')
      refreshAccountsList()
      await loadLeftInboxes()
    } catch (e) {
      console.error('[logout] render-logged-out failed:', e instanceof Error ? e.message : e)
    }
  }
}
