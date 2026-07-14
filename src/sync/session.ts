import type { AccountSession } from '../types.ts'
import * as jmapEmail from '../jmap/email.ts'
import * as jmapThread from '../jmap/thread.ts'
import * as jmapMailbox from '../jmap/mailbox.ts'
import * as jmapIdentity from '../jmap/identity.ts'
import * as querystate from '../jmap/querystate.ts'
import * as messages from '../store/messages.ts'
import * as threads from '../store/threads.ts'
import * as mailboxes from '../store/mailboxes.ts'
import * as identities from '../store/identities.ts'
import * as persist from '../vault/persist.ts'
import { writeThreadMD, ensureNewFile } from '../vault/render.ts'
import { vaultHandle, setMailboxRoute, accountKey } from '../context.ts'
import { mailboxNameFromId } from '../utils.ts'
import { filterNew } from './dedup.ts'
import { buildEffectiveGroups } from '../processing.ts'
import { decryptAndParse, uploadPeerKey } from '../pgp/crypto.ts'
import { readGroupHeaders, readGroupHeadersFromMime, cacheGroupHeaders, parseAutocryptKey, parseGossipKeys, readChatEditTarget, readChatDeleteTarget, parseEditBody, cacheEdit, isEdit } from '../deltachat/protocol.ts'
import { maybeHandleSecurejoin } from '../deltachat/securejoin.ts'
import { learnAvatar, learnGroupAvatar } from '../deltachat/avatar.ts'
import { learnApAvatar } from '../ap/avatar.ts'
import { isApRelay, identities as ownIdentities, sessionForRelay, identityKeyForEmail } from '../context.ts'
import { isReactionEmail, isReactionDisposition, cacheReaction, isReaction } from '../mail/reactions.ts'

// Chat-Delete (deltachat spec.md "Request deletion"): the sender asks every
// recipient to remove their own copy of a message the sender originally sent.
// Only honor the request if the requester really is that message's original
// sender — otherwise any group member could delete someone else's message by
// forging (their own, legitimately PGP-signed) Chat-Delete carrier.
async function applyIncomingDelete(identityEmail: string, requestedBy: string, targetMessageId: string): Promise<void> {
  const target = messages.forIdentity(identityKeyForEmail(identityEmail))
    .find(m => (m.messageId as string[] | undefined)?.[0] === targetMessageId)
  if (!target) return
  const targetFrom = (target.from as any[] | undefined)?.[0]?.email as string | undefined
  if (!targetFrom || targetFrom.toLowerCase() !== requestedBy.toLowerCase()) {
    console.warn('[chat-delete] ignoring: requester is not the original sender', requestedBy, targetFrom)
    return
  }
  const targetRelay = (target as any)._relay as string | undefined
  const targetSess = targetRelay ? sessionForRelay(identityEmail, targetRelay) : undefined
  const targetAcct = messages.accountOf(target)
  try {
    if (targetSess) await jmapEmail.destroy(targetSess.jmapClient, targetSess.jmapAccountId, [target.id as string])
  } catch (err) { console.warn('[chat-delete] server destroy failed', err) }
  messages.remove(targetAcct, target.id as string)
  await persist.removeMessage(targetAcct, target.id as string)
}

export async function sync(session: AccountSession): Promise<void> {
  const { jmapClient: client, jmapAccountId: accountId, account } = session
  const user = account.email          // this endpoint's address — From, decryption
  const acctKey = accountKey(account) // per-relay storage/querystate/persist key
  const qs = querystate.get(acctKey)

  try {
    // ── Email sync ──────────────────────────────────────────────────────────
    let newIds: string[] = []
    let removedIds: string[] = []
    let emailState = qs.emailState ?? undefined

    if (qs.emailQueryState) {
      try {
        const delta = await jmapEmail.queryChanges(client, accountId, qs.emailQueryState)
        newIds = delta.added
        removedIds = delta.removed
        await querystate.save(acctKey, { emailQueryState: delta.newQueryState })
      } catch (err) {
        // The server returns cannotCalculateChanges when its delta history
        // doesn't reach back to our cursor (e.g. a relay restart raced with
        // a delta.json flush — see go-jmapserver ARC.md). Previously this
        // threw straight out to the outer catch and aborted the ENTIRE
        // sync — every subsequent poll retried the same stale cursor and
        // failed the same way, forever, so new mail silently stopped
        // syncing with no visible error. Fall back to a full query instead,
        // exactly as the server-side doc already promises clients would.
        console.warn('[sync] queryChanges failed, falling back to full query:', err)
        const full = await jmapEmail.query(client, accountId)
        newIds = full.ids
        await querystate.save(acctKey, { emailQueryState: full.queryState })
      }
    } else {
      const full = await jmapEmail.query(client, accountId)
      newIds = full.ids
      await querystate.save(acctKey, { emailQueryState: full.queryState })
    }

    let emailChangedIds: string[] = []
    if (qs.emailState) {
      try {
        const changed = await jmapEmail.changes(client, accountId, qs.emailState)
        emailState = changed.newState
        emailChangedIds = [...(changed.created ?? []), ...(changed.updated ?? [])]
        await querystate.save(acctKey, { emailState: changed.newState })
      } catch (err) {
        // Same cannotCalculateChanges risk as above. This cursor only drives
        // picking up keyword/mailbox updates on already-known messages (see
        // the newIds fetch below, which sets emailState fresh if it was
        // never set) — safe to just drop it and let the next successful
        // Email/get reseed emailState, rather than aborting sync entirely.
        console.warn('[sync] email changes failed, dropping stale state:', err)
        await querystate.save(acctKey, { emailState: undefined })
      }
    }

    // Reconcile against the full server ID list. The delta cursors above are
    // saved BEFORE the messages they name are durably fetched+decrypted+stored
    // (below) — so any failure in that pipeline (one poison decrypt, a network
    // blip, the whole batch's Promise.all rejecting) used to advance the cursor
    // past messages that never made it into the local store, losing them for
    // good: the next delta returns nothing for them, yet they sit unread on the
    // server forever (never synced ⇒ never displayed ⇒ never markSeen-able).
    // An independent full Email/query (ids only — cheap) catches exactly this:
    // anything the server has that our store doesn't gets re-pulled through the
    // same pipeline, so past drops self-heal and no message is lost permanently.
    try {
      const full = await jmapEmail.query(client, accountId)
      const known = new Set(messages.forAccount(acctKey).map(e => e.id as string))
      const pending = new Set(newIds)
      const missing = full.ids.filter(id => !known.has(id) && !pending.has(id))
      if (missing.length) {
        console.warn(`[sync] reconcile: ${missing.length} message(s) on server but missing locally — re-pulling`)
        newIds = [...newIds, ...missing]
      }
    } catch (err) {
      console.warn('[sync] reconcile query failed:', err)
    }

    // Remove deleted emails from store + vault (scoped to this account).
    for (const id of removedIds) {
      messages.remove(acctKey, id)
      await persist.removeMessage(acctKey, id)
    }

    // Fetch new emails with body
    const newEmailIds = new Set<string>()
    if (newIds.length) {
      const { emails, state } = await jmapEmail.get(client, accountId, newIds, true)
      if (!emailState) await querystate.save(acctKey, { emailState: state })
      const fresh = filterNew(emails)
      // Stamp the owning account so the global store can partition by it (JMAP ids
      // collide across accounts on the same server). Which *identity* (DID) this
      // account belongs to is no longer stamped here — messages.forIdentity()
      // derives it dynamically from sessions instead (see store/messages.ts).
      for (const e of fresh) { (e as any)._account = acctKey; (e as any)._relay = account.serverUrl }
      // biset-old relay_view.go:ConvertRelayView 相当。
      // outer inReplyTo が空かつ body が PGP のとき復号して inner In-Reply-To を outer に昇格。
      // DeltaChat の Protected Headers や JMAP server が outer を拾い損ねるケースを store に入る前に補正。
      const handledSJ = new Set<string>()
      // Chat-Delete carrier emails: never stored (protocol noise, like
      // securejoin), and their target gets destroyed once decrypted below.
      const handledDelete = new Set<string>()
      const deleteRequests: { from: string; targetMessageId: string }[] = []
      // ActivityPub messages are plaintext (no PGP), so they skip the decrypt
      // path below. Learn the remote actor's avatar here via the AP relay's
      // /resolve before that early return.
      if (isApRelay(account.serverUrl)) {
        await Promise.all(fresh.map(async e => {
          const fromH = (e.from as any[] | undefined)?.[0]?.email as string | undefined
          if (fromH && fromH !== user) await learnApAvatar(fromH, account.serverUrl)
        }))
      }
      await Promise.all(fresh.map(async e => {
       // Isolate each message's decrypt/enrichment so one failure (a poison
       // body, a network error in key/avatar learning) can't reject the whole
       // Promise.all and skip the storage pass below for the ENTIRE batch —
       // which is how a single bad message used to strand every message that
       // arrived alongside it. On error the message still falls through to the
       // storage pass un-enriched: better stored plain than lost.
       try {
        const outerIrt = (e.inReplyTo as string[] | undefined)?.[0]
        const hasOuterGroup = !!readGroupHeaders(e).id
        const partId = (e.textBody as any[] | undefined)?.[0]?.partId as string | undefined
        const raw = partId ? (e.bodyValues as any)?.[partId]?.value as string ?? '' : ''
        const isPgp = raw.includes('-----BEGIN PGP MESSAGE-----')
        console.log('[promote]', (e.id as string)?.slice(0, 30), 'outerIrt:', outerIrt || 'EMPTY', 'isPgp:', isPgp, 'hasOuterGroup:', hasOuterGroup)
        const from = (e.from as any[] | undefined)?.[0]?.email as string | undefined
        // RFC 9078 reactions (src/mail/reactions.ts) — generic, not DeltaChat-
        // specific. Cleartext case only here; the encrypted case is handled
        // below once decrypted.headers is available.
        if (!isPgp && from && outerIrt && isReactionEmail(e)) {
          cacheReaction(e, { emoji: raw.trim(), from, targetMessageId: outerIrt })
        }
        if (!isPgp) return
        // Decrypt every new PGP message unconditionally. This used to be skipped
        // whenever the outer copy already had In-Reply-To + Chat-Group-ID (biset
        // stamps both as cleartext draft headers on its own group sends for MUA
        // compatibility — see groupDraftHeaders), back when header-promotion was
        // decrypt's only job. It has since grown gossip-key learning, avatar
        // learning, and reaction/edit/delete detection — none of which are
        // knowable without decrypting, and the skip condition was silently
        // disabling all of them from message #2 onward in any biset-authored
        // group thread. (null for symm-encrypted securejoin vc-request-pubkey.)
        const decrypted = await decryptAndParse(raw, user)
        console.log('[promote] decrypted innerIrt:', decrypted?.inReplyTo || 'NONE')
        if (decrypted) {
          if (!outerIrt && decrypted.inReplyTo) {
            ;(e as any).inReplyTo = [decrypted.inReplyTo]
          }
          if (decrypted.headers) {
            if (!hasOuterGroup) cacheGroupHeaders(e, readGroupHeadersFromMime(decrypted.headers))
            const groupId = readGroupHeaders(e).id
            if (groupId) await learnGroupAvatar(groupId, decrypted)
            if (from && decrypted.inReplyTo && isReactionDisposition(decrypted.headers)) {
              cacheReaction(e, { emoji: decrypted.body.trim(), from, targetMessageId: decrypted.inReplyTo })
            }
            // Chat-Edit / Chat-Delete (deltachat spec.md "Request editing" /
            // "Request deletion") — protected headers, only visible here.
            if (from) {
              const editTarget = readChatEditTarget(decrypted.headers)
              if (editTarget) cacheEdit(e, { targetMessageId: editTarget, newText: parseEditBody(decrypted.body), from })
              const deleteTarget = readChatDeleteTarget(decrypted.headers)
              if (deleteTarget) {
                handledDelete.add(e.id as string)
                deleteRequests.push({ from, targetMessageId: deleteTarget })
              }
            }
            // Learn the sender's key from the protected Autocrypt header so we can
            // encrypt replies (chatmail hides Autocrypt inside the encryption).
            const ac = parseAutocryptKey(decrypted.headers)
            if (ac) await uploadPeerKey(ac.addr, ac.key, user, account.serverUrl, account.password)
            // Learn other group members' keys from Autocrypt-Gossip so we can
            // encrypt to members who haven't messaged us directly yet.
            for (const g of parseGossipKeys(decrypted.gossip)) {
              if (g.addr.toLowerCase() !== user.toLowerCase()) {
                await uploadPeerKey(g.addr, g.key, user, account.serverUrl, account.password)
              }
            }
          }
        }
        // DeltaChat SecureJoin handshake (setup-contact v3). Runs after the
        // Autocrypt learning above so the sender's key is available for replies.
        // Learn the sender's DeltaChat profile picture (Chat-User-Avatar), if the
        // decrypted message carries one. No-op otherwise. Never learn an avatar
        // for one of OUR OWN identities: the locally-set avatar is authoritative,
        // and a peer's gossiped copy of it (present in our own sent messages, or
        // in messages from us that landed in another account's inbox) is stale —
        // learning it would clobber a freshly-uploaded avatar on the next sync.
        const fromIsSelf = !!from && ownIdentities().some(id => id.toLowerCase() === from.toLowerCase())
        if (from && decrypted && !fromIsSelf) await learnAvatar(from, decrypted)
        if (from && await maybeHandleSecurejoin(session, from, raw, decrypted)) {
          handledSJ.add(e.id as string)
        }
       } catch (err) {
        console.warn('[sync] per-message enrichment failed, storing plain:', (e.id as string)?.slice(0, 30), err)
       }
      }))
      await Promise.all(fresh.filter(e => !handledSJ.has(e.id as string) && !handledDelete.has(e.id as string)).map(async e => {
        messages.put(e)
        await persist.flushMessage(e)
        newEmailIds.add(e.id as string)
      }))
      // SecureJoin handshake messages are protocol noise — delete from the server
      // (DeltaChat hides them too) so they never surface in the inbox.
      if (handledSJ.size) {
        try { await jmapEmail.destroy(client, accountId, [...handledSJ]) }
        catch (err) { console.log('[securejoin] destroy failed', err) }
      }
      // Chat-Delete carriers are protocol noise too — delete from the server,
      // then apply the deletion each one requested (see applyIncomingDelete).
      if (handledDelete.size) {
        try { await jmapEmail.destroy(client, accountId, [...handledDelete]) }
        catch (err) { console.log('[chat-delete] carrier destroy failed', err) }
      }
      for (const req of deleteRequests) {
        await applyIncomingDelete(user, req.from, req.targetMessageId)
      }
    }

    // ── Thread sync ─────────────────────────────────────────────────────────
    if (qs.threadState) {
      const delta = await jmapThread.changes(client, accountId, qs.threadState)
      await querystate.save(acctKey, { threadState: delta.newState })
      const changedIds = [...delta.created, ...delta.updated]
      if (changedIds.length) {
        const { threads: fetched, state } = await jmapThread.get(client, accountId, changedIds)
        await Promise.all(fetched.map(async t => {
          const thread = { id: t.id as any, emailIds: t.emailIds as any }
          threads.put(thread)
          await persist.flushThread(thread)
        }))
        await querystate.save(acctKey, { threadState: state })
      }
    } else if (newIds.length) {
      const threadIds = [...new Set(
        messages.forAccount(acctKey)
          .map(e => e.threadId as string | undefined)
          .filter((id): id is string => !!id)
      )]
      if (threadIds.length) {
        const { threads: fetched, state } = await jmapThread.get(client, accountId, threadIds)
        await Promise.all(fetched.map(async t => {
          const thread = { id: t.id as any, emailIds: t.emailIds as any }
          threads.put(thread)
          await persist.flushThread(thread)
        }))
        await querystate.save(acctKey, { threadState: state })
      }
    }

    // ── Mailbox sync ────────────────────────────────────────────────────────
    if (qs.mailboxState) {
      const delta = await jmapMailbox.changes(client, accountId, qs.mailboxState)
      await querystate.save(acctKey, { mailboxState: delta.newState })
      const changedIds = [...delta.created, ...delta.updated]
      if (changedIds.length) {
        const { mailboxes: fetched } = await jmapMailbox.get(client, accountId)
        mailboxes.set(fetched)
        await persist.flushMailboxes()
      }
    } else {
      const { mailboxes: fetched, state } = await jmapMailbox.get(client, accountId)
      mailboxes.set(fetched)
      await persist.flushMailboxes()
      await querystate.save(acctKey, { mailboxState: state })
    }
    for (const mb of mailboxes.all()) {
      const name = mailboxNameFromId(mb.id as string)
      if (name) setMailboxRoute(name, session)
    }

    // ── Identity sync ────────────────────────────────────────────────────────
    try {
      const { identities: fetched } = await jmapIdentity.get(client, accountId)
      identities.set(fetched)
      await persist.flushIdentities()
    } catch { /* non-fatal */ }

    // 更新された (new でなく) email の keywords を fetch + store 更新。
    // markSeen 等で $seen が立つと、 これを取り込まないと MD render の isSeen 判定が古い。
    const updatedOnly = emailChangedIds.filter(id => !newEmailIds.has(id))
    if (updatedOnly.length) {
      try {
        const { emails: updated } = await jmapEmail.get(client, accountId, updatedOnly, false)
        for (const e of updated) {
          const cur = messages.get(acctKey, e.id as string)
          if (cur) {
            ;(cur as any).keywords = (e as any).keywords ?? {}
            ;(cur as any).mailboxIds = (e as any).mailboxIds ?? {}
            messages.put(cur)
            await persist.flushMessage(cur)
          }
        }
      } catch (err) { console.log('[sync] fetch updated failed', err) }
    }

    // ── Mark hidden protocol-noise as $seen ──────────────────────────────────
    // Reactions attach to their target message and edits overwrite their
    // target's text — both are deliberately hidden from every openable inbox
    // (see loadInboxSummaries / getInboxEmails). Because they never surface in
    // a conversation, markRead can never mark them $seen, so they sit unread on
    // the server forever and silently inflate every server-side unread count
    // (the account page's "Unread", the Web Push badge) — a count that no
    // amount of reading in the UI could ever bring down. Mark them $seen here,
    // at sync time, the moment we've recognised and filed them. This also
    // heals already-stored ones (scans the whole account, not just this batch's
    // fresh set), so the historical stuck count clears on the next sync.
    // (SecureJoin / Chat-Delete carriers don't need this — they're destroyed
    // outright above.)
    const noiseUnseen = messages.forAccount(acctKey).filter(e => {
      if ((e.keywords as any)?.['$seen']) return false
      const from = (e.from as any[] | undefined)?.[0]?.email as string | undefined
      if (from && (from === user || from === accountId)) return false
      return isReaction(e) || isEdit(e)
    })
    if (noiseUnseen.length) {
      const ids = noiseUnseen.map(e => e.id as string).filter(Boolean)
      try { await jmapEmail.markSeen(client, accountId, ids) }
      catch (err) { console.warn('[sync] mark reaction/edit $seen failed', err) }
      for (const e of noiseUnseen) {
        ;(e as any).keywords = { ...((e as any).keywords ?? {}), $seen: true }
        messages.put(e)
        await persist.flushMessage(e)
      }
    }

    // ── MD render (vault only) ───────────────────────────────────────────────
    // new または changed (keywords 更新等) を含むスレッドを再描画。
    // status:seen 等のローカル markSeen 後、 SSE で sync が再走したときに cui が再生成した
    // orphan ファイル (`_xxx`) も writeThreadMD 内の findExistingMDs 経由で削除される。
    if (vaultHandle && (newEmailIds.size || updatedOnly.length)) {
      const touchedIds = new Set<string>([...newEmailIds, ...updatedOnly])
      const { groups } = await buildEffectiveGroups(messages.forAccount(acctKey), user)
      for (const [effectiveTid, threadEmails] of groups) {
        if (!threadEmails.some(e => touchedIds.has(e.id as string))) continue
        const allMbxIds = new Set<string>()
        for (const e of threadEmails) {
          for (const id of Object.keys((e as any).mailboxIds ?? {})) allMbxIds.add(id)
        }
        const dirs = [...allMbxIds].map(id => mailboxNameFromId(id)).filter(Boolean)
        for (const dirName of dirs) {
          await writeThreadMD(dirName, user, threadEmails, effectiveTid)
          await ensureNewFile(dirName)
        }
      }
    }

  } catch (err) {
    console.error(`[sync] ${user} failed:`, err)
  }
}
