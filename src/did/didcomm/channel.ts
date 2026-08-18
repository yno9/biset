// Integrates DIDComm (relay-less messaging, DID⊥relay) into the SAME left-
// column-inbox / right-column-thread UI and the SAME local JMAP Email store
// every other conversation uses — no separate "/didcomm" page, no separate
// data model. The trick is a SYNTHETIC AccountSession: DIDComm has no JMAP
// account (no server, no Email/query, no EmailSubmission), but every piece of
// UI that lists/renders conversations (loadInboxSummaries, fetchInboxMessages,
// getInboxEmails — see app.ts) works ENTIRELY off store/messages.ts's local
// Email objects grouped by session-derived identity/mailbox-name, never a live
// JMAP fetch. So: register a session-shaped placeholder with no real
// jmapClient, stamp DIDComm-derived Email objects with its account key the
// same way sync/session.ts stamps real JMAP mail, and that machinery renders
// them unmodified. `isDidCommRelay` (context.ts) is the discriminant every
// JMAP-only code path (sync/index.ts's start(), app.ts's PGP/mailbox-lookup
// steps) uses to skip a session it can't actually speak JMAP to.
import type { AccountSession, StoredAccount } from '../../types.ts'
import type { Email } from 'jmap-rfc-types'
import { sessions, addSession, accountKey, relaysForId, DIDCOMM_SERVER_URL } from '../../context.ts'
import { getDidRecord, storeDidRecord } from '../store.ts'
import { ownDid, registerWithMediator, mediatorUrl } from '../didcomm-devices.ts'
import { DELIVER as MLS_DELIVER } from './mls-transport.ts'
import { readDelivery, type Delivery } from '../../mls/transport.ts'
import { receiveSelfGroupDelivery, catchUpSelfGroup, syncToOwnDevices, encodeDeviceSync, selfGroupIdHex, commitPendingProposals, type DeviceSyncPayload } from '../../mls/self-group.ts'
import {
  receiveConversationDelivery, commitPendingProposalsIn, conversationDs, conversations, catchUpConversation,
  conversationInfo, groupAddress, groupIdOfAddress, createConversation, sendToConversation, recoverMissingGroups,
  inviteToConversation, renameConversation,
  // removeFromConversation, leaveConversation: unused while removeFromGroup/
  // leaveGroup below are commented out — see the note there.
  type ReceivedGroupMessage,
} from '../../mls/conversation.ts'
import { catchUpGroup } from '../../mls/delivery.ts'
import { loadGroup, saveGroup } from '../../mls/store.ts'
import { displayNameFor } from '../displayname.ts'
import { resolveDidCommDoc, resolveSenderPublicKey } from './resolve.ts'
import { sendDidComm, DidCommUnreachableError } from './send.ts'
import { pickupDeliver, acknowledgeMessages } from './pickup.ts'
import { fetchMediatorInfo, subscribeMediatorPush, unsubscribeMediatorPush, type MediatorInfo, type WebPushSubscriptionJSON } from './coordinate.ts'
import { isExpired, type DidCommSender, type DidCommPlaintext, type PlaintextOptions } from './message.ts'
import { classifyInbound, protocolResponseFor, describeProblem } from './dispatch.ts'
import { verifyFromPrior } from './rotation.ts'
import { hexToBytes } from '../../utils.ts'
import { avatarDataUrl, saveAvatar } from '../../deltachat/avatar.ts'
import { recentlyMissed, noteMiss, didcommDocumentMissKey } from '../negcache.ts'
import { cachedSenderKey } from './sender-keys.ts'
import { fetchVapidPublicKey } from '../../push/api.ts'
import * as messages from '../../store/messages.ts'
import * as contactsStore from '../../store/contacts.ts'
import { buildCardForDid, rebindContactDid, labelForDid, displayLabelFor, representativeAddressForDid } from '../contacts.ts'
import * as persist from '../../vault/persist.ts'

const MAILBOX_PREFIX = 'mbx-' // go-jmapserver's own encoding — mailboxNameFromId decodes this back to the name with no lookup.

// Body stored for an incoming chat message whose text this build can't read.
// Better a visible "something arrived here" than a message the recipient never
// learns existed (pollDidCommOnce ack's every delivered message, so anything
// dropped there is gone from the mediator too).
const UNREADABLE_PLACEHOLDER = '(message could not be read)'

// Own-gateway-first resolve was a did:dht concern (a BEP44 lookup needs
// SOME gateway to ask, and asking this device's own relays before the public
// Pkarr fallbacks avoided a third-party rate limit — relay.pkarr.org 429s
// were seen live from a single browser's worth of test traffic). did:webvh
// derives its own https:// URL from the DID string itself
// (resolveDidCommDoc → webvh/resolver.ts), so there is no gateway list left
// to choose between — both functions below keep their `selfDid` parameter
// for call-site compatibility (and because negcache below still wants a
// stable key) but no longer use it to pick a gateway.
async function resolveDocOwnFirst(
  did: string, _selfDid?: string | null, opts?: { skipCache?: boolean },
): Promise<Awaited<ReturnType<typeof resolveDidCommDoc>>> {
  // negcache.ts bounds the cost of a DID that never resolves — its TTL is
  // seconds, so a device that registers a moment later is still found (see
  // its own note). `skipCache` bypasses the negative memory as well as the
  // document cache: a caller asking for a genuinely fresh answer must not be
  // handed a remembered "nothing there" either.
  const negKey = didcommDocumentMissKey(did)
  if (!opts?.skipCache && recentlyMissed(negKey)) return null
  const doc = await resolveDidCommDoc(did, [], opts)
  if (!doc) noteMiss(negKey)
  return doc
}

/** The sender's public key, cached across reloads (sender-keys.ts). Every
 * incoming message blocks on this — authcrypt cannot be opened without it —
 * so the cache is what keeps a resolve out of the path between a push
 * notification and the message showing up in the thread. `fresh` skips the
 * cache and replaces its entry, which is pickup.ts's repair for the one case
 * a permanently-cached key would otherwise be a permanent failure. */
function resolveSenderKeyOwnFirst(kid: string, _selfDid?: string | null, opts?: { fresh?: boolean }): Promise<Uint8Array> {
  return cachedSenderKey(kid, () => resolveSenderPublicKey(kid), opts)
}

/** The pseudo-StoredAccount a relay-less identity's DIDComm reachability is
 * represented as. `email` has no @ in it (just the DID) — every renderer that
 * displays "email" already just prints whatever string is there, and nothing
 * parses it as an RFC 5322 address. `serverUrl` is the sentinel isDidCommRelay
 * checks for. */
function didCommAccount(did: string): StoredAccount {
  return { serverUrl: DIDCOMM_SERVER_URL, email: did, password: '', did }
}

/** Ensures a synthetic session for this identity's DIDComm channel exists in
 * `sessions[]` — idempotent, safe to call every boot and right after a
 * "Register with mediator" action. Without this, the identity has no relays
 * (StoredAccount) at all yet for context.ts's relaysFor/identityIds to find,
 * so loadInboxSummaries would never surface its DIDComm conversations. */
export function ensureDidCommSession(did: string): AccountSession {
  const existing = sessions.find(s => s.account.did === did && s.account.serverUrl === DIDCOMM_SERVER_URL)
  if (existing) return existing
  const session: AccountSession = {
    account: didCommAccount(did),
    jmapAccountId: '',
    jmapClient: null as any, // never touched — isDidCommRelay guards every call site that would
    eventSourceUrl: null,    // connectSSE (shell.ts) bails immediately on a null eventUrl
  }
  addSession(session)
  return session
}

/** True if this identity has registered a DIDComm mediator at all — the
 * precondition for ensureDidCommSession being worth calling. */
export async function hasDidCommChannel(did: string): Promise<boolean> {
  const rec = await getDidRecord(did)
  const result = !!(rec?.didCommMediatorUrl && rec.didCommPrivateKey && rec.didCommOwnKid)
  // A false here means DIDComm polling never starts, with no other trace
  // anywhere (main.ts's own note) — pin down WHICH of the three conditions
  // failed rather than leaving that to be re-diagnosed from scratch next
  // time.
  if (!result) {
    console.warn('[didcomm] hasDidCommChannel: false', {
      did, found: !!rec,
      mediatorUrl: !!rec?.didCommMediatorUrl, privateKey: !!rec?.didCommPrivateKey, ownKid: !!rec?.didCommOwnKid,
    })
  }
  return result
}

/** This device's own DIDComm identity + mediator, built fresh from the local
 * record each call (mediator info is a cheap GET, and this only runs on a
 * poll/send cadence, not per-render). Null if this identity has no DIDComm
 * registration yet. */
async function ownSender(did: string): Promise<{ own: DidCommSender; mediator: MediatorInfo } | null> {
  const rec = await getDidRecord(did)
  if (!rec?.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) return null
  const own: DidCommSender = {
    did: rec.did, xKid: `${rec.did}${rec.didCommOwnKid}`, xPriv: hexToBytes(rec.didCommPrivateKey),
    mlkemPriv: rec.mlkemPrivateKey ? hexToBytes(rec.mlkemPrivateKey) : undefined,
  }
  const mediator = await fetchMediatorInfo(rec.didCommMediatorUrl)
  return { own, mediator }
}

/** The mediator's Web Push applicationServerKey, for an identity with no relay
 * to ask for one (DID⊥relay). Empty string when this identity has no mediator
 * or the mediator offers no push — either way, "can't subscribe", which the
 * caller must not confuse with a transport failure it should retry. */
export async function mediatorVapidPublicKey(did: string): Promise<string> {
  const rec = await getDidRecord(did)
  if (!rec?.didCommMediatorUrl) return ''
  return fetchVapidPublicKey(rec.didCommMediatorUrl, '/didcomm/push/vapid-public-key')
}

/** Registers this device's Web Push subscription with its mediator, so a
 * message queued for it wakes a closed browser. Returns false when this
 * identity has no DIDComm registration at all (nothing to register with) —
 * distinct from a throw, which means the mediator refused or was unreachable.
 *
 * The kid registered is this device's own xKid, which is exactly what
 * setupDidCommChannel already put in the mediator's keylist — the mediator
 * checks that and refuses any other. */
export async function registerMediatorPush(did: string, sub: WebPushSubscriptionJSON): Promise<boolean> {
  const sender = await ownSender(did)
  if (!sender) return false
  await subscribeMediatorPush(sender.mediator, sender.own, sender.own.xKid, sub)
  return true
}

export async function unregisterMediatorPush(did: string, endpoint: string): Promise<void> {
  const sender = await ownSender(did)
  if (!sender) return
  await unsubscribeMediatorPush(sender.mediator, sender.own, sender.own.xKid, endpoint)
}

// One conversation per correspondent DID — mirrors a 1:1 JMAP inbox (one
// mailbox = one account's own address; the contact comes from from/to
// matching, not a per-contact mailbox). threadId is a stable per-contact
// value so byThread()/thread-scoped helpers behave, though the 1:1 grouping
// itself (getInboxEmails, app.ts) matches on mailbox+contact, not threadId.
function threadIdFor(selfDid: string, otherDid: string): string {
  return [selfDid, otherDid].sort().join('|')
}

// `mailboxDid` decides which local inbox this Email is filed under (always
// OUR OWN did — see the module header note); `fromDid`/`toDid` decide the
// actual sender/recipient shown, independently. A receive stores it in our
// own mailbox with fromDid = the other party; a send ALSO stores it in our
// own mailbox (it's OUR copy) but with fromDid = us instead — two different
// mailboxDid/fromDid relationships that a single "selfDid doubles as both
// the mailbox owner AND the recipient" parameter couldn't represent at once
// (see the fixed bug this replaced: sendViaDidComm's local copy ended up
// filed under the RECIPIENT's mailbox because of that conflation, making a
// sender's own outgoing messages invisible in their own thread).
export function didCommToEmail(id: string, mailboxDid: string, fromDid: string, toDid: string, content: string, receivedAt: string, fromName?: string, subject = ''): Email {
  return {
    id,
    blobId: id,
    threadId: threadIdFor(fromDid, toDid),
    mailboxIds: { [`${MAILBOX_PREFIX}${mailboxDid}`]: true },
    keywords: {},
    size: content.length,
    receivedAt,
    from: fromName ? [{ email: fromDid, name: fromName }] : [{ email: fromDid }],
    to: [{ email: toDid }],
    subject,
    messageId: [id],
    textBody: [{ partId: '1', type: 'text/plain' }],
    bodyValues: { '1': { value: content, isEncodingProblem: false, isTruncated: false } },
  } as unknown as Email
}

// How far ahead of our own clock a sender's claimed send time is still taken
// at face value. Past this it is not skew, it is a wrong clock, and honouring
// it would pin that peer's messages to the bottom of the thread for as long as
// their clock stays ahead — so it is clamped to now instead.
//
// Deliberately one-sided. A time in the PAST is never clamped: a message
// collected after this device was away for a day genuinely belongs a day back
// in the thread, and putting it there is the entire point of ordering by send
// time. (It also means such a message arrives above the fold rather than at
// the bottom — the same trade every mail client makes, and the unread state
// still surfaces it.)
const FUTURE_SKEW_TOLERANCE_MS = 5 * 60 * 1000

/** When a received message was SENT, as an ISO timestamp.
 *
 * Three sources, in descending order of precision:
 *   `body.sentAt`   — biset's own extension (ISO, millisecond), on every
 *                     basicmessage this codebase sends.
 *   `created_time`  — the DIDComm header every conforming sender sets
 *                     (message_structure.md). Epoch SECONDS, so it cannot
 *                     separate two messages sent in the same second, which is
 *                     exactly what the per-message timestamp above exists to
 *                     avoid — hence second place, not first. It is what makes
 *                     a non-biset peer order correctly all the same.
 *   `fallback`      — local now, for a sender that provides neither.
 */
export function sentTimeOf(msg: { body?: { sentAt?: unknown }; created_time?: number }, fallback: string): string {
  const claimed = typeof msg?.body?.sentAt === 'string'
    ? Date.parse(msg.body.sentAt)
    : typeof msg?.created_time === 'number' ? msg.created_time * 1000 : NaN
  if (!Number.isFinite(claimed)) return fallback
  return claimed > Date.now() + FUTURE_SKEW_TOLERANCE_MS ? fallback : new Date(claimed).toISOString()
}

/** Sends the automatic protocol reply a received message owes (a ping-response
 * for a trust-ping, a disclose for a discover-features query), addressed back
 * to its sender. Fire-and-forget: a failed reply is logged, never fatal to the
 * poll cycle — the original message is still ack'd and the channel keeps
 * running. Resolves the sender's own DID document (own-gateways first, like
 * every other resolve here) to reach them. */
function maybeAutoReply(own: DidCommSender, selfDid: string, msg: DidCommPlaintext, fromDid: string): void {
  const reply = protocolResponseFor(msg, fromDid)
  if (!reply) return
  resolveDocOwnFirst(reply.toDid, selfDid).then(doc => {
    if (!doc) return
    return sendDidComm(own, reply.toDid, doc, reply.options)
  }).catch(e => console.warn('[didcomm] auto-reply failed:', e instanceof Error ? e.message : e))
}

/** One pickup cycle: drain this device's mediator queue, convert each
 * message into the same Email shape sync/session.ts stores real mail as, and
 * persist it (pickup is destructive at the mediator — the local store is the
 * ONLY copy from this point on, unlike JMAP where a reload just re-fetches).
 * Returns true if anything new arrived (caller re-renders only then). */
export async function pollDidCommOnce(did: string, onNameResolved?: () => void): Promise<boolean> {
  const sender = await ownSender(did)
  if (!sender) return false
  const acctKey = accountKey(didCommAccount(did))
  // Before the queue, because what this asks for is precisely what the queue
  // may not contain: the Delivery Service fans out to the roster a committer
  // declared and cannot verify (mls/self-group.ts's catchUpSelfGroup), so an
  // empty queue is not evidence that nothing was sent.
  let gotOne = await catchUpGroupsIfDue(did, sender, acctKey)
  let delivered: Awaited<ReturnType<typeof pickupDeliver>>
  try {
    // Authenticating an incoming message resolves the SENDER's DID document
    // (for their public key) — same file://-needs-CORS-gateways reasoning as
    // everywhere else here. Using only the public-fallback default silently
    // failed this resolve for every single incoming message, which
    // unpackAuthcrypt treats as a hard failure (can't authenticate = can't
    // decrypt), so nothing was ever delivered.
    // The same own-gateway-first resolver serves both jobs: authenticating the
    // authcrypt sender (X25519 keyAgreement key) AND, when a peer sign-then-
    // encrypts, verifying the inner JWS signer (Ed25519 authentication key) —
    // both are just "look up this kid's public key in its DID doc".
    const resolveKey = (kid: string) => resolveSenderKeyOwnFirst(kid, did)
    delivered = await pickupDeliver(sender.mediator, sender.own, resolveKey, 10, resolveKey)
  } catch (e) {
    console.warn('[didcomm] pickup failed:', e instanceof Error ? e.message : e)
    return gotOne
  }
  if (!delivered.length) return gotOne

  // Messages that must NOT be acknowledged this cycle — see the MLS branch.
  const withheld = new Set<string>()
  for (const d of delivered) {
    // Per message, not per pickup. One timestamp for the whole batch gave every
    // message in it an identical receivedAt, which left their display order
    // arbitrary — and, until the render cache stopped identifying messages by
    // sender+timestamp (state.ts's messageKey), silently merged them into a
    // single bubble: a friend sending two messages while this device was away
    // arrived as one.
    const now = new Date().toISOString()
    const body = d.plaintext as { type?: string; body?: { content?: unknown; subject?: unknown; syncTo?: unknown; sentAt?: unknown; fromName?: unknown; avatar?: unknown }; id?: string; expires_time?: number; created_time?: number }
    // A message whose sender-declared deadline has already passed is stale —
    // drop it rather than render it (problems.md "Timeouts"). It is still ack'd
    // below so the mediator stops redelivering it.
    if (isExpired(body)) continue
    const fromDid = d.senderKid.split('#')[0]!
    // DID Rotation (signature.md): a peer that rotated its DID carries a signed
    // from_prior. biset's OWN identities were rotation-less until did:webvh's
    // domain move gave them a real EMIT path (webvh/publish.ts's
    // moveDidToNewDomain, PLANWEBVH.md §5.1) — a conforming receiver VERIFIES
    // the claim (rejecting a forged one) and, on success, rebinds any locally-
    // known contact Card to the new DID (PLANWEBVH.md §5.2) so future sends/
    // lookups follow the move instead of a stale identifier. Best-effort: a
    // bad/absent signature just means no rotation is recorded, and a contact
    // this device never resolved before has no Card to rebind either.
    const fromPrior = (d.plaintext as DidCommPlaintext).from_prior
    if (typeof fromPrior === 'string') {
      verifyFromPrior(fromPrior, kid => resolveSenderKeyOwnFirst(kid, did), (d.plaintext as DidCommPlaintext).from)
        .then(async rot => {
          console.info(`[didcomm] verified DID rotation ${rot.priorDid} → ${rot.newDid ?? '(ended)'}`)
          if (rot.newDid && rebindContactDid(rot.priorDid, rot.newDid)) await persist.flushContacts()
        })
        .catch(e => console.warn('[didcomm] from_prior verification failed (ignoring rotation claim):', e instanceof Error ? e.message : e))
    }
    // A delivery from this identity's own self group: another of our devices
    // telling us what it just sent (mls/self-group.ts's syncToOwnDevices), or
    // a commit/proposal changing which devices this identity has. All of them
    // advance the group's own state; only a device-sync payload produces
    // something to file, and it is filed exactly like the copy the sending
    // device kept for itself.
    if (body.type === MLS_DELIVER) {
      const delivery = readDelivery(body.body)
      // Two kinds of group arrive through the same door, and which one this is
      // decides everything about what the payload MEANS: the self group's
      // application messages are copies of this user's own sends, a
      // conversation's are other people talking. The group id says which, and
      // nothing else has to.
      if (delivery.groupId !== selfGroupIdHex(did)) {
        if (await handleConversationDelivery(did, acctKey, sender, delivery, fromDid, d.ackId, withheld)) gotOne = true
        continue
      }
      const applied: Awaited<ReturnType<typeof receiveSelfGroupDelivery>> = await receiveSelfGroupDelivery(did, delivery)
        .catch(e => { console.warn('[didcomm] self-group delivery failed:', e instanceof Error ? e.message : e); return { retry: true } })
      // Held back from the acknowledgement below, so the mediator keeps it and
      // the next poll tries again. Acknowledging a commit this device could
      // not apply would leave it permanently a step behind the group, with
      // nothing left to fetch.
      if (applied?.retry) withheld.add(d.ackId)
      // A sibling declared its own departure. MLS cannot let it remove itself,
      // so this device commits the proposal on its behalf — promptly, because
      // until someone does, the leaving device is still a member and still
      // published (mls/self-group.ts's leaveSelfGroup).
      if (applied?.sawProposal) await commitPendingSelfGroup(did)
      if (applied?.sync) {
        await fileDeviceSync(did, acctKey, applied.sync)
        gotOne = true
      }
      continue
    }
    // Only basicmessage is chat and belongs in the inbox. Everything else is a
    // protocol message: hand it to the inbound dispatcher, which auto-replies
    // to a trust-ping / discover-features query and logs a problem-report, then
    // move on (never render it as a chat bubble).
    if (classifyInbound(body) !== 'chat') {
      if (classifyInbound(body) === 'problem-report') console.warn(`[didcomm] problem-report from ${fromDid}: ${describeProblem(d.plaintext as DidCommPlaintext)}`)
      else maybeAutoReply(sender.own, did, d.plaintext as DidCommPlaintext, fromDid)
      continue
    }
    // A chat message this build can't read the text of is still a message that
    // arrived. It used to be dropped here and ack'd below anyway, which told
    // the mediator to forget it too — the one place a real message could
    // disappear for good, leaving the recipient with no sign anything had ever
    // been sent. Store it with a visible placeholder instead: the conversation
    // shows that something came through, and nothing is silently destroyed.
    const rawContent = typeof body?.body?.content === 'string' ? body.body.content : ''
    if (!rawContent) {
      console.warn('[didcomm] chat message with no readable text content', { id: body?.id, from: fromDid })
    }
    const content = rawContent || UNREADABLE_PLACEHOLDER
    const subject = typeof body?.body?.subject === 'string' ? body.body.subject : ''
    // Sender's own profile picture, riding along on the message body — same
    // "no separate channel, no server-side hosting, just ship it with what's
    // already an encrypted P2P send" shape as DeltaChat's Chat-User-Avatar
    // header (deltachat/protocol.ts's buildProtectedHeaders): every outgoing
    // basicmessage carries it unconditionally, no dedup/gating, since a
    // downscaled (192px) avatar is small enough that the per-message cost is
    // negligible. Absent means "this message carries no avatar info", never
    // "clear it" — matching that same header's semantics.
    const avatar = typeof body?.body?.avatar === 'string' && body.body.avatar.startsWith('data:') ? body.body.avatar : undefined
    const id = typeof body?.id === 'string' ? body.id : crypto.randomUUID()
    // syncToSiblingDevices' own marker: a message from MYSELF (another one of
    // this identity's devices) carrying the real recipient it was actually
    // sent to. Filed exactly like sendViaDidComm's own local echo on the
    // sending device — same mailbox, same fromDid, same $seen — so a second
    // open browser ends up with the identical row the sender got, instead of
    // a bogus self-to-self conversation under fromDid=did/toDid=did.
    const syncTo = typeof body?.body?.syncTo === 'string' ? body.body.syncTo : undefined
    const syncFromName = typeof body?.body?.fromName === 'string' ? body.body.fromName : undefined
    const isOwnSync = fromDid === did && !!syncTo
    // WHEN IT WAS SENT, not when this device happened to collect it. Both
    // branches now agree on that, which they did not before: a sibling-sync
    // copy already carried the sender's own `sentAt`, while an ordinary
    // incoming message was stamped with the local pickup time. Since the
    // thread (processing.ts) and the inbox list (app.ts) are ordered by this
    // one field and nothing else, that made the position of someone else's
    // message a function of MY polling — a hidden tab on the 60s backstop, a
    // spell offline, a redelivery after a failed ack, each pushed it further
    // down the thread than it belonged, and always relative to my own
    // messages, which have carried a true send time all along. Worse, two
    // devices of one identity collect at different moments, so they showed
    // the SAME conversation in two different orders, and a redelivery
    // re-stamped a message to the bottom of the thread each time.
    const receivedAt = sentTimeOf(body, now)
    const email = isOwnSync
      ? didCommToEmail(id, did, did, syncTo!, content, receivedAt, syncFromName, subject)
      : didCommToEmail(id, did, fromDid, did, content, receivedAt, undefined, subject)
    if (isOwnSync) (email.keywords as any)['$seen'] = true // matches sendViaDidComm's own-outgoing-never-unread marking
    ;(email as any)._account = acctKey
    ;(email as any)._relay = DIDCOMM_SERVER_URL
    messages.put(email)
    await persist.flushMessage(email)
    gotOne = true
    // Learned regardless of isOwnSync: a sibling-sync copy's `fromDid` IS our
    // own identity's DID (isOwnSync's whole premise), and this DEVICE's local
    // avatar cache is independent storage from whichever sibling device the
    // picture was actually set on (pickAndSetIdentityAvatar only writes
    // locally + rides the next outgoing message — see channel.ts's own note
    // on syncBody/msgBody sharing one shape). Skipping this for isOwnSync
    // used to mean "set avatar on device A, it never appears on device B"
    // even though the bytes were already arriving in every sync copy —
    // found live (2026-08-11): a second logged-in device kept showing
    // initials no matter how many messages were sent from device A.
    if (avatar) await saveAvatar(fromDid, avatar)
    if (isOwnSync) continue // no contact-name resolve to do for a message from ourselves
    // Best-effort display name (the contact's self-asserted doc.name) —
    // resolved after storing, patched in on arrival if found, so the very
    // first message doesn't wait on a resolve to appear. Patches BOTH the
    // one stored Email (from.name — the thread bubble reads this directly)
    // AND syncs a Card into the shared contacts store (buildCardForDid, same
    // as discovery.ts's email-based contact resolution does), since
    // displayLabelFor — the left-pane inbox list and the thread header's
    // conv-to both use it — only ever reads a name from THAT store. A DID
    // reached with no email involved at all (pure DIDComm, no discovery.ts
    // flow ever runs) had its document's name go nowhere but this one email.
    resolveDocOwnFirst(fromDid, did).then(doc => {
      const name = doc?.name
      if (!name) return
      const cur = messages.get(acctKey, id)
      if (cur) {
        ;(cur.from as any[])[0].name = name
        messages.put(cur)
        persist.flushMessage(cur).catch(() => {})
      }
      contactsStore.put(buildCardForDid(fromDid, [{ did: fromDid, address: fromDid, relays: [], name }]))
      persist.flushContacts().catch(() => {})
      // This resolve lands well after the poll cycle that delivered the
      // message already returned (and, in practice, after its own re-render
      // already ran) — nothing else re-renders once it lands, which is why
      // the name only ever showed up after a full reload. Fire the same
      // refresh callback again now that it's actually known.
      onNameResolved?.()
    }).catch(() => {})
  }
  // Pickup 3.0 messages-received: confirm every delivered message (rendered,
  // synced, or dropped-as-stale alike) so the mediator removes it from the
  // queue. Without this, delivery being non-destructive means the same batch
  // returns on the very next poll — an endless redelivery loop. Best-effort: a
  // failed ack just means the batch is re-fetched next cycle (messages.put is
  // keyed by id, so a redelivery is deduped on storage, not doubled).
  try {
    const toAck = delivered.map(d => d.ackId).filter(id => !withheld.has(id))
    if (toAck.length) await acknowledgeMessages(sender.mediator, sender.own, toAck)
  } catch (e) {
    console.warn('[didcomm] messages-received ack failed (will redeliver next poll):', e instanceof Error ? e.message : e)
  }
  // A withheld ack means a delivery arrived that this device could not apply,
  // which in a strictly ordered group almost always means an EARLIER one never
  // arrived. Ask for it now rather than at the next heartbeat: until the gap
  // is filled nothing else in the group can be applied either.
  if (withheld.size && await catchUpGroupsIfDue(did, sender, acctKey, true)) gotOne = true
  return gotOne
}

interface PollEntry { tick: () => Promise<void>; timer: ReturnType<typeof setInterval> }
const _polls = new Map<string, PollEntry>()

// Pickup 3.0 is request/response: there is no server-initiated delivery over
// plain HTTP, so without another signal this interval IS the floor on receive
// latency, and 4s is what that costs — every open client hitting the mediator
// fifteen times a minute forever, most of them to be told "nothing".
//
// There is another signal now. The mediator sends a Web Push the moment it
// queues something (anchor/mediator/server.ts's notifyPush), and the Service
// Worker relays that to any open page (push/client.ts), which pokes the tick
// below immediately. That makes the timer a BACKSTOP rather than the mechanism
// — it only has to catch a push that was dropped, throttled or never permitted
// — so it drops to once a minute whenever push is armed and nobody is looking
// (the visibility qualifier is new; see the note on POLL_INTERVAL_MS below).
//
// Not SSE: Pickup 3.0's own live-delivery mode is defined over a duplex
// transport (the client sends live-delivery-change and receives on the same
// socket), and an SSE side channel would need a second authentication scheme
// on the one component that must not get authentication wrong — every other
// request here is authenticated by the authcrypt envelope in its POST body,
// which a GET has nowhere to put. It would also die the moment an iOS PWA is
// backgrounded, which is the case Web Push already covers.
//
// The backstop cadence is for a HIDDEN page. A visible one keeps the 4s tick
// even with push armed, because push is now deliberately not sent for
// everything: a device-sync copy of the user's own sent message is queued
// without a Web Push (server.ts's FORWARD case — the web has no silent push, so
// "don't notify" has to mean "don't push"). On screen, that message has to
// appear promptly, and the only thing that can fetch it is this timer. Hidden,
// it can wait: nobody is looking, and the moment they do look the
// visibilitychange handler below both ticks immediately and restores the fast
// cadence. Sync state converges when someone is there to see it; only messages
// worth interrupting a person for get a push.
const POLL_INTERVAL_MS = 4_000
const POLL_INTERVAL_PUSH_ARMED_MS = 60_000

let pushArmed = false
function isHidden(): boolean { return typeof document !== 'undefined' && document.visibilityState === 'hidden' }
function pollIntervalMs(): number { return pushArmed && isHidden() ? POLL_INTERVAL_PUSH_ARMED_MS : POLL_INTERVAL_MS }

/** Re-arms every live poll timer at the current interval. */
function reschedulePolls(): void {
  for (const [did, entry] of _polls) {
    clearInterval(entry.timer)
    _polls.set(did, { tick: entry.tick, timer: setInterval(entry.tick, pollIntervalMs()) })
  }
}

if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    reschedulePolls()
    // Catch up on anything that arrived unannounced while nobody was looking —
    // the sibling-sync copies above are exactly that. shell.ts's own
    // visibilitychange handler does the JMAP half of this.
    if (document.visibilityState === 'visible') pokeDidCommPoll()
  })
}

/** Tells the poll loop whether Web Push is actually delivering for this
 * identity's mediator — set by push/client.ts when the subscription is
 * registered (or torn down). False keeps the old 4s cadence, because then the
 * timer really is the only way anything arrives: a user who never granted
 * notification permission must not end up on a one-minute delay. */
export function setDidCommPushArmed(armed: boolean): void {
  if (armed === pushArmed) return
  pushArmed = armed
  reschedulePolls()
}

/** Runs every active identity's pickup right now, without waiting for the next
 * tick. Called when the Service Worker relays a push saying the mediator has
 * something queued — this is what turns a 60s backstop into sub-second
 * delivery while the app is open. */
export function pokeDidCommPoll(): void {
  for (const entry of _polls.values()) void entry.tick()
}

/** Starts polling this identity's DIDComm channel, calling `onNew` whenever a
 * cycle delivers something. Idempotent (replaces any existing timer for this
 * DID). Returns a stop function; startPolling() (shell.ts) calls it on every
 * restart the same way it tears down JMAP's SSE sources. */
export function startDidCommPolling(did: string, onNew: () => void): () => void {
  stopDidCommPolling(did)
  const tick = serialize(async () => {
    if (await pollDidCommOnce(did, onNew)) onNew()
    // No outbox flush here any more: a device-sync copy is submitted to the
    // Delivery Service, which owns the fan-out, and each device's mediator
    // queue holds it until collected — nothing is owed by this device once a
    // send returns.
  })
  tick() // don't wait a full interval for the first check
  _polls.set(did, { tick, timer: setInterval(tick, pollIntervalMs()) })
  return () => stopDidCommPolling(did)
}

/** Runs `fn` one at a time. A call that arrives while a cycle is in flight
 * does not start a second one — it joins the running cycle and asks for
 * exactly ONE more afterwards, however many times it was asked.
 *
 * Three independent things fire this tick — the interval timer, the Service
 * Worker's push relay (pokeDidCommPoll) and the visibilitychange handler —
 * and none of them used to check whether one was already running. That is
 * harmless while a cycle is fast and actively harmful the moment it isn't: a
 * pickup blocked on a cold gateway lookup (seconds, measured) collects two or
 * three more timer ticks on top of itself, and because Pickup 3.0's delivery
 * is non-destructive until acknowledged, every one of them fetches the SAME
 * batch, resolves the SAME sender keys through the SAME slow gateways, and
 * stores and acks the same messages again. Load on the gateways multiplies
 * exactly when the gateways are what's slow — a rate-limit spiral that makes
 * its own cause worse, and the likeliest explanation for a wait blowing out
 * from seconds to far longer. */
export function serialize(fn: () => Promise<void>): () => Promise<void> {
  let running: Promise<void> | null = null
  let again = false
  const run = (): Promise<void> => {
    if (running) { again = true; return running }
    running = (async () => {
      try { await fn() } finally { running = null }
      if (again) { again = false; await run() }
    })()
    return running
  }
  return run
}

function stopDidCommPolling(did: string): void {
  const entry = _polls.get(did)
  if (!entry) return
  clearInterval(entry.timer)
  _polls.delete(did)
}

export function stopAllDidCommPolling(): void {
  for (const entry of _polls.values()) clearInterval(entry.timer)
  _polls.clear()
}

export interface DidCommSendResult {
  ok: boolean
  fromEmail?: string
  error?: string
  /** Set only when the message reached SOME of the recipient's devices but not
   * all of them. The send succeeded (ok stays true) — this is for telling the
   * sender that one of the other end's devices will not see it, which used to
   * be a console warning and nothing else. */
  partial?: { delivered: number; total: number }
}

/** Sends a chat message to `toDid` and stores the SAME optimistic local copy a
 * JMAP send's EmailSubmission produces — there is no server-side "sent" copy
 * to ever sync back for DIDComm, so this local write is the only record.
 *
 * Also fans a copy out to this identity's OWN other registered devices (see
 * syncToSiblingDevices below) — without it, y@biset.md open in two browsers
 * had NO way for one to ever learn what the other sent: an incoming message
 * already reaches every device (send.ts fans out to every kid in the
 * recipient's resolved doc, proven by mediator-multidevice.test.ts), but a
 * device's own OUTGOING send only ever touched its own local store, so the
 * other browser's thread simply never gained the reply at all — not stale,
 * not delayed, just absent. */
/** did:webvh domain-move rotation (PLANWEBVH.md §5.1): attaches this
 * identity's from_prior JWT — built once at move time by
 * webvh/move.ts's moveWebvhIdentity, stored on the NEW DID's record — to
 * outgoing messages until the window expires, so a peer that hasn't
 * re-resolved this DID yet still learns of the move from the message
 * itself rather than only by noticing the old DID went stale. No-op (empty
 * headers) for an identity that never moved, or whose window has lapsed —
 * covers both did:dht (never sets these fields, rotation-less by design)
 * and a did:webvh identity outside its move window. */
/** What to tell the person who just pressed send when the recipient's own
 * published document says they can't receive DIDComm at all (send.ts's
 * DidCommUnreachableError). The wire-level wording ("recipient DID doc has no
 * keyAgreement") describes a data shape nobody outside this codebase can act
 * on; what the sender needs is who it was, that it isn't their own fault or a
 * retryable glitch, and — when biset already knows one — the address that
 * still works. */
function unreachableMessage(toDid: string): string {
  const who = displayLabelFor(toDid) || labelForDid(toDid)
  const fallback = representativeAddressForDid(toDid)
  return fallback
    ? `${who} has no device registered for DIDComm right now — try their address ${fallback} instead`
    : `${who} has no device registered for DIDComm right now — they need to reopen biset and register a device before they can be reached this way`
}

async function fromPriorHeaders(selfDid: string): Promise<PlaintextOptions> {
  const rec = await getDidRecord(selfDid)
  if (rec?.movedFromJwt && rec.movedFromExpiresAt && Date.now() < rec.movedFromExpiresAt) {
    return { fromPrior: rec.movedFromJwt }
  }
  return {}
}

export async function sendViaDidComm(selfDid: string, toDid: string, body: string, subject = ''): Promise<DidCommSendResult> {
  // Both of these do NETWORK work — ownSender fetches the mediator's document,
  // resolveDocOwnFirst hits every gateway — and both used to sit outside any
  // try. A mediator or gateway that was merely unreachable therefore rejected
  // straight out through jmapCreateEmail into sendReply's bare `await`, and
  // with no global unhandledrejection handler anywhere the send neither
  // completed nor reported: the optimistic bubble just stayed dimmed forever.
  // Every failure in this function now leaves through the same DidCommSendResult
  // the caller already knows how to show.
  let sender: Awaited<ReturnType<typeof ownSender>>
  let toDoc: Awaited<ReturnType<typeof resolveDocOwnFirst>>
  try {
    sender = await ownSender(selfDid)
    if (!sender) return { ok: false, error: 'this identity has no DIDComm mediator registered' }
    toDoc = await resolveDocOwnFirst(toDid, selfDid)
  } catch (e) {
    return { ok: false, error: `could not reach the DIDComm network: ${e instanceof Error ? e.message : String(e)}` }
  }
  if (!toDoc) return { ok: false, error: `could not resolve recipient ${labelForDid(toDid)}` }
  const id = crypto.randomUUID()
  // Stamped BEFORE the send, and carried on the wire for every recipient —
  // not just for our own other devices, which is all `sentAt` used to travel
  // with. It is the only thing that lets the person on the other end place
  // this message where it belongs: their thread is ordered by one timestamp
  // (processing.ts), and without a send time on the message their only option
  // was the moment their own device happened to collect it, which reorders the
  // conversation by their polling luck. `created_time` (message.ts) carries
  // the same fact for a non-biset peer but only to the second, so this stays
  // the precise source — see sentTimeOf.
  //
  // Before the send rather than after, so a slow fan-out doesn't get counted
  // as part of when the user wrote it.
  const sentAt = new Date().toISOString()
  // `subject` is a biset extension to basicmessage/2.0 (not part of the
  // DIDComm spec) — omitted entirely when empty so the wire payload matches
  // a plain reference-implementation basicmessage for the common case.
  const msgBody: { content: string; id: string; sentAt: string; subject?: string; avatar?: string } = { content: body, id, sentAt }
  if (subject) msgBody.subject = subject
  // Same avatar as every other protocol this identity might also be
  // reachable on (deltachat/avatar.ts's shared cache, saved DID-keyed by
  // left-pane.ts's pickAndSetIdentityAvatar) — attached unconditionally,
  // exactly like DeltaChat's Chat-User-Avatar header, so a DIDComm-only
  // (DID⊥relay) identity has a way to share a picture too, with no DID
  // Document / anchor changes needed.
  const ownAvatar = avatarDataUrl(selfDid)
  if (ownAvatar) msgBody.avatar = ownAvatar
  let fanout: Awaited<ReturnType<typeof sendDidComm>>
  try {
    const headers = await fromPriorHeaders(selfDid)
    fanout = await sendDidComm(sender.own, toDid, toDoc, { type: 'https://didcomm.org/basicmessage/2.0/message', body: msgBody, headers })
  } catch (e) {
    if (e instanceof DidCommUnreachableError) return { ok: false, error: unreachableMessage(toDid) }
    return { ok: false, error: e instanceof Error ? e.message : String(e) }
  }
  // Own display name (the same JMAP Identity.name buildOwnDocument publishes
  // into this identity's DID doc — see publish.ts's displayNameFor) — without
  // it, msg.from_name was left unset for every message we send, so our own
  // bubble/left-pane row showed the raw DID with no way to ever resolve it
  // (unlike a remote contact's name, which self-resolves off THEIR doc).
  const fromName = displayNameFor(relaysForId(selfDid).filter(s => s.account.serverUrl !== DIDCOMM_SERVER_URL))
  syncToOwnDevicesBestEffort(selfDid, toDid, msgBody, fromName)
  const acctKey = accountKey(didCommAccount(selfDid))
  const email = didCommToEmail(id, selfDid, selfDid, toDid, body, sentAt, fromName, subject)
  ;(email.keywords as any)['$seen'] = true // own outgoing mail is never "unread"
  ;(email as any)._account = acctKey
  ;(email as any)._relay = DIDCOMM_SERVER_URL
  messages.put(email)
  await persist.flushMessage(email)
  return fanout.delivered < fanout.total
    ? { ok: true, fromEmail: selfDid, partial: { delivered: fanout.delivered, total: fanout.total } }
    : { ok: true, fromEmail: selfDid }
}

/** File a device-sync copy — a message one of this identity's OTHER devices
 * sent — into the local store, exactly as the sending device filed it.
 *
 * One function because a copy arrives two ways: pushed by the Delivery Service
 * (the ordinary case), and pulled by this device when it notices it is missing
 * deliveries. The two must produce the identical row; two copies of this
 * filing logic would be two ways for them to drift. */
async function fileDeviceSync(did: string, acctKey: string, synced: DeviceSyncPayload): Promise<void> {
  const at = synced.sentAt || new Date().toISOString()
  const copy = didCommToEmail(synced.id, did, did, synced.syncTo, synced.content, at, synced.fromName, synced.subject ?? '')
  ;(copy.keywords as any)['$seen'] = true // our own outgoing message is never unread
  ;(copy as any)._account = acctKey
  ;(copy as any)._relay = DIDCOMM_SERVER_URL
  messages.put(copy)
  await persist.flushMessage(copy)
  if (synced.avatar) await saveAvatar(did, synced.avatar).catch(() => {})
}

/** Create a group conversation and invite people into it.
 *
 * Returns who could not be reached: an identity with no key packages left
 * published (or none at all — someone who has never run a build with MLS in
 * it) cannot be invited right now, and the group is more useful with the
 * people who could be than not created at all. They can be added later by the
 * same path. */
export async function createGroupConversation(
  selfDid: string, name: string, memberDids: string[],
): Promise<{ ok: true; groupId: string; skipped: string[] } | { ok: false; error: string }> {
  try {
    const sender = await ownSender(selfDid)
    if (!sender) return { ok: false, error: 'this identity has no DIDComm mediator registered' }
    const created = await createConversation(sender.mediator, sender.own, name, memberDids)
    return { ok: true, groupId: groupAddress(created.id), skipped: created.skipped }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) }
  }
}

/** Send to a group conversation.
 *
 * One submission, whatever the group's size: the Delivery Service fans it out
 * (PLANMLS.md §3.3 — the O(n) is the DS's, not the sender's), and each
 * member's own mediator queue holds their copy until they collect it. That
 * includes this identity's OTHER devices, which are ordinary members of the
 * group, so a group message needs none of the device-sync machinery a 1:1 send
 * does. */
export async function sendToGroup(selfDid: string, address: string, body: string, subject = ''): Promise<DidCommSendResult> {
  const id = groupIdOfAddress(address)
  if (!id) return { ok: false, error: `${address} is not a group conversation` }
  let sender: Awaited<ReturnType<typeof ownSender>>
  let ds: MediatorInfo | undefined
  try {
    sender = await ownSender(selfDid)
    if (!sender) return { ok: false, error: 'this identity has no DIDComm mediator registered' }
    ds = await conversationDs(id)
  } catch (e) {
    return { ok: false, error: `could not reach the DIDComm network: ${e instanceof Error ? e.message : String(e)}` }
  }
  // A group whose delivery service is unknown can be read and not spoken to.
  // That is a real state (joined from a Welcome whose sender could not be
  // resolved), and saying so beats a send that silently goes nowhere.
  if (!ds) return { ok: false, error: 'this conversation has no reachable delivery service' }
  const messageId = crypto.randomUUID()
  const sentAt = new Date().toISOString()
  const fromName = displayNameFor(relaysForId(selfDid).filter(s => s.account.serverUrl !== DIDCOMM_SERVER_URL))
  const avatar = avatarDataUrl(selfDid)
  try {
    await sendToConversation(ds, sender.own, id, {
      t: 'msg', id: messageId, content: body, sentAt,
      ...(subject ? { subject } : {}), ...(fromName ? { fromName } : {}), ...(avatar ? { avatar } : {}),
    })
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) }
  }
  // The sender's own copy. The DS deliberately does not send a message back to
  // the device that submitted it, so this is the only copy this device will
  // ever have — same as a 1:1 send.
  await fileGroupMessage(selfDid, accountKey(didCommAccount(selfDid)), {
    groupId: id,
    from: { did: selfDid, kid: sender.own.xKid },
    payload: { t: 'msg', id: messageId, content: body, sentAt, ...(subject ? { subject } : {}), ...(fromName ? { fromName } : {}) },
  })
  return { ok: true, fromEmail: selfDid }
}

/** Who is in a group conversation right now, from its ratchet tree — the only
 * authority on membership. Empty when this device is not in it. */
export async function groupMembersOf(address: string): Promise<string[]> {
  const id = groupIdOfAddress(address)
  return id ? (await conversationInfo(id))?.members ?? [] : []
}

/** Everything one can do to a group's membership, from the UI's point of view.
 * Each is one commit, ordered by the group's Delivery Service like any other.
 *
 * All four report their failure rather than throwing: the caller is a click
 * handler, and "the group moved on while you were deciding" is a normal
 * outcome that deserves a sentence, not a stack trace. */
export async function inviteToGroup(selfDid: string, address: string, did: string): Promise<{ ok: boolean; error?: string }> {
  return groupAction(selfDid, address, async (ds, own, id) => {
    const added = await inviteToConversation(ds, own, id, did)
    if (!added) throw new Error(`${labelForDid(did)} has no key packages published, so they cannot be added yet`)
  })
}

// removeFromGroup / leaveGroup: pulled from the UI (2026-08-16). MLS itself
// has no notion of roles — createProposal/removeMembers only check that the
// target is a current member, not that the caller has any special standing.
// So with the chip wired up, ANY member could remove ANY other member,
// including one who joined seconds ago removing the group's creator. That
// was never a deliberate access-control decision, just the shape you get by
// wiring the UI straight to the MLS primitive. Until there is an actual
// permission model (e.g. creator-only, or a voted removal), membership
// changes are add-only from the UI; the underlying conversation.ts functions
// (removeFromConversation, leaveConversation) and groupAction plumbing below
// are left in place for when that design lands.
//
// export async function removeFromGroup(selfDid: string, address: string, did: string): Promise<{ ok: boolean; error?: string }> {
//   return groupAction(selfDid, address, (ds, own, id) => removeFromConversation(ds, own, id, did))
// }

export async function renameGroup(selfDid: string, address: string, name: string): Promise<{ ok: boolean; error?: string }> {
  return groupAction(selfDid, address, (ds, own, id) => renameConversation(ds, own, id, name))
}

/** Leave. The declaration is what this device can do on its own — MLS forbids
 * committing one's own removal — and another member carries it out. The local
 * state goes either way: staying able to read a conversation one has left
 * would make the word mean nothing.
 *
 * Commented out alongside removeFromGroup (see note above) — leaving is the
 * same "any member can end anyone's membership" primitive from the other
 * side, and until removal has a permission model, hiding leave too keeps the
 * UI's story consistent (add-only) rather than allowing one asymmetric hole. */
// export async function leaveGroup(selfDid: string, address: string): Promise<{ ok: boolean; error?: string }> {
//   return groupAction(selfDid, address, (ds, own, id) => leaveConversation(ds, own, id))
// }

async function groupAction(
  selfDid: string, address: string, act: (ds: MediatorInfo, own: DidCommSender, id: string) => Promise<void>,
): Promise<{ ok: boolean; error?: string }> {
  const id = groupIdOfAddress(address)
  if (!id) return { ok: false, error: `${address} is not a group conversation` }
  try {
    const sender = await ownSender(selfDid)
    if (!sender) return { ok: false, error: 'this identity has no DIDComm mediator registered' }
    const ds = await conversationDs(id)
    if (!ds) return { ok: false, error: 'this conversation has no reachable delivery service' }
    await act(ds, sender.own, id)
    return { ok: true }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) }
  }
}

/** File a message somebody sent to a group conversation.
 *
 * Attribution comes from `msg.from`, which is the MLS leaf that sent it — the
 * only trustworthy answer in a group of several people, since a `from` header
 * is written by whoever packed the envelope and the DS repacks every copy.
 * The stored row therefore names the sender's DID, not the Delivery Service
 * that handed it over. */
async function fileGroupMessage(did: string, acctKey: string, msg: ReceivedGroupMessage): Promise<void> {
  const address = groupAddress(msg.groupId)
  const info = await conversationInfo(msg.groupId)
  const at = msg.payload.sentAt || new Date().toISOString()
  const row = didCommToEmail(msg.payload.id, did, msg.from.did, address, msg.payload.content, at, msg.payload.fromName, msg.payload.subject ?? '')
  // The conversation is the thread: every message in it belongs together
  // whoever sent it, unlike a 1:1 thread whose id is a function of the pair.
  ;(row as any).threadId = address
  // The same two headers an email group carries (deltachat/protocol.ts), so a
  // conversation reaches the existing group UI — list row, participants,
  // thread view — without a second notion of "group" alongside it. The id is
  // namespaced `mls:` because the SEND path has to tell the two apart: an
  // email group goes out over JMAP, this one to its Delivery Service.
  ;(row as any).headers = [
    { name: 'Chat-Group-ID', value: address },
    ...(info?.name ? [{ name: 'Chat-Group-Name', value: info.name }] : []),
  ]
  // Everyone else in the group, so the list row can show who is in it. Taken
  // from the ratchet tree rather than from anything the message says — the
  // tree is the membership, and a sender's idea of it may be an epoch old.
  ;(row as any).cc = (info?.members ?? []).filter(m => m !== msg.from.did && m !== did).map(m => ({ email: m }))
  ;(row as any)._account = acctKey
  ;(row as any)._relay = DIDCOMM_SERVER_URL
  if (msg.from.did === did) (row.keywords as any)['$seen'] = true // our own message, arriving from another of our devices
  messages.put(row)
  await persist.flushMessage(row)
  if (msg.payload.avatar) await saveAvatar(msg.from.did, msg.payload.avatar).catch(() => {})
}

/** Apply one delivery for a group conversation and file whatever came out.
 * Returns whether anything new arrived. */
async function handleConversationDelivery(
  did: string, acctKey: string, sender: { own: DidCommSender; mediator: MediatorInfo },
  delivery: Delivery, fromDid: string, ackId: string, withheld: Set<string>,
): Promise<boolean> {
  const applied = await receiveConversationDelivery(sender.own, delivery, fromDid)
    .catch(e => { console.warn('[didcomm] conversation delivery failed:', e instanceof Error ? e.message : e); return { retry: true } as Awaited<ReturnType<typeof receiveConversationDelivery>> })
  if (applied.retry) withheld.add(ackId)
  // Somebody declared they are leaving. MLS forbids removing oneself, so the
  // departure only takes effect when another member commits it — and until
  // one does, they remain a member of a group they have said they are done
  // with. Any member can do it; doing it promptly is the point.
  if (applied.sawProposal) await commitPendingConversation(sender, delivery.groupId)
  if (applied.message) await fileGroupMessage(did, acctKey, applied.message)
  return !!applied.message || !!applied.joined || !!applied.renamed
}

/** Commit a conversation's outstanding proposals — a member's declared
 * departure, in practice. Best-effort: if another member commits first, their
 * commit arrives here as an ordinary delivery and both end up in the same
 * place. */
async function commitPendingConversation(sender: { own: DidCommSender; mediator: MediatorInfo }, id: string): Promise<void> {
  try {
    const ds = await conversationDs(id)
    if (ds) await commitPendingProposalsIn(ds, sender.own, id)
  } catch (e) {
    console.warn('[didcomm] could not commit a conversation proposal:', e instanceof Error ? e.message : e)
  }
}

/** How often a device asks the Delivery Service whether it is missing
 * self-group deliveries, absent any other reason to ask.
 *
 * There has to be a heartbeat and not only an on-demand check, because the
 * failure it exists for is SILENT: a device left out of the fan-out sees no
 * deliveries, so it has no gap to notice — the absence looks exactly like a
 * quiet group. Asking on a timer is the only way to tell the two apart. */
const SELF_GROUP_CATCH_UP_INTERVAL_MS = 5 * 60 * 1000
const lastCatchUp = new Map<string, number>()

/** Run the catch-up if it is due (or `force`d by evidence of a gap: a delivery
 * that would not apply). Returns whether it filed anything.
 *
 * Best-effort throughout — a DS that cannot be reached, or a group this device
 * has not joined, simply means nothing to catch up on right now. */
async function catchUpGroupsIfDue(
  did: string, sender: { own: DidCommSender; mediator: MediatorInfo }, acctKey: string, force = false,
): Promise<boolean> {
  if (!force && Date.now() - (lastCatchUp.get(did) ?? 0) < SELF_GROUP_CATCH_UP_INTERVAL_MS) return false
  lastCatchUp.set(did, Date.now())
  let filed = false
  try {
    const { syncs, sawProposal } = await catchUpSelfGroup(sender.mediator, sender.own)
    for (const sync of syncs) await fileDeviceSync(did, acctKey, sync)
    if (sawProposal) await commitPendingSelfGroup(did)
    filed = syncs.length > 0
  } catch (e) {
    console.warn('[didcomm] self-group catch-up failed:', e instanceof Error ? e.message : e)
  }
  // Invitations that never took effect. Joining is the one step with no push
  // to fall back on — a Welcome is sent once — so a device asks its mediator
  // which groups it is in and pulls anything it has never seen.
  try {
    const recovered = await recoverMissingGroups(sender.mediator, sender.own, did)
    if (recovered.length) filed = true
  } catch (e) {
    console.warn('[didcomm] could not check for missed invitations:', e instanceof Error ? e.message : e)
  }
  // Every conversation as well, each against its OWN delivery service — which
  // for a group somebody else created is their mediator, not this one.
  for (const conversation of await conversations(did).catch(() => [])) {
    try {
      const ds = await conversationDs(conversation.id)
      if (!ds) continue
      const { messages, sawProposal } = await catchUpConversation(ds, sender.own, conversation.id)
      for (const message of messages) { await fileGroupMessage(did, acctKey, message); filed = true }
      if (sawProposal) await commitPendingProposalsIn(ds, sender.own, conversation.id).catch(() => {})
    } catch (e) {
      console.warn(`[didcomm] catch-up on ${conversation.id.slice(0, 12)} failed:`, e instanceof Error ? e.message : e)
    }
  }
  return filed
}

/** Commit whatever the self group has pending — a sibling's declared
 * departure, in practice. Best-effort and silent about ordinary losses: if
 * another device commits first, its commit reaches this one as an ordinary
 * delivery and both end up in the same place. */
async function commitPendingSelfGroup(did: string): Promise<void> {
  try {
    const rec = await getDidRecord(did)
    if (!rec?.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) return
    const stored = await loadGroup(selfGroupIdHex(did))
    if (!stored) return
    const own: DidCommSender = { did, xKid: `${did}${rec.didCommOwnKid}`, xPriv: hexToBytes(rec.didCommPrivateKey) }
    const mediator = await fetchMediatorInfo(rec.didCommMediatorUrl)
    const next = await commitPendingProposals(mediator, own, stored.state)
    await saveGroup({ ...stored, state: next })
  } catch (e) {
    console.warn('[didcomm] could not commit a self-group proposal:', e instanceof Error ? e.message : e)
  }
}

/** Hand an already-sent message to this identity's OWN other devices, so a
 * second open browser's thread gains it too. DIDComm has no carbon-copy
 * protocol, so the sender does this itself.
 *
 * One MLS application message to the self group, submitted once. The Delivery
 * Service fans it out per device, and each device's mediator queue holds it
 * until collected — which is why there is no retry, no owed-work record and no
 * outbox here any more. The previous version resolved this identity's own
 * document for a device list, sent a separate copy per kid, and needed a
 * durable outbox because a copy that failed to send existed nowhere else: the
 * sending device was the only party holding it, so a failure meant two devices
 * disagreed about the conversation permanently, with nothing anywhere
 * recording the debt.
 *
 * Never affects DidCommSendResult — the message to the real recipient has
 * already succeeded by the time this runs. A device that has not joined its
 * self group yet simply syncs nothing; its own sends still reach their
 * recipient, and it starts syncing as soon as it joins. */
function syncToOwnDevicesBestEffort(
  selfDid: string, toDid: string,
  msgBody: { content: string; id: string; sentAt: string; subject?: string; avatar?: string },
  fromName: string | undefined,
): void {
  void (async () => {
    const rec = await getDidRecord(selfDid)
    if (!rec?.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) return
    const stored = await loadGroup(selfGroupIdHex(selfDid))
    if (!stored) return // not in the group yet — nothing to sync to, and nothing owed
    // State this device is no longer a member of encrypts to an epoch the
    // group has left: the Delivery Service accepts the submission (its roster
    // is per identity, and this IS our identity), fans it out, and every other
    // device fails to open it. The copy would be lost with nothing reporting
    // it. Skipping is honest — the next registration rejoins and syncing
    // resumes.
    const { isActiveMember } = await import('../../mls/group.ts')
    if (!isActiveMember(stored.state, `${selfDid}${rec.didCommOwnKid}`)) {
      console.warn('[didcomm] skipping device sync: this device is not a current member of its own group')
      return
    }
    const payload: DeviceSyncPayload = {
      t: 'sync', id: msgBody.id, content: msgBody.content, sentAt: msgBody.sentAt, syncTo: toDid,
      ...(msgBody.subject ? { subject: msgBody.subject } : {}),
      ...(fromName ? { fromName } : {}),
      ...(msgBody.avatar ? { avatar: msgBody.avatar } : {}),
    }
    const own: DidCommSender = {
      did: selfDid, xKid: `${selfDid}${rec.didCommOwnKid}`, xPriv: hexToBytes(rec.didCommPrivateKey),
      mlkemPriv: rec.mlkemPrivateKey ? hexToBytes(rec.mlkemPrivateKey) : undefined,
    }
    const mediator = await fetchMediatorInfo(rec.didCommMediatorUrl)
    const next = await syncToOwnDevices(mediator, own, stored.state, encodeDeviceSync(payload))
    await saveGroup({ ...stored, state: next })
  })().catch(e => console.warn('[didcomm] device sync failed (message still sent):', e instanceof Error ? e.message : e))
}

/** Sets up everything a DIDComm-registered identity's inbox needs: the
 * synthetic session (if not already present) and a poll loop. Called at boot
 * (main.ts) for both a relay-backed identity that also has DIDComm and a
 * fully relay-less one, and again right after "Register with mediator"
 * succeeds so the new channel appears without a reload. `onNew` re-renders
 * the left pane / active thread the same way a JMAP SSE event does. */
export async function setupDidCommChannel(did: string, onNew: () => void): Promise<boolean> {
  if (!(await hasDidCommChannel(did))) {
    // A device that holds a DIDComm key but no mediator URL never finished
    // registering — and could never finish, because the boot-time
    // re-registration below is gated on `didCommMediatorUrl`, the field
    // registration itself sets. Nothing retried, nothing was published, and no
    // error appeared anywhere: the only trace was hasDidCommChannel's own
    // warning saying `mediatorUrl: false` forever.
    //
    // Found live (2026-08-13) on an identity whose registration had failed
    // earlier for an unrelated reason (its did:webvh log had outgrown the
    // store's request limit). Once that was fixed the device still sat in this
    // dead end, because the thing that would have re-tried was switched off by
    // the failure it was supposed to recover from.
    if (!(await completeFirstRegistration(did))) return false
  }
  ensureDidCommSession(did)
  reassertKeylistRegistration(did)
  startDidCommPolling(did, onNew)
  return true
}

/** One attempt to finish a registration that was started and never completed.
 *
 * Which mediator: the identity's OWN published DIDCommMessaging service if it
 * still has one — that is the mediator its other devices are already using,
 * and picking a different one would split the identity across two. Otherwise
 * this deployment's default, but only when it answers: registering against a
 * mediator that is down would fail anyway, and the probe is what tells this
 * apart from "this identity deliberately has no mediator".
 *
 * Returns false without complaint for an identity that simply has no DIDComm
 * key — that is not a broken registration, it is an identity that never
 * started one. */
async function completeFirstRegistration(did: string): Promise<boolean> {
  const rec = await getDidRecord(did)
  if (!rec?.didCommPrivateKey || !rec.didCommOwnKid || rec.didCommMediatorUrl) return false
  try {
    // The identity's own document first, and the deployment default only if it
    // has none — asking this deployment before asking the identity would put a
    // device on a mediator its siblings are not using, and each device would
    // then be reachable only through its own.
    const doc = await resolveDidCommDoc(did).catch(() => null)
    const service = doc?.service.find(s => s.type === 'DIDCommMessaging')
    let url = service?.serviceEndpoint.uri ?? ''

    // A prior registration can have reached Phase 3 (the public DID document
    // names the mediator) but lost its final local IndexedDB write — for
    // example when the page was closed while that write was in flight.  This
    // is not a new registration at all, so do not republish the document just
    // to rediscover information it already authoritatively carries.  Persist
    // it first; setupDidCommChannel then starts polling immediately and its
    // ordinary background reassertion restores this device's mediator keylist
    // entry if that part was the interrupted step.
    const routingKey = service?.serviceEndpoint.routing_keys?.[0]
    if (url && routingKey) {
      rec.didCommMediatorUrl = url
      rec.didCommRoutingKey = routingKey
      await storeDidRecord(rec)
      console.info(`[didcomm] restored mediator registration metadata for ${did} at ${url}`)
      return true
    }

    if (!url) {
      const { anchorReachable, mediatorUrl: defaultMediatorUrl } = await import('../didcomm-devices.ts')
      // Probed rather than assumed: registering against a mediator that is
      // down fails anyway, and the probe is what separates that from "this
      // identity deliberately has no mediator".
      if (await anchorReachable()) url = defaultMediatorUrl()
    }
    if (!url) return false
    console.info(`[didcomm] finishing an incomplete registration for ${did} at ${url}`)
    await registerWithMediator(url)
    return await hasDidCommChannel(did)
  } catch (e) {
    // Loud, because this is the recovery path for a device that is otherwise
    // silently unreachable — a warning nobody reads is how it stayed stuck.
    console.warn('[didcomm] could not finish registration:', e instanceof Error ? e.message : e)
    return false
  }
}

/** A full re-registration on every boot, not just at the one-time "Register
 * with mediator" click — self-healing against every way this identity's
 * DIDComm state can drift from what's actually live: the mediator's
 * ConnectionStore losing this device's registration (happened in production,
 * for a device that had registered before ConnectionStore persistence
 * existed), or this device's claimed kid/key silently no longer matching
 * what's published for it (also happened live — see didcomm-devices.ts's
 * syncDevicePosition note). Either failure is otherwise invisible to the
 * affected device forever: the errors land on the SENDER'S Forward attempt
 * or the mediator's reply-encryption step, never on this device's own
 * pickup, so pickupDeliver just quietly keeps returning empty.
 *
 * This used to do its own lighter version — syncDevicePosition +
 * mediate-request + keylist-update, skipping the actual document republish —
 * on the theory that publish.ts's separate routine republish would cover
 * that half. It didn't always: the two run as independent, unordered
 * fire-and-forget chains at boot, and a device found live with a genuinely
 * mismatched kid needed a full manual "log out of mediator, register again"
 * (didcomm-devices.ts's registerWithMediator, the exact function called
 * here now) before it started receiving — the lighter self-heal alone wasn't
 * enough. registerWithMediator does the whole cycle atomically: resolve +
 * correct this device's slot, rebuild the FULL document (relay services if
 * any, plus the DIDComm layer), republish it, then mediate-request +
 * keylist-update — so there's no window where the mediator and the DHT
 * record can disagree. Every step is independently idempotent, so repeating
 * the whole thing unconditionally on every load is safe, if heavier than the
 * old version — worth it since the lighter one demonstrably wasn't always
 * enough. Never blocks startDidCommPolling: a mediator or gateway hiccup
 * here must not stop the poll loop from starting. */
function reassertKeylistRegistration(did: string): void {
  (async () => {
    const rec = await getDidRecord(did)
    if (!rec?.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) return
    await registerWithMediator(rec.didCommMediatorUrl)
  })().catch(e => console.warn('[didcomm] re-registration failed (will retry next load):', e instanceof Error ? e.message : e))
}

/** The identity currently boot-relevant: a logged-in session's DID, or this
 * device's own DID with zero relays yet. Mirrors the same fallback used
 * throughout didcomm-devices.ts (registerWithMediator, etc.). */
export function currentIdentityDid(): string | null {
  return sessions.find(s => s.account.did)?.account.did ?? ownDid()
}
