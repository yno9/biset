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
import { getDidRecord } from '../store.ts'
import { ownDid, registerWithMediator, mediatorUrl } from '../didcomm-devices.ts'
import { displayNameFor } from '../dht/publish.ts'
import { PUBLIC_PKARR_FALLBACKS } from '../resolver.ts'
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
import { rememberSiblingSync, dueSiblingSyncs, hasPendingSiblingSyncs, noteSiblingAttempt, type SiblingSync } from './sibling-outbox.ts'
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

/** This browser's own relay /pkarr gateways (CORS-open) first, then — if
 * `selfDid` is given and has a mediator on record — that mediator's own
 * anchor's pkarr gateway too (anchor/server.ts's /pkarr, open to anyone — see
 * its own note on why that's safe), so a relay-less identity (DID⊥relay,
 * zero relay sessions to draw a gateway from) isn't left with ONLY the
 * public fallbacks, which is what silently starved it: did:dht resolution
 * from a plain file:// page never works through the public gateways alone in
 * practice (no CORS there — or, per a live case, simply hasn't propagated
 * there), and the ONE gateway that definitely has this identity's fresh
 * record is whichever it just published to. Excludes the synthetic DIDComm
 * session itself (DIDCOMM_SERVER_URL has no real HTTP endpoint behind it —
 * including it fed a literal, browser-rejected "didcomm:/pkarr/..." fetch
 * into the gateway list). Exported: left-pane.ts's own DID-doc resolves (the
 * To field's protocol pills, the /account identity panel) reuse this rather
 * than re-deriving the same gateway list a second way. */
export async function ownGateways(selfDid?: string | null): Promise<string[]> {
  const out = new Set(sessions.filter(s => s.account.serverUrl !== DIDCOMM_SERVER_URL).map(s => s.account.serverUrl.replace(/\/$/, '') + '/pkarr'))
  if (selfDid) {
    const rec = await getDidRecord(selfDid)
    if (rec?.didCommMediatorUrl) out.add(`${rec.didCommMediatorUrl.replace(/\/$/, '')}/pkarr`)
  }
  // This deployment's own anchor answers /pkarr for ANY identity, registered
  // with it or not (server.ts: "/pkarr/* answers anyone") — include it
  // unconditionally so PUBLIC_PKARR_FALLBACKS stays a true last resort
  // instead of the only gateway an identity with no relay and no mediator
  // registration yet has. At scale (100s-1000s of users), leaning on a
  // third-party public relay as the default path is a rate-limit bottleneck
  // waiting to happen (relay.pkarr.org 429s already seen from a single
  // browser's worth of test traffic).
  const mUrl = mediatorUrl()
  if (mUrl) out.add(`${mUrl.replace(/\/$/, '')}/pkarr`)
  return [...out]
}

// Own-gateway-first resolve, public fallbacks only on a miss — this module's
// resolveDidCommDoc/resolveSenderPublicKey calls used to always be handed
// ownGateways() + PUBLIC_PKARR_FALLBACKS flattened together and query BOTH
// in parallel on every call. That's fine for a rare call, but this is by far
// the highest-volume consumer of any gateway in the app: every message send
// (sendViaDidComm) AND every poll tick (pollDidCommOnce, every 4s per open
// identity) resolves through here. Constantly hitting relay.pkarr.org/
// pkarr.pubky.org at that rate — not just the rarer registration/publish
// paths — is what actually tripped their rate limit this session. Own
// gateways (this device's relays + this deployment's own anchor) answer the
// ordinary case; public fallbacks are queried only when they come back
// empty, keeping them a genuine last resort instead of constant background
// load.
async function resolveDocOwnFirst(
  did: string, selfDid?: string | null, opts?: { skipCache?: boolean },
): Promise<Awaited<ReturnType<typeof resolveDidCommDoc>>> {
  // Both rounds coming back empty is the most expensive thing that can happen
  // here — every gateway in both lists runs to completion — and it repeated in
  // full for every send, every poll tick and every contact refresh of the same
  // unresolvable DID. negcache.ts bounds that; its TTL is seconds, so a device
  // that registers a moment later is still found (see its own note).
  // `skipCache` bypasses the negative memory as well as the document cache: a
  // caller asking for a genuinely fresh answer must not be handed a remembered
  // "nothing there" either.
  const negKey = didcommDocumentMissKey(did)
  if (!opts?.skipCache && recentlyMissed(negKey)) return null
  const own = await ownGateways(selfDid)
  const doc = await resolveDidCommDoc(did, own, opts)
  if (doc) return doc
  const full = await resolveDidCommDoc(did, [...own, ...PUBLIC_PKARR_FALLBACKS], opts)
  if (!full) noteMiss(negKey)
  return full
}

/** The sender's public key, cached across reloads (sender-keys.ts). Every
 * incoming message blocks on this — authcrypt cannot be opened without it —
 * so the cache is what keeps a gateway round trip out of the path between a
 * push notification and the message showing up in the thread. `fresh` skips
 * the cache and replaces its entry, which is pickup.ts's repair for the one
 * case a permanently-cached key would otherwise be a permanent failure. */
function resolveSenderKeyOwnFirst(kid: string, selfDid?: string | null, opts?: { fresh?: boolean }): Promise<Uint8Array> {
  return cachedSenderKey(kid, async () => {
    const own = await ownGateways(selfDid)
    try {
      return await resolveSenderPublicKey(kid, own)
    } catch {
      return resolveSenderPublicKey(kid, [...own, ...PUBLIC_PKARR_FALLBACKS])
    }
  }, opts)
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
    return false
  }
  if (!delivered.length) return false

  const acctKey = accountKey(didCommAccount(did))
  let gotOne = false
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
    await acknowledgeMessages(sender.mediator, sender.own, delivered.map(d => d.ackId))
  } catch (e) {
    console.warn('[didcomm] messages-received ack failed (will redeliver next poll):', e instanceof Error ? e.message : e)
  }
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
    // After the pickup, never before: collecting what has arrived is what the
    // person is waiting on, and the outbox is a background debt.
    await flushSiblingOutbox(did).catch(e => console.warn('[didcomm] sibling outbox flush failed (will retry):', e instanceof Error ? e.message : e))
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
  syncToSiblingDevices(sender.own, selfDid, toDid, msgBody, fromName)
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

/** Best-effort fan-out of an already-sent message to this identity's OWN
 * other devices, so a second open browser's thread gains it too.
 *
 * Works by resolving OUR OWN DID document rather than asking the mediator
 * anything new: every device that registers DIDComm publishes its own
 * keyAgreement entry into the SAME shared did:dht document (document.ts's
 * DidKeyAgreement note — the exact mechanism that already lets a stranger's
 * single send reach all of a recipient's devices), so it doubles as the
 * multi-device roster for free. Filters OUR sending kid out before handing
 * the (possibly single-entry, possibly empty) rest to sendDidComm — it fans
 * out to every kid in whatever doc it's given with no self-awareness of its
 * own, so an unfiltered list would mail this device a copy of its own
 * message back through the mediator. `syncTo`/`sentAt` on the payload are
 * what let a sibling's pollDidCommOnce recognize this as "my own sent copy,
 * actually addressed to `syncTo`" rather than an ordinary incoming message
 * from myself. Never affects DidCommSendResult — the message to the real
 * recipient already succeeded by the time this runs; a sibling that's
 * offline or fails to resolve just doesn't get synced yet, exactly like a
 * poll cycle that hasn't run. */
function syncToSiblingDevices(
  own: DidCommSender, selfDid: string, toDid: string,
  msgBody: { content: string; id: string; sentAt: string; subject?: string },
  fromName: string | undefined,
): void {
  // Written down FIRST, attempted second. Everything below is best-effort and
  // always was; the difference is that a failure now leaves a record of what
  // this device still owes, which flushSiblingOutbox retries.
  const entry: Parameters<typeof rememberSiblingSync>[0] = { id: msgBody.id, selfDid, toDid, body: msgBody }
  if (fromName) entry.fromName = fromName
  rememberSiblingSync(entry)
    .then(() => deliverSiblingSync(own, { ...entry, deliveredKids: [], attempts: 0, lastAttemptAt: 0, createdAt: Date.now() }))
    .catch(e => console.warn('[didcomm] sync to sibling devices failed (message still sent, will retry):', e instanceof Error ? e.message : e))
}

/** One attempt at an owed sync copy, recording what it achieved. Never throws:
 * the message to the real recipient already succeeded, and a sibling that
 * can't be reached this minute is retried on a later poll tick. */
async function deliverSiblingSync(own: DidCommSender, entry: SiblingSync): Promise<void> {
  try {
    await attemptSiblingSync(own, entry)
  } catch (e) {
    await noteSiblingAttempt(entry.id, [], false).catch(() => {})
    console.warn('[didcomm] device-sync copy failed (queued for retry):', e instanceof Error ? e.message : e)
  }
}

async function attemptSiblingSync(own: DidCommSender, entry: SiblingSync): Promise<void> {
  const { selfDid, toDid, body: msgBody, fromName } = entry
  // skipCache on a RETRY only. The first attempt may legitimately use the
  // cached document, but a retry exists because something was wrong — and one
  // of the things that can be wrong is precisely that the cached document
  // predates a sibling registering, which is a failure a cached read repeats
  // forever.
  const selfDoc = await resolveDocOwnFirst(selfDid, selfDid, { skipCache: entry.attempts > 0 })
  if (!selfDoc) throw new Error(`could not resolve own DID document for ${selfDid}`)
  {
    const siblings = selfDoc.keyAgreement.filter(k => k !== own.xKid && !entry.deliveredKids.includes(k))
    // Nothing left to reach — either this identity has no other device, or
    // every one of them already has a copy. Either way the debt is settled.
    if (siblings.length === 0) { await noteSiblingAttempt(entry.id, [], true); return }
    // fromName travels with it (rather than each sibling re-resolving its own
    // owner's name) so the synced row matches the sending device's own bubble
    // exactly — same displayNameFor source, just carried instead of re-derived.
    // `sentAt` rides along inside msgBody now, the same value every OTHER
    // recipient of this message gets — it used to be passed in separately and
    // attached only here, which is how the sender's send time ended up being
    // something only this identity's own devices could see.
    const syncBody: typeof msgBody & { syncTo: string; fromName?: string } = { ...msgBody, syncTo: toDid }
    if (fromName) syncBody.fromName = fromName
    // silent: this is a copy of what the user just sent, going to their own
    // other devices. A notification there announces their own action back to
    // them — the one message in the system that is never news. See
    // SendOptions.silent: the mediator recognizes the sibling delivery from its
    // own keylist and skips the Web Push, so no banner and no badge.
    const fanout = await sendDidComm(own, selfDid, { ...selfDoc, keyAgreement: siblings }, { type: 'https://didcomm.org/basicmessage/2.0/message', body: syncBody, silent: true })
    // Done only when EVERY sibling got one. A partial fan-out keeps the entry,
    // with the reached kids recorded so the retry doesn't send them a second
    // copy — sendDidComm succeeds as long as one device took it, which is
    // exactly the case that used to look like success and leave a device out.
    await noteSiblingAttempt(entry.id, fanout.deliveredKids, fanout.delivered === fanout.total)
    if (fanout.delivered < fanout.total) {
      console.warn(`[didcomm] device-sync copy reached ${fanout.delivered}/${fanout.total} of this identity's other devices — retrying the rest`)
    }
  }
}

/** Retries every sync copy this identity still owes. Called from the poll tick,
 * which is the only thing that runs on a timer while the app is open; a boot
 * with pending entries therefore picks them up on its very first tick.
 *
 * Cheap when there is nothing owed (one IndexedDB read, no network), which is
 * the normal case — worth checking on every tick precisely because the whole
 * point is that a failure must not need the user to do anything. */
export async function flushSiblingOutbox(did: string): Promise<void> {
  if (!(await hasPendingSiblingSyncs(did))) return
  const sender = await ownSender(did)
  if (!sender) return
  for (const entry of await dueSiblingSyncs(did)) {
    await deliverSiblingSync(sender.own, entry)
  }
}

/** Sets up everything a DIDComm-registered identity's inbox needs: the
 * synthetic session (if not already present) and a poll loop. Called at boot
 * (main.ts) for both a relay-backed identity that also has DIDComm and a
 * fully relay-less one, and again right after "Register with mediator"
 * succeeds so the new channel appears without a reload. `onNew` re-renders
 * the left pane / active thread the same way a JMAP SSE event does. */
export async function setupDidCommChannel(did: string, onNew: () => void): Promise<boolean> {
  if (!(await hasDidCommChannel(did))) return false
  ensureDidCommSession(did)
  reassertKeylistRegistration(did)
  startDidCommPolling(did, onNew)
  return true
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
