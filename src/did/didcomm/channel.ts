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
import { standaloneDid, registerWithMediator, mediatorUrl } from '../create-standalone.ts'
import { displayNameFor } from '../publish.ts'
import { PUBLIC_PKARR_FALLBACKS } from '../resolver.ts'
import { resolveDidCommDoc, resolveSenderPublicKey } from './resolve.ts'
import { sendDidComm } from './send.ts'
import { pickupDeliver } from './pickup.ts'
import { fetchMediatorInfo, type MediatorInfo } from './coordinate.ts'
import { isExpired, type DidCommSender } from './message.ts'
import { hexToBytes } from '../../utils.ts'
import * as messages from '../../store/messages.ts'
import * as contactsStore from '../../store/contacts.ts'
import { buildCardForDid } from '../contacts.ts'
import * as persist from '../../vault/persist.ts'

const MAILBOX_PREFIX = 'mbx-' // go-jmapserver's own encoding — mailboxNameFromId decodes this back to the name with no lookup.

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
    const rec = await getDidRecord(didRecordKey(selfDid))
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
async function resolveDocOwnFirst(did: string, selfDid?: string | null): Promise<Awaited<ReturnType<typeof resolveDidCommDoc>>> {
  const own = await ownGateways(selfDid)
  const doc = await resolveDidCommDoc(did, own)
  if (doc) return doc
  return resolveDidCommDoc(did, [...own, ...PUBLIC_PKARR_FALLBACKS])
}

async function resolveSenderKeyOwnFirst(kid: string, selfDid?: string | null): Promise<Uint8Array> {
  const own = await ownGateways(selfDid)
  try {
    return await resolveSenderPublicKey(kid, own)
  } catch {
    return resolveSenderPublicKey(kid, [...own, ...PUBLIC_PKARR_FALLBACKS])
  }
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

/** DidRecord is IndexedDB-keyed by `.email` (create-standalone.ts/provision.ts:
 * a relay-backed identity's record lives under its relay address, only a
 * fully relay-less identity's record is keyed by the DID itself — mirrors the
 * `sessions[0]?.account.email ?? standaloneDid()` pattern registerWithMediator
 * and left-pane.ts's mediator card already use). Looking a relay-backed
 * identity's record up by bare DID silently misses it — this resolves the
 * right key for whichever `did` a caller here has in hand. */
function didRecordKey(did: string): string {
  const relaySession = sessions.find(s => s.account.did === did && s.account.serverUrl !== DIDCOMM_SERVER_URL)
  return relaySession?.account.email ?? did
}

/** True if this identity has registered a DIDComm mediator at all — the
 * precondition for ensureDidCommSession being worth calling. */
export async function hasDidCommChannel(did: string): Promise<boolean> {
  const key = didRecordKey(did)
  const rec = await getDidRecord(key)
  const result = !!(rec?.didCommMediatorUrl && rec.didCommPrivateKey && rec.didCommOwnKid)
  // A false here means DIDComm polling never starts, with no other trace
  // anywhere (main.ts's own note) — pin down WHICH of the three conditions
  // failed, and whether didRecordKey even resolved to the record's actual
  // storage key, rather than leaving that to be re-diagnosed from scratch
  // next time.
  if (!result) {
    console.warn('[didcomm] hasDidCommChannel: false', {
      did, key, found: !!rec,
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
  const rec = await getDidRecord(didRecordKey(did))
  if (!rec?.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) return null
  const own: DidCommSender = { did: rec.did, xKid: `${rec.did}${rec.didCommOwnKid}`, xPriv: hexToBytes(rec.didCommPrivateKey) }
  const mediator = await fetchMediatorInfo(rec.didCommMediatorUrl)
  return { own, mediator }
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
    delivered = await pickupDeliver(sender.mediator, sender.own, kid => resolveSenderKeyOwnFirst(kid, did))
  } catch (e) {
    console.warn('[didcomm] pickup failed:', e instanceof Error ? e.message : e)
    return false
  }
  if (!delivered.length) return false

  const acctKey = accountKey(didCommAccount(did))
  const now = new Date().toISOString()
  let gotOne = false
  for (const d of delivered) {
    const body = d.plaintext as { type?: string; body?: { content?: unknown; subject?: unknown; syncTo?: unknown; sentAt?: unknown; fromName?: unknown }; id?: string; expires_time?: number }
    // A message whose sender-declared deadline has already passed is stale —
    // drop it rather than render it (problems.md "Timeouts"). Pickup is
    // destructive at the mediator, so this is the last point that sees it.
    if (isExpired(body)) continue
    if (body?.type && !body.type.includes('basicmessage')) continue // admin/unknown traffic — never queued here in practice, but don't render it as a chat message if it ever is
    const content = typeof body?.body?.content === 'string' ? body.body.content : ''
    if (!content) continue
    const subject = typeof body?.body?.subject === 'string' ? body.body.subject : ''
    const fromDid = d.senderKid.split('#')[0]!
    const id = typeof body?.id === 'string' ? body.id : crypto.randomUUID()
    // syncToSiblingDevices' own marker: a message from MYSELF (another one of
    // this identity's devices) carrying the real recipient it was actually
    // sent to. Filed exactly like sendViaDidComm's own local echo on the
    // sending device — same mailbox, same fromDid, same $seen — so a second
    // open browser ends up with the identical row the sender got, instead of
    // a bogus self-to-self conversation under fromDid=did/toDid=did.
    const syncTo = typeof body?.body?.syncTo === 'string' ? body.body.syncTo : undefined
    const sentAt = typeof body?.body?.sentAt === 'string' ? body.body.sentAt : now
    const syncFromName = typeof body?.body?.fromName === 'string' ? body.body.fromName : undefined
    const isOwnSync = fromDid === did && !!syncTo
    const email = isOwnSync
      ? didCommToEmail(id, did, did, syncTo!, content, sentAt, syncFromName, subject)
      : didCommToEmail(id, did, fromDid, did, content, now, undefined, subject)
    if (isOwnSync) (email.keywords as any)['$seen'] = true // matches sendViaDidComm's own-outgoing-never-unread marking
    ;(email as any)._account = acctKey
    ;(email as any)._relay = DIDCOMM_SERVER_URL
    messages.put(email)
    await persist.flushMessage(email)
    gotOne = true
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
  return gotOne
}

const _pollTimers = new Map<string, ReturnType<typeof setInterval>>()
// DIDComm pickup is pull-only (Pickup 3.0) — no push equivalent to an
// EventSource, so this interval IS the floor on receive latency. Was 15s
// (half the reported "10-20 seconds" end-to-end lag on its own, worst-case);
// pickupDeliver is one lightweight HTTP round trip against our own mediator,
// so polling several times a minute per open client is cheap for it.
const POLL_INTERVAL_MS = 4_000

/** Starts polling this identity's DIDComm channel, calling `onNew` whenever a
 * cycle delivers something. Idempotent (replaces any existing timer for this
 * DID). Returns a stop function; startPolling() (shell.ts) calls it on every
 * restart the same way it tears down JMAP's SSE sources. */
export function startDidCommPolling(did: string, onNew: () => void): () => void {
  const existing = _pollTimers.get(did)
  if (existing) clearInterval(existing)
  const tick = async () => { if (await pollDidCommOnce(did, onNew)) onNew() }
  tick() // don't wait a full interval for the first check
  const timer = setInterval(tick, POLL_INTERVAL_MS)
  _pollTimers.set(did, timer)
  return () => { clearInterval(timer); _pollTimers.delete(did) }
}

export function stopAllDidCommPolling(): void {
  for (const t of _pollTimers.values()) clearInterval(t)
  _pollTimers.clear()
}

export interface DidCommSendResult { ok: boolean; fromEmail?: string; error?: string }

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
export async function sendViaDidComm(selfDid: string, toDid: string, body: string, subject = ''): Promise<DidCommSendResult> {
  const sender = await ownSender(selfDid)
  if (!sender) return { ok: false, error: 'this identity has no DIDComm mediator registered' }
  const toDoc = await resolveDocOwnFirst(toDid, selfDid)
  if (!toDoc) return { ok: false, error: `could not resolve recipient ${toDid}` }
  const id = crypto.randomUUID()
  // `subject` is a biset extension to basicmessage/2.0 (not part of the
  // DIDComm spec) — omitted entirely when empty so the wire payload matches
  // a plain reference-implementation basicmessage for the common case.
  const msgBody: { content: string; id: string; subject?: string } = { content: body, id }
  if (subject) msgBody.subject = subject
  try {
    await sendDidComm(sender.own, toDid, toDoc, { type: 'https://didcomm.org/basicmessage/2.0/message', body: msgBody })
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) }
  }
  const sentAt = new Date().toISOString()
  // Own display name (the same JMAP Identity.name buildOwnDocument publishes
  // into this identity's DID doc — see publish.ts's displayNameFor) — without
  // it, msg.from_name was left unset for every message we send, so our own
  // bubble/left-pane row showed the raw DID with no way to ever resolve it
  // (unlike a remote contact's name, which self-resolves off THEIR doc).
  const fromName = displayNameFor(relaysForId(selfDid).filter(s => s.account.serverUrl !== DIDCOMM_SERVER_URL))
  syncToSiblingDevices(sender.own, selfDid, toDid, msgBody, sentAt, fromName)
  const acctKey = accountKey(didCommAccount(selfDid))
  const email = didCommToEmail(id, selfDid, selfDid, toDid, body, sentAt, fromName, subject)
  ;(email.keywords as any)['$seen'] = true // own outgoing mail is never "unread"
  ;(email as any)._account = acctKey
  ;(email as any)._relay = DIDCOMM_SERVER_URL
  messages.put(email)
  await persist.flushMessage(email)
  return { ok: true, fromEmail: selfDid }
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
  msgBody: { content: string; id: string; subject?: string },
  sentAt: string, fromName: string | undefined,
): void {
  resolveDocOwnFirst(selfDid, selfDid).then(async selfDoc => {
    if (!selfDoc) return
    const siblings = selfDoc.keyAgreement.filter(k => k !== own.xKid)
    if (siblings.length === 0) return
    // fromName travels with it (rather than each sibling re-resolving its own
    // owner's name) so the synced row matches the sending device's own bubble
    // exactly — same displayNameFor source, just carried instead of re-derived.
    const syncBody: typeof msgBody & { syncTo: string; sentAt: string; fromName?: string } = { ...msgBody, syncTo: toDid, sentAt }
    if (fromName) syncBody.fromName = fromName
    await sendDidComm(own, selfDid, { ...selfDoc, keyAgreement: siblings }, { type: 'https://didcomm.org/basicmessage/2.0/message', body: syncBody })
  }).catch(e => console.warn('[didcomm] sync to sibling devices failed (message still sent):', e instanceof Error ? e.message : e))
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
 * what's published for it (also happened live — see create-standalone.ts's
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
 * (create-standalone.ts's registerWithMediator, the exact function called
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
    const rec = await getDidRecord(didRecordKey(did))
    if (!rec?.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) return
    await registerWithMediator(rec.didCommMediatorUrl)
  })().catch(e => console.warn('[didcomm] re-registration failed (will retry next load):', e instanceof Error ? e.message : e))
}

/** The identity currently boot-relevant: a logged-in session's DID, or the
 * relay-less standalone identity. Mirrors the same fallback used throughout
 * create-standalone.ts (registerWithMediator, etc.). */
export function currentIdentityDid(): string | null {
  return sessions.find(s => s.account.did)?.account.did ?? standaloneDid()
}
