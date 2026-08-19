import type { AccountSession, StoredAccount, InboxSummary } from './types.ts'
import * as idb from './store/idb.ts'
import { stableIdKey } from './did/idkey.ts'
import { SW_KEYS } from './push/shared.ts'

// ── Vault ──────────────────────────────────────────────────────────────────────
export let vaultHandle: FileSystemDirectoryHandle | null = null
export function setVaultHandle(h: FileSystemDirectoryHandle): void { vaultHandle = h }
export function clearVaultHandle(): void { vaultHandle = null }

// ── Sessions ───────────────────────────────────────────────────────────────────
export let sessions: AccountSession[] = []
export function addSession(s: AccountSession): void {
  sessions.push(s)
  mirrorSessionAccounts()
}
export function clearSessions(): void {
  sessions.length = 0
  mirrorSessionAccounts()
}

// The credentials that ACTUALLY authenticate, mirrored for sw.ts.
//
// The stored-account mirror below ('all') is not enough any more: a DID-bound
// account has no static password at all — account-create.ts stores '' for it
// and jmap/client.ts logs in with a device-signed session token instead
// (initSession's own note on why that token must never be written back over
// the durable record). The Service Worker was reading the durable record, so
// every JMAP call it made came back 401 and its whole unread scan silently
// contributed zero to the badge.
//
// Kept under its own key for exactly that reason: this is the short-lived
// credential, 'all' stays the durable one. The token is good for 30 days and
// is reissued on every boot, so a Service Worker waking days later still has a
// working one. Same trust boundary as the existing mirror — same origin, and a
// bearer token for this account was already reachable from JS here.
function mirrorSessionAccounts(): void {
  const accounts = sessions
    .filter(s => !isDidCommRelay(s.account.serverUrl))
    .map(s => s.account)
  idb.put(idb.STORES.accounts, accounts, SW_KEYS.sessionAccounts).catch(() => {})
}

export function sessionFor(email: string): AccountSession | undefined {
  return sessions.find(s => s.account.email === email)
}

// One identity can be served by multiple relays (mail via mail.non.md, AP via
// ap.non.md) and, after a move, even by different email addresses. JMAP ids
// collide across servers, so the store / querystate / persist must key per-relay
// (accountKey), while the merged view groups by IDENTITY.
//
// Identity-by-DID: the identity key is the session's `did` when known, else its
// email (backward-compatible — an endpoint whose DID isn't derived yet still
// groups by address exactly as before). `identityKey()` is the single place that
// decides "which identity is this endpoint", so grouping stays consistent.
export function accountKey(a: { email: string; serverUrl: string }): string {
  return a.email + '\0' + a.serverUrl
}
// Normalized through stableIdKey (did/idkey.ts, PLANWEBVH.md §3.1) so a
// did:webvh identity keeps ONE key across a domain move — the DID string it
// publishes under changes, the key biset groups its sessions, messages and
// contacts by does not. Identity-function for did:dht and for the email
// fallback, so nothing else about this changes.
export function identityKey(s: AccountSession): string {
  return stableIdKey(s.account.did || s.account.email)
}
// Identity key for an email address: its DID if a connected session carries one,
// else the email itself (DID-less relays — plain IMAP etc. — still work, keyed by
// address, exactly as before). This is the key store/messages.ts's forIdentity()
// resolves dynamically (via relaysForId), so consumers that only hold an email
// map through this to query it.
export function identityKeyForEmail(email: string): string {
  return stableIdKey(sessions.find(s => s.account.email === email)?.account.did || email)
}
// Unique identities as DID (or email fallback) — for per-identity operations
// that must not double-fire across a DID's multiple addresses (e.g. publish).
export function identityIds(): string[] {
  return [...new Set(sessions.map(identityKey))]
}
// All endpoints of the identity that `email` belongs to — following the DID, so
// this spans every relay AND every address of that identity, not just the ones
// sharing this email.
export function relaysFor(email: string): AccountSession[] {
  const self = sessions.find(s => s.account.email === email)
  if (!self) return []
  const id = identityKey(self)
  return sessions.filter(s => identityKey(s) === id)
}
// Endpoints of a specific identity id. Accepts either form — a full DID
// string or an already-normalized stable key (did/idkey.ts) — by normalizing
// its argument, so a caller holding a pre-move DID string still finds the
// identity's live sessions.
export function relaysForId(id: string): AccountSession[] {
  const key = stableIdKey(id)
  return sessions.filter(s => identityKey(s) === key)
}
// The session for a specific relay of an identity. DID-aware: resolves within
// the identity `email` belongs to, so it finds the relay's session even after a
// move where that relay is registered under a different address of the same DID.
// (For a single-address identity this is exactly the old email+serverUrl match.)
//
// No relay given => no relay-specific session exists to find, so `undefined` —
// NOT a crash. A DIDComm send has no relay to route through at all (left-pane's
// #new composer passes `relayUrl = undefined` for a DID recipient, and
// shell.ts's relayForSend can return nothing), and callers all already fall
// back with `?? sessionFor(...) ?? activeSession()`. Without this guard the
// `norm()` below dereferenced undefined and threw — inside the composer's async
// send handler, AFTER the message had already gone out, so every step that
// follows the send (hideCmdPalette, loadLeftInboxes, switchInbox) was skipped:
// the recipient got the message but the sender's own UI never gained the
// conversation (2026-07-28, user-reported). Guarding the one shared helper
// covers every call site instead of each one re-checking.
export function sessionForRelay(email: string, serverUrl?: string): AccountSession | undefined {
  if (!serverUrl) return undefined
  const norm = (u: string) => u.replace(/\/$/, '')
  return relaysFor(email).find(s => norm(s.account.serverUrl) === norm(serverUrl))
}

// ── Relay-advertised display info (label/color) ─────────────────────────────────
// Each relay serves GET /relay-info → {label, color, type, domain?}. biset caches
// it per relay so conversation UI stays relay-agnostic (no hardcoded protocol
// knowledge). `domain`: the domain a NEW account actually lands under
// (server-side provisionDomain()) — not necessarily this relay's own hostname
// (e.g. t.biset.md accounts are provisioned on the mail.biset.md relay).
export interface RelayInfo { label: string; color: string; type?: 'mail' | 'activitypub'; domain?: string }
const relayInfoCache = new Map<string, RelayInfo>()

export function relayInfoFor(serverUrl?: string): RelayInfo | undefined {
  if (!serverUrl) return undefined
  return relayInfoCache.get(serverUrl.replace(/\/$/, ''))
}

// ActivityPub relays deliver plaintext Notes to the fediverse — PGP has no place
// there (no WKD, no peer-key store; Mastodon et al. don't do OpenPGP). Recognise
// AP relays so the send path can skip encryption and the recipient key lookups
// that would otherwise hit a route an AP relay doesn't serve.
//
// Primary signal: the relay's own /relay-info `type` field (what the relay
// actually IS), cached by fetchRelayInfo. Fallback: string-match against the
// user's own configured ap_url — only correct for their home AP relay, and the
// only signal available in the brief window before /relay-info has loaded (or
// if a relay predates the `type` field). Relying on the fallback ALONE (the
// previous implementation) silently mislabeled every OTHER AP relay — e.g. a
// third-party one added via "Move to another relay…" — as "mail", both in the
// UI and in the DID document this client publishes (see did/dht/publish.ts).
// DIDComm's synthetic "relay": a session with this serverUrl has no real JMAP
// account behind it (did/didcomm/channel.ts) — every JMAP-only code path
// (sync/index.ts's start(), app.ts's send) must skip a session flagged this
// way rather than try to speak JMAP through a null client.
export const DIDCOMM_SERVER_URL = 'didcomm:'
export function isDidCommRelay(serverUrl?: string): boolean {
  return serverUrl === DIDCOMM_SERVER_URL
}

// This deployment's single jmapsmtp relay lives at mail.<apex>, regardless
// of which same-network subdomain a page is served from or an identity is
// rooted at (t.biset.md/biset.md, ...) — one relay serves every domain
// behind ONE URL, distinguished by the `domain` field in the request body,
// never by a different vhost per domain (see did/provision.ts's
// provisionAccount). Apex-collapses the same way didcomm-devices.ts's
// mediatorUrl() already does (t.biset.md -> biset.md) before building the
// URL. Found live (2026-08-17): three separate call sites each built
// `mail.<domain>` from the LITERAL (non-apex) domain instead — mail.t.biset.md
// has no DNS record at all, only mail.biset.md does, so every one of them
// DNS-failed for any identity/page not rooted at the apex itself. Consolidated
// here rather than left divergent across call sites.
export function mailRelayUrl(domain: string): string {
  const apex = domain.split('.').slice(-2).join('.')
  return `https://mail.${apex}`
}

// Deliberately independent of ap/config.ts's AP_ENABLED (outbound AP is
// retired, but this classifies whatever's already on disk — an existing
// AP-relay session/account, if any — so it must keep working regardless of
// whether the app would reach OUT to AP for anything new).
export function isApRelay(serverUrl?: string): boolean {
  if (!serverUrl) return false
  const url = serverUrl.replace(/\/$/, '')
  const cached = relayInfoCache.get(url)
  if (cached?.type) return cached.type === 'activitypub'
  const cfg = (window as any).__BISET_CONFIG__
  const apUrl: string | undefined = cfg?.ap_url || (cfg?.hostname ? `https://ap.${cfg.hostname}` : undefined)
  if (!apUrl) return false
  return url === apUrl.replace(/\/$/, '')
}

// Transport label for a relay (serverUrl) — the relay's own advertised
// label/color (GET /relay-info, cached above) so the UI stays relay-agnostic;
// falls back to the subdomain until that fetch lands. Shared by thread.ts's
// conversation header and left-pane.ts's compose From selector — one source
// of truth for "how do we describe this transport", not a reimplementation
// per call site.
export function relayProtocolLabel(relay?: string): { text: string; color: string } | null {
  if (!relay) return null
  if (isDidCommRelay(relay)) return { text: 'DID', color: '#0ea5e9' }
  const info = relayInfoFor(relay)
  if (info) return { text: info.label, color: info.color }
  let sub = ''
  try { sub = new URL(relay).hostname.split('.')[0].toLowerCase() } catch { return null }
  if (sub === 'ap') return { text: 'AP', color: '#8b5cf6' }
  if (sub === 'mail') return { text: 'Mail', color: '#64748b' }
  return { text: sub.toUpperCase(), color: '#64748b' }
}

export async function fetchRelayInfo(serverUrl: string): Promise<void> {
  const url = serverUrl.replace(/\/$/, '')
  if (relayInfoCache.has(url)) return
  try {
    const r = await fetch(`${url}/relay-info`)
    if (!r.ok) return
    const j = await r.json() as { label?: string; color?: string; type?: string; domain?: string }
    const type = j?.type === 'mail' || j?.type === 'activitypub' ? j.type : undefined
    if (j?.label) relayInfoCache.set(url, { label: String(j.label), color: String(j.color || '#64748b'), type, domain: j.domain })
  } catch { /* best-effort */ }
}

export function activeSession(): AccountSession | undefined {
  if (currentInbox) return sessionFor(currentInbox.user)
  return sessions[0]
}

// ── Mailbox routing ────────────────────────────────────────────────────────────
export const mailboxRoutes = new Map<string, AccountSession>()
export function setMailboxRoute(mailboxName: string, session: AccountSession): void {
  mailboxRoutes.set(mailboxName, session)
}

// ── Current inbox ──────────────────────────────────────────────────────────────
export let currentInbox: InboxSummary | null = null

export function setCurrentInbox(s: InboxSummary | null): void {
  currentInbox = s
}

// ── Account storage (localStorage, vault-off compatible) ───────────────────────
const ACCOUNTS_KEY = 'biset_accounts'

export function loadStoredAccounts(): StoredAccount[] {
  try {
    const raw = localStorage.getItem(ACCOUNTS_KEY)
    const accounts = raw ? JSON.parse(raw) as StoredAccount[] : []
    const migrated = migrateApexToMail(accounts)
    // Mirror on every read too, not just on save — a session that logged in
    // before sw.ts's IndexedDB mirror existed would otherwise never populate
    // it (saveStoredAccounts only fires on login/add/remove), leaving the
    // Service Worker with an empty account list forever and silently zeroing
    // the badge on every push.
    idb.put(idb.STORES.accounts, migrated, 'all').catch(() => {})
    return migrated
  } catch { return [] }
}

// The apex (https://<hostname>) now serves the ActivityPub identity surface, and
// its /.well-known/jmap only *redirects* to the mail relay — which browsers
// reject on CORS preflight ("Redirect is not allowed for a preflight request").
// So mail accounts must connect straight to the mail relay. Rewrite any account
// still pointing at the apex to the configured mail_url (one-time, persisted).
function migrateApexToMail(accounts: StoredAccount[]): StoredAccount[] {
  const cfg = (window as any).__BISET_CONFIG__
  const hostname: string | undefined = cfg?.hostname
  const mailUrl: string | undefined = cfg?.mail_url || (hostname ? `https://mail.${hostname}` : undefined)
  if (!hostname || !mailUrl) return accounts
  const apex = `https://${hostname}`.replace(/\/$/, '')
  let changed = false
  const out = accounts.map(a => {
    if (a.serverUrl.replace(/\/$/, '') === apex) { changed = true; return { ...a, serverUrl: mailUrl } }
    return a
  })
  if (changed) saveStoredAccounts(out)
  return out
}

export function saveStoredAccounts(accounts: StoredAccount[]): void {
  localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(accounts))
  // Best-effort mirror for sw.ts (see store/idb.ts STORES.accounts) — the
  // Service Worker can't read localStorage, only IndexedDB.
  idb.put(idb.STORES.accounts, accounts, 'all').catch(() => {})
}

// ── Active identity (2026-07-14: one client session = one identity) ────────────
// biset can *store* credentials for several distinct identities (DIDs) at
// once, but only ever loads one of them into `sessions[]` — switching to a
// different one is logout, then log back in as that identity (Gmail-style
// account switching and the finer "add a relay to me" vs "add a different
// identity" UX are both deferred; see ARC.md). This is just which identity
// key (did || email) that is, persisted so a reload keeps showing the same
// one instead of picking arbitrarily.
const ACTIVE_IDENTITY_KEY = 'biset_active_identity'

export function getActiveIdentity(): string | null {
  try { return localStorage.getItem(ACTIVE_IDENTITY_KEY) } catch { return null }
}

export function setActiveIdentity(identity: string): void {
  try { localStorage.setItem(ACTIVE_IDENTITY_KEY, identity) } catch { /* quota / private mode */ }
}

// Narrows a full stored-accounts list down to the ones belonging to the
// active identity — main.ts's boot sequence uses this instead of the raw
// list so `sessions[]` only ever spans one identity. If no active identity
// is set yet (first launch), or the one that was set no longer has any
// stored accounts (logged out of it entirely), adopts whichever identity IS
// present instead of returning nothing.
//
// DID-less accounts (a plain JMAP password login — jmap/client.ts's non-DID
// branch, config's "+ New Relay" → Log in with a password) are kept
// UNCONDITIONALLY, on top of whichever DID identity is active, rather than
// competing for the one identity slot: they have no DID of their own to be
// "the active identity", and the whole point of allowing that login
// alongside an existing DID identity (its own submit handler skips the
// identity-switch guard for exactly this reason) was for both to work at
// once. Without this, only one of the two ever reached initSession on a
// reload — the other's account card sat "Sync: Never" forever, silently
// dropped here before route() ever saw it, with no error logged anywhere
// because it was never attempted at all (2026-08-19, user-reported).
export function accountsForActiveIdentity(accounts: StoredAccount[]): StoredAccount[] {
  if (!accounts.length) return []
  const didLess = accounts.filter(a => !a.did)
  const withDid = accounts.filter(a => a.did)
  if (!withDid.length) return accounts
  let active = getActiveIdentity()
  const matches = (a: StoredAccount) => a.did === active
  if (!active || !withDid.some(matches)) {
    active = withDid[0]!.did!
    setActiveIdentity(active)
  }
  return [...withDid.filter(matches), ...didLess]
}
