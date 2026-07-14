import type { AccountSession, StoredAccount, InboxSummary } from './types.ts'
import * as idb from './store/idb.ts'

// ── Vault ──────────────────────────────────────────────────────────────────────
export let vaultHandle: FileSystemDirectoryHandle | null = null
export function setVaultHandle(h: FileSystemDirectoryHandle): void { vaultHandle = h }

// ── Sessions ───────────────────────────────────────────────────────────────────
export let sessions: AccountSession[] = []
export function addSession(s: AccountSession): void { sessions.push(s) }
export function clearSessions(): void { sessions.length = 0 }

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
export function identityKey(s: AccountSession): string {
  return s.account.did || s.account.email
}
// Identity key for an email address: its DID if a connected session carries one,
// else the email itself (DID-less relays — plain IMAP etc. — still work, keyed by
// address, exactly as before). This is the key store/messages.ts's forIdentity()
// resolves dynamically (via relaysForId), so consumers that only hold an email
// map through this to query it.
export function identityKeyForEmail(email: string): string {
  return sessions.find(s => s.account.email === email)?.account.did || email
}
// Unique identities as their canonical email (representative endpoint address).
// A DID's representative is the primary address (its `alsoKnownAs`); until that
// plumbing lands, the first-seen endpoint's email stands in.
export function identities(): string[] {
  const byId = new Map<string, string>() // identityKey → representative email
  for (const s of sessions) if (!byId.has(identityKey(s))) byId.set(identityKey(s), s.account.email)
  return [...byId.values()]
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
// Endpoints of a specific identity id (did or email).
export function relaysForId(id: string): AccountSession[] {
  return sessions.filter(s => identityKey(s) === id)
}
// The session for a specific relay of an identity. DID-aware: resolves within
// the identity `email` belongs to, so it finds the relay's session even after a
// move where that relay is registered under a different address of the same DID.
// (For a single-address identity this is exactly the old email+serverUrl match.)
export function sessionForRelay(email: string, serverUrl: string): AccountSession | undefined {
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
// UI and in the DID document this client publishes (see did/publish.ts).
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
export function accountsForActiveIdentity(accounts: StoredAccount[]): StoredAccount[] {
  if (!accounts.length) return []
  let active = getActiveIdentity()
  const matches = (a: StoredAccount) => (a.did || a.email) === active
  if (!active || !accounts.some(matches)) {
    active = accounts[0]!.did || accounts[0]!.email
    setActiveIdentity(active)
  }
  return accounts.filter(matches)
}
