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

// One identity (email, e.g. alice@non.md) can be served by multiple relays
// (mail via mail.non.md, ActivityPub via ap.non.md). JMAP ids collide across
// servers, so the store / querystate / persist must key per-relay (accountKey),
// while the merged inbox view groups by identity (email).
export function accountKey(a: { email: string; serverUrl: string }): string {
  return a.email + '\0' + a.serverUrl
}
export function identities(): string[] {
  return [...new Set(sessions.map(s => s.account.email))]
}
export function relaysFor(email: string): AccountSession[] {
  return sessions.filter(s => s.account.email === email)
}
// The session for a specific relay of an identity (email may span mail + AP).
export function sessionForRelay(email: string, serverUrl: string): AccountSession | undefined {
  return sessions.find(s => s.account.email === email && s.account.serverUrl === serverUrl)
}

// ── Relay-advertised display info (label/color) ─────────────────────────────────
// Each relay serves GET /relay-info → {label, color}. biset caches it per relay
// so conversation UI stays relay-agnostic (no hardcoded protocol knowledge).
export interface RelayInfo { label: string; color: string }
const relayInfoCache = new Map<string, RelayInfo>()

export function relayInfoFor(serverUrl?: string): RelayInfo | undefined {
  if (!serverUrl) return undefined
  return relayInfoCache.get(serverUrl.replace(/\/$/, ''))
}

// ActivityPub relays deliver plaintext Notes to the fediverse — PGP has no place
// there (no WKD, no peer-key store; Mastodon et al. don't do OpenPGP). Recognise
// the configured AP relay so the send path can skip encryption and the recipient
// key lookups that would otherwise hit a route the AP relay doesn't serve.
export function isApRelay(serverUrl?: string): boolean {
  if (!serverUrl) return false
  const cfg = (window as any).__BISET_CONFIG__
  const apUrl: string | undefined = cfg?.ap_url || (cfg?.hostname ? `https://ap.${cfg.hostname}` : undefined)
  if (!apUrl) return false
  return serverUrl.replace(/\/$/, '') === apUrl.replace(/\/$/, '')
}

export async function fetchRelayInfo(serverUrl: string): Promise<void> {
  const url = serverUrl.replace(/\/$/, '')
  if (relayInfoCache.has(url)) return
  try {
    const r = await fetch(`${url}/relay-info`)
    if (!r.ok) return
    const j = await r.json() as { label?: string; color?: string }
    if (j?.label) relayInfoCache.set(url, { label: String(j.label), color: String(j.color || '#64748b') })
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
