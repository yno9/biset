import type { AccountSession, StoredAccount, InboxSummary } from './types.ts'
import { stableIdKey } from './identity/idkey.ts'

// Trimmed from src.bak/context.ts (2026-08-25, per user direction: code
// conflicting with the current design gets deleted, not kept alongside it).
// Dropped entirely, not adapted -- all multi-relay/AP-relay concepts this
// rewrite's Vault Core design has no equivalent for:
//   - RelayInfo/relayInfoFor/fetchRelayInfo (GET /relay-info -- no relay
//     serves this any more, mail goes through Vault Core's narrow API).
//   - isApRelay/AP relay classification (ActivityPub outbound is retired,
//     [[project_biset_ap_e2ee]]).
//   - mailboxRoutes, migrateApexToMail, claimed-relay tracking
//     (markRelayClaimed/isRelayClaimed) -- all "claim this relay account"
//     flow, superseded by identity/bootstrap.ts's enableDidComm-style
//     opt-in provisioning against Vault Core directly.
//   - sw.ts IndexedDB account mirror (idb.put(...SW_KEYS.sessionAccounts)) --
//     no Service Worker badge-count polling exists in this rewrite.
// Kept: the session-list bookkeeping, DIDComm relay sentinel (still
// meaningful -- a session with no live JMAP account behind it), and the
// single-active-identity model (still true: PLAN.md §7's single-account
// slice).
export let sessions: AccountSession[] = []
export function addSession(s: AccountSession): void {
  sessions.push(s)
}
export function clearSessions(): void {
  sessions.length = 0
}

export function sessionFor(accountId: string): AccountSession | undefined {
  return sessions.find(s => s.accountId === accountId)
}

// One identity is exactly one AccountSession in this rewrite (no
// multi-relay fan-out) -- identityKey collapses to the session's own
// accountId, stableIdKey-normalized for parity with src.bak's DID-move
// handling (LocalVaultSession.accountId/RemoteJmapSession.accountId are
// both already stable strings, but a remote-jmap session may still carry a
// did:webvh identity subject to the same domain-move portability concern).
export function identityKey(s: AccountSession): string {
  return stableIdKey(s.kind === 'local-vault' ? s.identityId : s.accountId)
}
export function identityIds(): string[] {
  return [...new Set(sessions.map(identityKey))]
}
export function relaysForId(id: string): AccountSession[] {
  const key = stableIdKey(id)
  return sessions.filter(s => identityKey(s) === key)
}

// DIDComm's synthetic "relay": historically a session with no real JMAP
// account behind it (src.bak/did/didcomm/channel.ts's didCommAccount). This
// rewrite's DIDComm adapter (PLAN.md §6.1) has no session/AccountSession of
// its own yet -- it rides the same local-vault identity, not a separate
// relay -- so this stays here as the discriminant future DIDComm UI work
// needs, not yet produced by anything.
export const DIDCOMM_SERVER_URL = 'didcomm:'
export function isDidCommRelay(serverUrl?: string): boolean {
  return serverUrl === DIDCOMM_SERVER_URL
}

// Transport label for a conversation's origin -- src.bak's own relay-info
// lookup replaced with a static answer, since this rewrite has exactly one
// transport in production use (mail, via biset-core) plus DIDComm's own
// pill (thread.ts wires this directly for the DIDComm case; see that
// file's own conv-via wiring, PLAN.md §6.1). No relay-info fetch: nothing
// serves that endpoint any more.
export function relayProtocolLabel(relay?: string): { text: string; color: string } | null {
  if (!relay) return null
  if (isDidCommRelay(relay)) return { text: 'DID', color: '#0ea5e9' }
  return { text: 'Mail', color: '#64748b' }
}

export function activeSession(): AccountSession | undefined {
  if (currentInbox) return sessionFor(currentInbox.user)
  return sessions[0]
}

// ── Current inbox ──────────────────────────────────────────────────────────────
export let currentInbox: InboxSummary | null = null

export function setCurrentInbox(s: InboxSummary | null): void {
  currentInbox = s
}

// ── Account storage (localStorage) ──────────────────────────────────────────────
const ACCOUNTS_KEY = 'biset_accounts'

export function loadStoredAccounts(): StoredAccount[] {
  try {
    const raw = localStorage.getItem(ACCOUNTS_KEY)
    return raw ? JSON.parse(raw) as StoredAccount[] : []
  } catch { return [] }
}

export function saveStoredAccounts(accounts: StoredAccount[]): void {
  localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(accounts))
}

// ── Active identity (2026-07-14: one client session = one identity) ────────────
// Unchanged from src.bak: biset can *store* credentials for several distinct
// identities at once, but only ever loads one of them into `sessions[]`.
const ACTIVE_IDENTITY_KEY = 'biset_active_identity'

export function getActiveIdentity(): string | null {
  try { return localStorage.getItem(ACTIVE_IDENTITY_KEY) } catch { return null }
}

export function setActiveIdentity(identity: string): void {
  try { localStorage.setItem(ACTIVE_IDENTITY_KEY, identity) } catch { /* quota / private mode */ }
}

// Narrows a full stored-accounts list down to the ones belonging to the
// active identity. No did-less/DID-having split any more (every
// StoredAccount here has a `did` -- local-vault always, remote-jmap once
// discovered) -- simplified from src.bak's own version, which had to
// special-case DID-less plain-password JMAP logins.
export function accountsForActiveIdentity(accounts: StoredAccount[]): StoredAccount[] {
  if (!accounts.length) return []
  let active = getActiveIdentity()
  const matches = (a: StoredAccount) => a.did === active
  if (!active || !accounts.some(matches)) {
    active = accounts[0]!.did ?? accounts[0]!.accountId
    setActiveIdentity(active)
  }
  return accounts.filter(matches)
}
