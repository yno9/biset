import { JamClient } from 'jmap-jam'
import type { StoredAccount, AccountSession } from '../types.ts'
import { fetchRelayInfo } from '../context.ts'

export async function initSession(account: StoredAccount): Promise<AccountSession | null> {
  const { serverUrl, email, password } = account
  // Per-device credential (this session's account-model redesign,
  // src/did/devicebind.ts): a DID-bound account logs in ONLY via a
  // device-signed session — no masterSecret-derived static password exists
  // for it any more (provision.ts's provisionAccount stopped creating one).
  // No fallback here on purpose: falling back to `password` for a DID-bound
  // account would mean silently trying an empty/stale placeholder
  // (account-create.ts stores '' for these) or, worse, papering over a
  // genuine problem (device revoked, never vouched) with a credential that
  // doesn't actually exist server-side for accounts created after this
  // pass. A DID-less account (no `account.did` at all — pre-DID or
  // third-party-relay accounts that predate this redesign) has nothing but
  // the legacy password to begin with, so that path is unchanged.
  let effectivePassword: string
  if (account.did) {
    const at = email.lastIndexOf('@')
    if (at <= 0) {
      console.error('[initSession] malformed email for a DID-bound account:', email)
      return null
    }
    const { deviceSessionLogin } = await import('../did/provision.ts')
    const token = await deviceSessionLogin(serverUrl, email.slice(0, at), email.slice(at + 1), account.did).catch(() => null)
    if (!token) {
      console.error('[initSession] device session login failed (never vouched here, or revoked):', email, serverUrl)
      return null
    }
    effectivePassword = token
  } else {
    effectivePassword = password
  }
  const jmapClient = new JamClient({
    sessionUrl: serverUrl + '/.well-known/jmap',
    bearerToken: email + ':' + effectivePassword,
  })
  let session: Awaited<typeof jmapClient.session>
  try { session = await jmapClient.session } catch (e) {
    console.error('[initSession] failed:', email, serverUrl, e)
    return null
  }
  if (!session?.apiUrl) return null

  const jmapAccountId: string = (email && (session.accounts as any)?.[email] ? email : null)
    ?? session.primaryAccounts?.['urn:ietf:params:jmap:mail']
    ?? Object.keys(session.accounts ?? {})[0]
    ?? email
  const eventSourceUrl = (session as any).eventSourceUrl as string | null ?? null
  fetchRelayInfo(serverUrl) // fire-and-forget: cache this relay's label/color
  // A shallow copy with the EFFECTIVE credential, never the original
  // `account` reference: other code (discovery.ts's syncContactCard,
  // pullOwnContacts, PGP key fetch) reads session.account.password directly
  // for its own Basic-Auth calls and should see whatever actually worked —
  // but the input `account` may be the same object context.ts persists to
  // localStorage, and a short-lived session token must never overwrite the
  // durable stored password there.
  const sessionAccount: StoredAccount = effectivePassword === password ? account : { ...account, password: effectivePassword }
  return { account: sessionAccount, jmapAccountId, jmapClient, eventSourceUrl }
}
