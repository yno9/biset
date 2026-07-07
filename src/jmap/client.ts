import { JamClient } from 'jmap-jam'
import type { StoredAccount, AccountSession } from '../types.ts'
import { fetchRelayInfo } from '../context.ts'

export async function initSession(account: StoredAccount): Promise<AccountSession | null> {
  const { serverUrl, email, password } = account
  const jmapClient = new JamClient({
    sessionUrl: serverUrl + '/.well-known/jmap',
    bearerToken: email + ':' + password,
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
  return { account, jmapAccountId, jmapClient, eventSourceUrl }
}
